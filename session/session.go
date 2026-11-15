package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
	"gorm.io/gorm"
)

// Service defines session management operations.
type Service interface {
	CreateSession(ctx context.Context, userID uuid.UUID, sessionType db.SessionType, ip, userAgent string) (*Session, string, error)
	GetSession(ctx context.Context, rawID string) (*Session, error)
	InvalidateSession(ctx context.Context, rawID string) error
	InvalidateAllUserSessions(ctx context.Context, userID uuid.UUID) error
	RotateSession(ctx context.Context, oldRawID string, ip, userAgent string) (*Session, string, error)
}

type service struct {
	db  *gorm.DB
	cfg *config.Config
}

// NewService constructs a concrete session Service.
func NewService(gormDB *gorm.DB, cfg *config.Config) Service {
	return &service{db: gormDB, cfg: cfg}
}

// generateRawID creates a cryptographically random 128-bit session ID.
// 16 bytes from crypto/rand -> hex-encoded -> 32-character string.
func generateRawID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: rand.Read: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// hashID returns the SHA-256 hex digest of rawID.
// Output is always exactly 64 hex characters.
func hashID(rawID string) string {
	sum := sha256.Sum256([]byte(rawID))
	return hex.EncodeToString(sum[:])
}

func (s *service) CreateSession(
	ctx context.Context,
	userID uuid.UUID,
	sessionType db.SessionType,
	ip, userAgent string,
) (*Session, string, error) {
	rawID, err := generateRawID()
	if err != nil {
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to generate session ID", err)
	}

	now := time.Now().UTC()
	record := &db.Session{
		ID:                uuid.New(),
		UserID:            userID,
		IDHash:            hashID(rawID),
		SessionType:       sessionType,
		IPAddress:         ip,
		UserAgent:         userAgent,
		LastActiveAt:      now,
		AbsoluteExpiresAt: now.Add(s.cfg.SessionAbsoluteMaxAge),
		CreatedAt:         now,
	}

	if err := s.db.WithContext(ctx).Create(record).Error; err != nil {
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to create session", err)
	}

	slog.InfoContext(ctx, "session_created",
		"user_id", userID.String(),
		"session_type", string(sessionType),
		"ip", ip,
	)

	return fromDB(record), rawID, nil
}

func (s *service) GetSession(ctx context.Context, rawID string) (*Session, error) {
	idHash := hashID(rawID)

	var record db.Session
	err := s.db.WithContext(ctx).
		Where("id_hash = ?", idHash).
		First(&record).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrSessionNotFound
		}
		return nil, apperrors.New(apperrors.CodeInternalError, "failed to query session", err)
	}

	now := time.Now().UTC()

	// Check idle timeout: now > LastActiveAt + IdleTimeout
	if now.After(record.LastActiveAt.Add(s.cfg.SessionIdleTimeout)) {
		_ = s.db.WithContext(ctx).Delete(&record).Error
		slog.InfoContext(ctx, "session_expired",
			"user_id", record.UserID.String(),
			"reason", "idle_timeout",
		)
		return nil, apperrors.ErrSessionExpired
	}

	// Check absolute timeout: now > AbsoluteExpiresAt
	if now.After(record.AbsoluteExpiresAt) {
		_ = s.db.WithContext(ctx).Delete(&record).Error
		slog.InfoContext(ctx, "session_expired",
			"user_id", record.UserID.String(),
			"reason", "absolute_timeout",
		)
		return nil, apperrors.ErrSessionExpired
	}

	// Capture record ID and construct domain Session prior to launching the detached background update.
	sessionID := record.ID
	domainSession := fromDB(&record)

	// Update LastActiveAt asynchronously with a detached context without racing on record pointer.
	go func() {
		updateCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.db.WithContext(updateCtx).
			Model(&db.Session{}).
			Where("id = ?", sessionID).
			Update("last_active_at", now).Error
	}()

	return domainSession, nil
}

func (s *service) InvalidateSession(ctx context.Context, rawID string) error {
	idHash := hashID(rawID)
	result := s.db.WithContext(ctx).
		Where("id_hash = ?", idHash).
		Delete(&db.Session{})
	if result.Error != nil {
		return apperrors.New(apperrors.CodeInternalError, "failed to invalidate session", result.Error)
	}
	return nil
}

func (s *service) InvalidateAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	result := s.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&db.Session{})
	if result.Error != nil {
		return apperrors.New(apperrors.CodeInternalError, "failed to invalidate all sessions", result.Error)
	}
	slog.InfoContext(ctx, "all_sessions_invalidated", "user_id", userID.String())
	return nil
}

func (s *service) RotateSession(
	ctx context.Context,
	oldRawID string,
	ip, userAgent string,
) (*Session, string, error) {
	oldHash := hashID(oldRawID)
	var oldRecord db.Session
	if err := s.db.WithContext(ctx).
		Where("id_hash = ?", oldHash).
		First(&oldRecord).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", apperrors.ErrSessionNotFound
		}
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to rotate session", err)
	}

	now := time.Now().UTC()
	if now.After(oldRecord.LastActiveAt.Add(s.cfg.SessionIdleTimeout)) || now.After(oldRecord.AbsoluteExpiresAt) {
		_ = s.db.WithContext(ctx).Where("id_hash = ?", oldHash).Delete(&db.Session{}).Error
		slog.InfoContext(ctx, "session_expired",
			"user_id", oldRecord.UserID.String(),
			"reason", "rotate_expired",
		)
		return nil, "", apperrors.ErrSessionExpired
	}

	tx := s.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to begin transaction", tx.Error)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if err := tx.Where("id_hash = ?", oldHash).Delete(&db.Session{}).Error; err != nil {
		tx.Rollback()
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to rotate session", err)
	}

	rawID, err := generateRawID()
	if err != nil {
		tx.Rollback()
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to generate new session ID", err)
	}

	if ip == "" {
		ip = oldRecord.IPAddress
	}
	if userAgent == "" {
		userAgent = oldRecord.UserAgent
	}

	now = time.Now().UTC()
	newRecord := &db.Session{
		ID:                uuid.New(),
		UserID:            oldRecord.UserID,
		IDHash:            hashID(rawID),
		SessionType:       oldRecord.SessionType,
		IPAddress:         ip,
		UserAgent:         userAgent,
		LastActiveAt:      now,
		AbsoluteExpiresAt: now.Add(s.cfg.SessionAbsoluteMaxAge),
		CreatedAt:         now,
	}

	if err := tx.Create(newRecord).Error; err != nil {
		tx.Rollback()
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to create rotated session", err)
	}

	if err := tx.Commit().Error; err != nil {
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to commit session rotation", err)
	}

	return fromDB(newRecord), rawID, nil
}
