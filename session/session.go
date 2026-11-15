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
	ListSessions(ctx context.Context, userID uuid.UUID) ([]*Session, error)
}

type service struct {
	db  *gorm.DB
	cfg *config.Config
}

// NewService constructs a concrete session Service.
func NewService(gormDB *gorm.DB, cfg *config.Config) Service {
	if gormDB == nil {
		panic("session: nil gorm.DB")
	}
	if cfg == nil {
		defaultCfg := config.DefaultConfig()
		cfg = &defaultCfg
	}
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

// validateRawID validates that rawID is exactly a 32-character hexadecimal string.
func validateRawID(rawID string) error {
	if len(rawID) != 32 {
		return apperrors.ErrSessionInvalid
	}
	if _, err := hex.DecodeString(rawID); err != nil {
		return apperrors.ErrSessionInvalid
	}
	return nil
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
	if sessionType != db.SessionTypeCookie && sessionType != db.SessionTypeBearer {
		return nil, "", apperrors.ErrSessionInvalid
	}

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
	if err := validateRawID(rawID); err != nil {
		return nil, err
	}

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
		res := s.db.WithContext(ctx).
			Where("id = ? AND last_active_at <= ?", record.ID, record.LastActiveAt).
			Delete(&db.Session{})
		if res.Error != nil {
			return nil, apperrors.New(apperrors.CodeInternalError, "failed to delete expired session", res.Error)
		}
		if res.RowsAffected == 0 {
			var reloaded db.Session
			if err := s.db.WithContext(ctx).Where("id = ?", record.ID).First(&reloaded).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, apperrors.ErrSessionExpired
				}
				return nil, apperrors.New(apperrors.CodeInternalError, "failed to reload session", err)
			}
			record = reloaded
			if now.After(record.LastActiveAt.Add(s.cfg.SessionIdleTimeout)) {
				_ = s.db.WithContext(ctx).
					Where("id = ? AND last_active_at <= ?", record.ID, record.LastActiveAt).
					Delete(&db.Session{}).Error
				slog.InfoContext(ctx, "session_expired",
					"user_id", record.UserID.String(),
					"reason", "idle_timeout",
				)
				return nil, apperrors.ErrSessionExpired
			}
			if now.After(record.AbsoluteExpiresAt) {
				_ = s.db.WithContext(ctx).Delete(&record).Error
				slog.InfoContext(ctx, "session_expired",
					"user_id", record.UserID.String(),
					"reason", "absolute_timeout",
				)
				return nil, apperrors.ErrSessionExpired
			}
		} else {
			slog.InfoContext(ctx, "session_expired",
				"user_id", record.UserID.String(),
				"reason", "idle_timeout",
			)
			return nil, apperrors.ErrSessionExpired
		}
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

	// Capture record ID and construct domain Session.
	sessionID := record.ID
	domainSession := fromDB(&record)

	// Throttle LastActiveAt touch updates to prevent unthrottled writes and goroutine churn.
	// Only touch if time elapsed since LastActiveAt exceeds the threshold (1 minute or a fraction of idle timeout).
	touchThreshold := 1 * time.Minute
	if s.cfg != nil && s.cfg.SessionIdleTimeout > 0 {
		if frac := s.cfg.SessionIdleTimeout / 10; frac > 0 && frac < touchThreshold {
			touchThreshold = frac
		}
	}

	if now.Sub(record.LastActiveAt) >= touchThreshold {
		if err := s.db.WithContext(ctx).
			Model(&db.Session{}).
			Where("id = ? AND last_active_at < ?", sessionID, now).
			Update("last_active_at", now).Error; err != nil {
			slog.ErrorContext(ctx, "failed to update session last_active_at",
				"session_id", sessionID.String(),
				"error", err,
			)
		} else {
			domainSession.LastActiveAt = now
		}
	}

	return domainSession, nil
}

func (s *service) InvalidateSession(ctx context.Context, rawID string) error {
	if err := validateRawID(rawID); err != nil {
		return err
	}

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
	if err := validateRawID(oldRawID); err != nil {
		return nil, "", err
	}

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
		if now.After(oldRecord.AbsoluteExpiresAt) {
			_ = s.db.WithContext(ctx).Where("id_hash = ?", oldHash).Delete(&db.Session{}).Error
			slog.InfoContext(ctx, "session_expired",
				"user_id", oldRecord.UserID.String(),
				"reason", "rotate_expired",
			)
			return nil, "", apperrors.ErrSessionExpired
		}

		res := s.db.WithContext(ctx).
			Where("id_hash = ? AND last_active_at <= ?", oldHash, oldRecord.LastActiveAt).
			Delete(&db.Session{})
		if res.Error != nil {
			return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to delete expired session", res.Error)
		}
		if res.RowsAffected == 0 {
			var reloaded db.Session
			if err := s.db.WithContext(ctx).Where("id_hash = ?", oldHash).First(&reloaded).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, "", apperrors.ErrSessionExpired
				}
				return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to reload session", err)
			}
			oldRecord = reloaded
			if now.After(oldRecord.LastActiveAt.Add(s.cfg.SessionIdleTimeout)) || now.After(oldRecord.AbsoluteExpiresAt) {
				_ = s.db.WithContext(ctx).Where("id_hash = ?", oldHash).Delete(&db.Session{}).Error
				slog.InfoContext(ctx, "session_expired",
					"user_id", oldRecord.UserID.String(),
					"reason", "rotate_expired",
				)
				return nil, "", apperrors.ErrSessionExpired
			}
		} else {
			slog.InfoContext(ctx, "session_expired",
				"user_id", oldRecord.UserID.String(),
				"reason", "rotate_expired",
			)
			return nil, "", apperrors.ErrSessionExpired
		}
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

	res := tx.Where("id_hash = ?", oldHash).Delete(&db.Session{})
	if res.Error != nil {
		tx.Rollback()
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to rotate session", res.Error)
	}
	if res.RowsAffected == 0 {
		tx.Rollback()
		return nil, "", apperrors.ErrSessionNotFound
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
	if !oldRecord.AbsoluteExpiresAt.After(now) || !oldRecord.LastActiveAt.Add(s.cfg.SessionIdleTimeout).After(now) {
		tx.Rollback()
		slog.InfoContext(ctx, "session_expired",
			"user_id", oldRecord.UserID.String(),
			"reason", "rotate_expired",
		)
		return nil, "", apperrors.ErrSessionExpired
	}

	newRecord := &db.Session{
		ID:                uuid.New(),
		UserID:            oldRecord.UserID,
		IDHash:            hashID(rawID),
		SessionType:       oldRecord.SessionType,
		IPAddress:         ip,
		UserAgent:         userAgent,
		LastActiveAt:      now,
		AbsoluteExpiresAt: oldRecord.AbsoluteExpiresAt,
		CreatedAt:         oldRecord.CreatedAt,
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

func (s *service) ListSessions(ctx context.Context, userID uuid.UUID) ([]*Session, error) {
	now := time.Now().UTC()
	idleCutoff := now.Add(-s.cfg.SessionIdleTimeout)

	// 1. Purge expired sessions for this user
	_ = s.db.WithContext(ctx).
		Where("user_id = ? AND (absolute_expires_at <= ? OR last_active_at <= ?)", userID, now, idleCutoff).
		Delete(&db.Session{}).Error

	// 2. Fetch active sessions with bounded limit
	var records []db.Session
	if err := s.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("last_active_at DESC").
		Limit(50).
		Find(&records).Error; err != nil {
		return nil, apperrors.New(apperrors.CodeInternalError, "failed to list sessions", err)
	}

	sessions := make([]*Session, len(records))
	for i := range records {
		sessions[i] = fromDB(&records[i])
	}
	return sessions, nil
}
