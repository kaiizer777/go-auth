package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Service defines session management operations.
type Service interface {
	CreateSession(ctx context.Context, userID uuid.UUID, credentialVersion int, sessionType db.SessionType, ip, userAgent string) (*Session, string, error)
	GetSession(ctx context.Context, rawID string) (*Session, error)
	InvalidateSession(ctx context.Context, rawID string) error
	InvalidateAllUserSessions(ctx context.Context, userID uuid.UUID) error
	RotateSession(ctx context.Context, oldRawID string, ip, userAgent string) (*Session, string, error)
	ListSessions(ctx context.Context, userID uuid.UUID) ([]*Session, error)
	PurgeExpired(ctx context.Context) (int64, error)
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

// lockForUpdate applies SELECT ... FOR UPDATE on dialects with row locking.
// SQLite has no FOR UPDATE syntax and serializes writers inside the tx, so the
// clause is skipped there; other dialects lock the re-read user row.
func lockForUpdate(tx *gorm.DB) *gorm.DB {
	if strings.Contains(strings.ToLower(tx.Name()), "sqlite") {
		return tx
	}
	return tx.Clauses(clause.Locking{Strength: "UPDATE"})
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
	credentialVersion int,
	sessionType db.SessionType,
	ip, userAgent string,
) (*Session, string, error) {
	if sessionType != db.SessionTypeCookie && sessionType != db.SessionTypeBearer {
		return nil, "", apperrors.ErrSessionInvalid
	}

	// Mint-time credential check runs inside a transaction with the insert so
	// a password reset committing between the version re-read and the insert
	// cannot mint a stale-version row. The user row is locked for update
	// where the dialect supports it (skipped on SQLite, which serializes
	// writers in-tx). A missing user row fails closed with
	// ErrSessionInvalid (no orphan mint). Read-time rejection in GetSession
	// stays as backstop. Nothing persists on mismatch.
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

	var user db.User
	if uerr := lockForUpdate(tx).Select("credential_version").Where("id = ?", userID).First(&user).Error; uerr != nil {
		tx.Rollback()
		if errors.Is(uerr, gorm.ErrRecordNotFound) {
			slog.InfoContext(ctx, "session_invalidated",
				"user_id", userID.String(),
				"reason", "missing_user_at_mint",
			)
			return nil, "", apperrors.ErrSessionInvalid
		}
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to query user", uerr)
	}
	if user.CredentialVersion != credentialVersion {
		tx.Rollback()
		slog.InfoContext(ctx, "session_invalidated",
			"user_id", userID.String(),
			"reason", "stale_credential_version_at_mint",
		)
		return nil, "", apperrors.ErrSessionInvalid
	}

	rawID, err := generateRawID()
	if err != nil {
		tx.Rollback()
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
		CredentialVersion: credentialVersion,
		LastActiveAt:      now,
		AbsoluteExpiresAt: now.Add(s.cfg.SessionAbsoluteMaxAge),
		CreatedAt:         now,
	}

	if err := tx.Create(record).Error; err != nil {
		tx.Rollback()
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to create session", err)
	}
	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to commit session", err)
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
			// Unknown token rejects as invalid so errors.Is cannot oracle stale-vs-nonexistent.
			return nil, apperrors.ErrSessionInvalid
		}
		return nil, apperrors.New(apperrors.CodeInternalError, "failed to query session", err)
	}

	// Non-locking snapshot read of credential_version to avoid row-lock contention
	// on users table across concurrent requests. If a discrepancy or missing user is
	// detected, begin a transaction to purge the stale/orphan session.
	var user db.User
	uerr := s.db.WithContext(ctx).
		Select("credential_version").
		Where("id = ?", record.UserID).
		First(&user).Error
	if uerr != nil {
		if errors.Is(uerr, gorm.ErrRecordNotFound) {
			tx := s.db.WithContext(ctx).Begin()
			if tx.Error == nil {
				_ = tx.Where("id = ?", record.ID).Delete(&db.Session{}).Error
				_ = tx.Commit().Error
			}
			slog.InfoContext(ctx, "session_invalidated",
				"user_id", record.UserID.String(),
				"reason", "missing_user_at_read",
			)
			return nil, apperrors.ErrSessionInvalid
		}
		return nil, apperrors.New(apperrors.CodeInternalError, "failed to query user", uerr)
	}
	if user.CredentialVersion != record.CredentialVersion {
		tx := s.db.WithContext(ctx).Begin()
		if tx.Error == nil {
			_ = tx.Where("id = ?", record.ID).Delete(&db.Session{}).Error
			_ = tx.Commit().Error
		}
		slog.InfoContext(ctx, "session_invalidated",
			"user_id", record.UserID.String(),
			"reason", "credential_version_mismatch",
		)
		return nil, apperrors.ErrSessionInvalid
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
	tx := s.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return apperrors.New(apperrors.CodeInternalError, "failed to begin transaction", tx.Error)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	// Bump the user's credential version (revocation epoch) when the row
	// exists; this serializes against concurrent RotateSession/CreateSession
	// via the row lock and gives a read-time backstop for any session row
	// that escapes deletion. Missing user is a no-op success (no row to bump).
	if err := tx.Model(&db.User{}).Where("id = ?", userID).
		Update("credential_version", gorm.Expr("credential_version + 1")).Error; err != nil {
		tx.Rollback()
		return apperrors.New(apperrors.CodeInternalError, "failed to bump credential version", err)
	}

	if err := tx.Where("user_id = ?", userID).Delete(&db.Session{}).Error; err != nil {
		tx.Rollback()
		return apperrors.New(apperrors.CodeInternalError, "failed to invalidate all sessions", err)
	}
	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return apperrors.New(apperrors.CodeInternalError, "failed to commit session invalidation", err)
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
			// Unknown token rejects as invalid so errors.Is cannot oracle stale-vs-nonexistent.
			return nil, "", apperrors.ErrSessionInvalid
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

	// Re-check the user's current credential version inside the transaction so a
	// rotation cannot mint a session under a superseded credential. The user
	// row is locked where the dialect supports it; a missing user fails
	// closed and purges the orphan row. Transient lookup failures surface as
	// internal errors; a version mismatch purges the stale row.
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

	var user db.User
	uerr := lockForUpdate(tx).
		Select("credential_version").
		Where("id = ?", oldRecord.UserID).
		First(&user).Error
	if uerr != nil {
		if errors.Is(uerr, gorm.ErrRecordNotFound) {
			_ = tx.Where("id_hash = ?", oldHash).Delete(&db.Session{}).Error
			_ = tx.Commit().Error
			slog.InfoContext(ctx, "session_invalidated",
				"user_id", oldRecord.UserID.String(),
				"reason", "missing_user_at_rotate",
			)
			return nil, "", apperrors.ErrSessionInvalid
		}
		tx.Rollback()
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to query user", uerr)
	}
	currentVersion := user.CredentialVersion
	if currentVersion != oldRecord.CredentialVersion {
		_ = tx.Where("id_hash = ?", oldHash).Delete(&db.Session{}).Error
		_ = tx.Commit().Error
		slog.InfoContext(ctx, "session_invalidated",
			"user_id", oldRecord.UserID.String(),
			"reason", "credential_version_mismatch",
		)
		return nil, "", apperrors.ErrSessionInvalid
	}

	res := tx.Where("id_hash = ?", oldHash).Delete(&db.Session{})
	if res.Error != nil {
		tx.Rollback()
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to rotate session", res.Error)
	}
	if res.RowsAffected == 0 {
		tx.Rollback()
		return nil, "", apperrors.ErrSessionInvalid
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
		CredentialVersion: currentVersion,
		LastActiveAt:      now,
		AbsoluteExpiresAt: oldRecord.AbsoluteExpiresAt,
		CreatedAt:         oldRecord.CreatedAt,
	}

	if err := tx.Create(newRecord).Error; err != nil {
		tx.Rollback()
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to create rotated session", err)
	}

	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
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

	// 2. Fetch active sessions with bounded limit, defensively filtering out expired sessions
	var records []db.Session
	if err := s.db.WithContext(ctx).
		Where("user_id = ? AND absolute_expires_at > ? AND last_active_at > ?", userID, now, idleCutoff).
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

// PurgeExpired deletes all sessions past their absolute expiration or idle timeout across all users.
func (s *service) PurgeExpired(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	idleCutoff := now.Add(-s.cfg.SessionIdleTimeout)
	res := s.db.WithContext(ctx).
		Where("absolute_expires_at <= ? OR last_active_at <= ?", now, idleCutoff).
		Delete(&db.Session{})
	if res.Error != nil {
		return 0, apperrors.New(apperrors.CodeInternalError, "failed to purge expired sessions", res.Error)
	}
	return res.RowsAffected, nil
}
