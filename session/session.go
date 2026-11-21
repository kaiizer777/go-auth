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
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
	apperrors "github.com/kaiizer777/go-auth/errors"
	"gorm.io/gorm"
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
	store db.Store
	cfg   *config.Config
}

// NewServiceWithStore constructs a concrete session Service backed by a db.Store.
func NewServiceWithStore(store db.Store, cfg *config.Config) Service {
	if store == nil {
		panic("session: nil db.Store")
	}
	if cfg == nil {
		defaultCfg := config.DefaultConfig()
		cfg = &defaultCfg
	}
	return &service{store: store, cfg: cfg}
}

// NewService constructs a concrete session Service backed by a GORM DB.
func NewService(gormDB *gorm.DB, cfg *config.Config) Service {
	if gormDB == nil {
		panic("session: nil gorm.DB")
	}
	return NewServiceWithStore(gormstore.New(gormDB), cfg)
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
		CredentialVersion: credentialVersion,
		LastActiveAt:      now,
		AbsoluteExpiresAt: now.Add(s.cfg.SessionAbsoluteMaxAge),
		CreatedAt:         now,
	}

	var sessionErr error
	err = s.store.Transaction(ctx, func(txStore db.Store) error {
		user, uerr := txStore.Users().GetByIDForUpdate(ctx, userID)
		if uerr != nil {
			if errors.Is(uerr, gorm.ErrRecordNotFound) {
				slog.InfoContext(ctx, "session_invalidated",
					"user_id", userID.String(),
					"reason", "missing_user_at_mint",
				)
				sessionErr = apperrors.ErrSessionInvalid
				return nil
			}
			return apperrors.New(apperrors.CodeInternalError, "failed to query user", uerr)
		}
		if user.CredentialVersion != credentialVersion {
			slog.InfoContext(ctx, "session_invalidated",
				"user_id", userID.String(),
				"reason", "stale_credential_version_at_mint",
			)
			sessionErr = apperrors.ErrSessionInvalid
			return nil
		}

		if err := txStore.Sessions().Create(ctx, record); err != nil {
			return apperrors.New(apperrors.CodeInternalError, "failed to create session", err)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if sessionErr != nil {
		return nil, "", sessionErr
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

	record, err := s.store.Sessions().GetByIDHash(ctx, idHash)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrSessionInvalid
		}
		return nil, apperrors.New(apperrors.CodeInternalError, "failed to query session", err)
	}

	user, uerr := s.store.Users().GetByID(ctx, record.UserID)
	if uerr != nil {
		if errors.Is(uerr, gorm.ErrRecordNotFound) {
			_ = s.store.Sessions().Delete(ctx, record.ID)
			slog.InfoContext(ctx, "session_invalidated",
				"user_id", record.UserID.String(),
				"reason", "missing_user_at_read",
			)
			return nil, apperrors.ErrSessionInvalid
		}
		return nil, apperrors.New(apperrors.CodeInternalError, "failed to query user", uerr)
	}
	if user.CredentialVersion != record.CredentialVersion {
		_ = s.store.Sessions().Delete(ctx, record.ID)
		slog.InfoContext(ctx, "session_invalidated",
			"user_id", record.UserID.String(),
			"reason", "credential_version_mismatch",
		)
		return nil, apperrors.ErrSessionInvalid
	}

	now := time.Now().UTC()

	// Check idle timeout: now > LastActiveAt + IdleTimeout
	if now.After(record.LastActiveAt.Add(s.cfg.SessionIdleTimeout)) {
		affected, err := s.store.Sessions().DeleteIfStale(ctx, record.ID, record.LastActiveAt)
		if err != nil {
			return nil, apperrors.New(apperrors.CodeInternalError, "failed to delete expired session", err)
		}
		if affected == 0 {
			reloaded, err := s.store.Sessions().GetByID(ctx, record.ID)
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, apperrors.ErrSessionExpired
				}
				return nil, apperrors.New(apperrors.CodeInternalError, "failed to reload session", err)
			}
			record = reloaded
			if now.After(record.LastActiveAt.Add(s.cfg.SessionIdleTimeout)) {
				_, _ = s.store.Sessions().DeleteIfStale(ctx, record.ID, record.LastActiveAt)
				slog.InfoContext(ctx, "session_expired",
					"user_id", record.UserID.String(),
					"reason", "idle_timeout",
				)
				return nil, apperrors.ErrSessionExpired
			}
			if now.After(record.AbsoluteExpiresAt) {
				_ = s.store.Sessions().Delete(ctx, record.ID)
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
		_ = s.store.Sessions().Delete(ctx, record.ID)
		slog.InfoContext(ctx, "session_expired",
			"user_id", record.UserID.String(),
			"reason", "absolute_timeout",
		)
		return nil, apperrors.ErrSessionExpired
	}

	// Capture record ID and construct domain Session.
	sessionID := record.ID
	domainSession := fromDB(record)

	// Throttle LastActiveAt touch updates to prevent unthrottled writes and goroutine churn.
	touchThreshold := 1 * time.Minute
	if s.cfg != nil && s.cfg.SessionIdleTimeout > 0 {
		if frac := s.cfg.SessionIdleTimeout / 10; frac > 0 && frac < touchThreshold {
			touchThreshold = frac
		}
	}

	if now.Sub(record.LastActiveAt) >= touchThreshold {
		if err := s.store.Sessions().UpdateLastActive(ctx, sessionID, now); err != nil {
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
	if _, err := s.store.Sessions().DeleteByIDHash(ctx, idHash); err != nil {
		return apperrors.New(apperrors.CodeInternalError, "failed to invalidate session", err)
	}
	return nil
}

func (s *service) InvalidateAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	err := s.store.Transaction(ctx, func(txStore db.Store) error {
		if _, err := txStore.Users().IncrementCredentialVersion(ctx, userID); err != nil {
			return apperrors.New(apperrors.CodeInternalError, "failed to bump credential version", err)
		}
		if err := txStore.Sessions().DeleteByUserID(ctx, userID); err != nil {
			return apperrors.New(apperrors.CodeInternalError, "failed to invalidate all sessions", err)
		}
		return nil
	})
	if err != nil {
		return err
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
	oldRecord, err := s.store.Sessions().GetByIDHash(ctx, oldHash)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", apperrors.ErrSessionInvalid
		}
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to rotate session", err)
	}

	now := time.Now().UTC()
	if now.After(oldRecord.LastActiveAt.Add(s.cfg.SessionIdleTimeout)) {
		affected, err := s.store.Sessions().DeleteIfStaleByIDHash(ctx, oldHash, oldRecord.LastActiveAt)
		if err != nil {
			return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to delete expired session", err)
		}
		if affected == 0 {
			reloaded, err := s.store.Sessions().GetByIDHash(ctx, oldHash)
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, "", apperrors.ErrSessionExpired
				}
				return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to reload session", err)
			}
			oldRecord = reloaded
			if now.After(oldRecord.LastActiveAt.Add(s.cfg.SessionIdleTimeout)) || now.After(oldRecord.AbsoluteExpiresAt) {
				_, _ = s.store.Sessions().DeleteIfStaleByIDHash(ctx, oldHash, oldRecord.LastActiveAt)
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
	if now.After(oldRecord.AbsoluteExpiresAt) {
		_, _ = s.store.Sessions().DeleteByIDHash(ctx, oldHash)
		slog.InfoContext(ctx, "session_expired",
			"user_id", oldRecord.UserID.String(),
			"reason", "rotate_expired",
		)
		return nil, "", apperrors.ErrSessionExpired
	}

	rawID, err := generateRawID()
	if err != nil {
		return nil, "", apperrors.New(apperrors.CodeInternalError, "failed to generate new session ID", err)
	}

	if ip == "" {
		ip = oldRecord.IPAddress
	}
	if userAgent == "" {
		userAgent = oldRecord.UserAgent
	}

	var (
		newRecord *db.Session
		rotateErr error
	)

	err = s.store.Transaction(ctx, func(txStore db.Store) error {
		user, uerr := txStore.Users().GetByIDForUpdate(ctx, oldRecord.UserID)
		if uerr != nil {
			if errors.Is(uerr, gorm.ErrRecordNotFound) {
				_, _ = txStore.Sessions().DeleteByIDHash(ctx, oldHash)
				slog.InfoContext(ctx, "session_invalidated",
					"user_id", oldRecord.UserID.String(),
					"reason", "missing_user_at_rotate",
				)
				rotateErr = apperrors.ErrSessionInvalid
				return nil
			}
			return apperrors.New(apperrors.CodeInternalError, "failed to query user", uerr)
		}
		currentVersion := user.CredentialVersion
		if currentVersion != oldRecord.CredentialVersion {
			_, _ = txStore.Sessions().DeleteByIDHash(ctx, oldHash)
			slog.InfoContext(ctx, "session_invalidated",
				"user_id", oldRecord.UserID.String(),
				"reason", "credential_version_mismatch",
			)
			rotateErr = apperrors.ErrSessionInvalid
			return nil
		}

		resRows, err := txStore.Sessions().DeleteByIDHash(ctx, oldHash)
		if err != nil {
			return apperrors.New(apperrors.CodeInternalError, "failed to rotate session", err)
		}
		if resRows == 0 {
			rotateErr = apperrors.ErrSessionInvalid
			return nil
		}

		now = time.Now().UTC()
		if !oldRecord.AbsoluteExpiresAt.After(now) || !oldRecord.LastActiveAt.Add(s.cfg.SessionIdleTimeout).After(now) {
			slog.InfoContext(ctx, "session_expired",
				"user_id", oldRecord.UserID.String(),
				"reason", "rotate_expired",
			)
			rotateErr = apperrors.ErrSessionExpired
			return nil
		}

		newRecord = &db.Session{
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

		if err := txStore.Sessions().Create(ctx, newRecord); err != nil {
			return apperrors.New(apperrors.CodeInternalError, "failed to create rotated session", err)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if rotateErr != nil {
		return nil, "", rotateErr
	}

	return fromDB(newRecord), rawID, nil
}

func (s *service) ListSessions(ctx context.Context, userID uuid.UUID) ([]*Session, error) {
	now := time.Now().UTC()
	idleCutoff := now.Add(-s.cfg.SessionIdleTimeout)

	// 1. Purge expired sessions for this user
	_ = s.store.Sessions().DeleteExpiredByUserID(ctx, userID, now, idleCutoff)

	// 2. Fetch active sessions with bounded limit, defensively filtering out expired sessions
	records, err := s.store.Sessions().ListByUserID(ctx, userID)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeInternalError, "failed to list sessions", err)
	}

	sessions := make([]*Session, len(records))
	for i := range records {
		sessions[i] = fromDB(records[i])
	}
	return sessions, nil
}

// PurgeExpired deletes all sessions past their absolute expiration or idle timeout across all users.
func (s *service) PurgeExpired(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	idleCutoff := now.Add(-s.cfg.SessionIdleTimeout)
	n, err := s.store.Sessions().DeleteExpired(ctx, now, idleCutoff)
	if err != nil {
		return 0, apperrors.New(apperrors.CodeInternalError, "failed to purge expired sessions", err)
	}
	return n, nil
}
