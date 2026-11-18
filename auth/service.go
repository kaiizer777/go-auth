package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/google/uuid"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
)

// Service defines the business operations for core user authentication.
type Service interface {
	Signup(ctx context.Context, req db.SignupRequest) (*db.User, string, error)
	Login(ctx context.Context, req db.LoginRequest) (*db.User, error)
	Logout(ctx context.Context, sessionID string) error
	VerifyEmail(ctx context.Context, req db.VerifyEmailRequest) (*db.User, error)
	RequestPasswordReset(ctx context.Context, req db.PasswordResetRequest) (string, error)
	ResetPassword(ctx context.Context, req db.PasswordResetConfirmRequest) (*db.User, error)
}

const emailDispatchSemaphoreSize = 128

// emailDispatchPendingSize bounds the number of dispatch goroutines that may
// park waiting for a semaphore slot, preventing unbounded goroutine/memory
// growth under sustained saturated dispatch traffic.
const emailDispatchPendingSize = 256

type authService struct {
	cfg               config.Config
	db                *gorm.DB
	hooks             email.Hooks
	dummyHash         string
	hashParams        crypto.HashParams
	emailSem          chan struct{}
	emailPendingSem   chan struct{}
	recoveryMu        sync.Mutex
	onPreRecoveryLock func()
}

// New constructs a new concrete auth Service.
func New(cfg config.Config, database *gorm.DB, hooks email.Hooks) (Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, errors.Wrap(err, errors.CodeInvalidConfig, "invalid config")
	}
	if database == nil {
		return nil, errors.New(errors.CodeDatabaseError, "database connection is required", nil)
	}

	hashParams := crypto.HashParams{
		Memory:      cfg.Argon2.Memory,
		Time:        cfg.Argon2.Time,
		Parallelism: cfg.Argon2.Parallelism,
		SaltLength:  cfg.Argon2.SaltLength,
		KeyLength:   cfg.Argon2.KeyLength,
	}

	dummyHash, err := crypto.GenerateDummyHash(hashParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalError, "failed to generate dummy hash")
	}

	return &authService{
		cfg:             cfg,
		db:              database,
		hooks:           hooks,
		dummyHash:       dummyHash,
		hashParams:      hashParams,
		emailSem:        make(chan struct{}, emailDispatchSemaphoreSize),
		emailPendingSem: make(chan struct{}, emailDispatchPendingSize),
	}, nil
}

// Signup registers a new user, hashes credentials with Argon2id, creates a verification
// token, and dispatches a verification email. If the email already exists, it executes
// anti-enumeration dummy parity operations and returns silent success.
func (s *authService) Signup(ctx context.Context, req db.SignupRequest) (*db.User, string, error) {
	if err := db.ValidateEmail(req.Email); err != nil {
		return nil, "", err
	}
	if err := crypto.ValidatePassword(req.Password, s.cfg.PasswordMinLength, s.cfg.PasswordMaxLength); err != nil {
		return nil, "", err
	}

	var existing db.User
	err := s.db.WithContext(ctx).Where("LOWER(email) = LOWER(?)", req.Email).First(&existing).Error
	if err == nil {
		// Recovery: if the account is still unverified (e.g. a dropped
		// verification email), bind the new (caller-supplied) password to a
		// fresh verification token so an attacker-set password on the original
		// unverified account cannot be activated by verification. Invalidate
		// any prior verification tokens for this user first.
		if !existing.EmailVerified {
			if s.onPreRecoveryLock != nil {
				s.onPreRecoveryLock()
			}
			s.recoveryMu.Lock()
			defer s.recoveryMu.Unlock()

			// Re-check under the lock to avoid racing recoveries overwriting
			// each other's password/token state.
			var latest db.User
			if rerr := s.db.WithContext(ctx).Where("id = ?", existing.ID).First(&latest).Error; rerr == nil {
				existing = latest
			}
			if !existing.EmailVerified {
				passwordHash, herr := crypto.HashPassword(req.Password, s.hashParams)
				if herr != nil {
					return nil, "", errors.Wrap(herr, errors.CodeInternalError, "failed to hash password")
				}
				rawToken, tokenHash, gerr := crypto.GenerateToken()
				if gerr != nil {
					return nil, "", errors.Wrap(gerr, errors.CodeInternalError, "failed to generate verification token")
				}
				now := time.Now().UTC()
				var updated bool
				if terr := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
					res := tx.Model(&db.User{}).Where("id = ? AND email_verified = ?", existing.ID, false).Updates(map[string]any{
						"password_hash":      passwordHash,
						"credential_version": gorm.Expr("credential_version + 1"),
					})
					if res.Error != nil {
						return res.Error
					}
					if res.RowsAffected == 0 {
						// Already verified or updated concurrently
						return nil
					}
					updated = true
					if err := tx.Where("user_id = ?", existing.ID).Delete(&db.VerificationToken{}).Error; err != nil {
						return err
					}
					if err := tx.Where("user_id = ?", existing.ID).Delete(&db.Session{}).Error; err != nil {
						return err
					}
					tok := db.VerificationToken{
						TokenHash: tokenHash[:],
						UserID:    existing.ID,
						ExpiresAt: now.Add(s.cfg.VerificationTokenExpiry),
						CreatedAt: now,
					}
					return tx.Create(&tok).Error
				}); terr != nil {
					return nil, "", errors.Wrap(terr, errors.CodeDatabaseError, "failed to update unverified account")
				}
				if updated {
					s.dispatchVerificationEmail(ctx, existing.Email, rawToken)
				}
				// Recovery already performed real hashing; return immediately without redundant dummy hash.
				return nil, "", nil
			}
		}
		// Anti-enumeration parity: perform dummy hashing only for verified accounts where real hashing was skipped.
		_, _ = crypto.HashPassword(req.Password, s.hashParams)
		return nil, "", nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, "", errors.Wrap(err, errors.CodeDatabaseError, "failed to query user")
	}

	passwordHash, err := crypto.HashPassword(req.Password, s.hashParams)
	if err != nil {
		return nil, "", errors.Wrap(err, errors.CodeInternalError, "failed to hash password")
	}

	rawToken, tokenHash, err := crypto.GenerateToken()
	if err != nil {
		return nil, "", errors.Wrap(err, errors.CodeInternalError, "failed to generate verification token")
	}

	user := db.User{
		ID:            uuid.New(),
		Email:         req.Email,
		PasswordHash:  passwordHash,
		EmailVerified: false,
	}

	now := time.Now().UTC()
	tok := db.VerificationToken{
		TokenHash: tokenHash[:],
		UserID:    user.ID,
		ExpiresAt: now.Add(s.cfg.VerificationTokenExpiry),
		CreatedAt: now,
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		tok.UserID = user.ID
		return tx.Create(&tok).Error
	})
	if err != nil {
		var existingUser db.User
		if queryErr := s.db.WithContext(ctx).Where("LOWER(email) = LOWER(?)", req.Email).First(&existingUser).Error; queryErr == nil {
			// Anti-enumeration parity: concurrent signup succeeded
			_, _ = crypto.HashPassword(req.Password, s.hashParams)
			return nil, "", nil
		}
		return nil, "", errors.Wrap(err, errors.CodeDatabaseError, "failed to create user")
	}

	s.dispatchVerificationEmail(ctx, user.Email, rawToken)

	return &user, rawToken, nil
}

// Login verifies credentials using constant-time Argon2id comparison and returns the user.
func (s *authService) Login(ctx context.Context, req db.LoginRequest) (*db.User, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	var user db.User
	err := s.db.WithContext(ctx).Where("LOWER(email) = LOWER(?)", req.Email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_, _ = crypto.VerifyPassword(req.Password, s.dummyHash)
			return nil, errors.ErrInvalidCredentials
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query user")
	}

	match, err := crypto.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !match {
		if err != nil {
			// Empty or unusable hash (OAuth-only account): burn dummy Argon2id
			// work so login timing never reveals the account has no password.
			_, _ = crypto.VerifyPassword(req.Password, s.dummyHash)
		}
		return nil, errors.ErrInvalidCredentials
	}

	if s.cfg.RequireEmailVerification && !user.EmailVerified {
		return nil, errors.ErrEmailNotVerified
	}

	return &user, nil
}

// Logout invalidates the active session by hashed token.
func (s *authService) Logout(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(sessionID))
	idHash := hex.EncodeToString(sum[:])
	if err := s.db.WithContext(ctx).Where("id_hash = ?", idHash).Delete(&db.Session{}).Error; err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete session")
	}
	return nil
}

// VerifyEmail consumes a single-use verification token and marks the account verified.
func (s *authService) VerifyEmail(ctx context.Context, req db.VerifyEmailRequest) (*db.User, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	tokenHash, err := crypto.HashToken(req.Token)
	if err != nil {
		return nil, errors.ErrInvalidToken
	}

	var isExpired bool
	var verifiedUser db.User
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var tok db.VerificationToken
		if err := tx.Where("token_hash = ?", tokenHash[:]).First(&tok).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errors.ErrInvalidToken
			}
			return errors.Wrap(err, errors.CodeDatabaseError, "failed to query verification token")
		}

		if time.Now().UTC().After(tok.ExpiresAt) {
			isExpired = true
			return tx.Where("token_hash = ?", tokenHash[:]).Delete(&db.VerificationToken{}).Error
		}

		res := tx.Where("token_hash = ?", tokenHash[:]).Delete(&db.VerificationToken{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errors.ErrInvalidToken
		}

		if err := tx.Model(&db.User{}).Where("id = ?", tok.UserID).Update("email_verified", true).Error; err != nil {
			return err
		}
		// Load inside the transaction: a post-commit read failure would report
		// an error for an already-consumed token, making retry impossible.
		// Here the read failure rolls back instead, preserving retry.
		return tx.Where("id = ?", tok.UserID).First(&verifiedUser).Error
	})
	if err != nil {
		var appErr *errors.Error
		if errors.As(err, &appErr) && (appErr.Code() == errors.CodeInvalidToken || appErr.Code() == errors.CodeTokenExpired) {
			return nil, err
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to verify email")
	}
	if isExpired {
		return nil, errors.ErrTokenExpired
	}

	return &verifiedUser, nil
}

// lockForUpdate applies SELECT ... FOR UPDATE on dialects with row locking.
func lockForUpdate(tx *gorm.DB) *gorm.DB {
	if strings.Contains(strings.ToLower(tx.Name()), "sqlite") {
		return tx
	}
	return tx.Clauses(clause.Locking{Strength: "UPDATE"})
}

// RequestPasswordReset initiates a password reset flow, generating a single-use token.
// Non-existent emails trigger anti-enumeration parity operations and return silent success.
func (s *authService) RequestPasswordReset(ctx context.Context, req db.PasswordResetRequest) (string, error) {
	if err := req.Validate(); err != nil {
		return "", err
	}

	var user db.User
	err := s.db.WithContext(ctx).Where("LOWER(email) = LOWER(?)", req.Email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_, _, _ = crypto.GenerateToken()
			// Anti-enumeration timing parity: perform a simulated DB query to equalize latency with found branch
			var dummy db.PasswordResetToken
			_ = s.db.WithContext(ctx).Where("user_id = ?", uuid.Nil).First(&dummy).Error
			return "", nil
		}
		return "", errors.Wrap(err, errors.CodeDatabaseError, "failed to query user")
	}

	rawToken, tokenHash, err := crypto.GenerateToken()
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalError, "failed to generate password reset token")
	}

	now := time.Now().UTC()
	resetToken := db.PasswordResetToken{
		TokenHash: tokenHash[:],
		UserID:    user.ID,
		ExpiresAt: now.Add(s.cfg.PasswordResetTokenExpiry),
		CreatedAt: now,
	}

	// Invalidate prior unconsumed reset tokens. Serialize per-user via a row lock
	// on the user record so concurrent requests under READ COMMITTED cannot race.
	if terr := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var lockedUser db.User
		if err := lockForUpdate(tx).Select("id").Where("id = ?", user.ID).First(&lockedUser).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", user.ID).Delete(&db.PasswordResetToken{}).Error; err != nil {
			return err
		}
		return tx.Create(&resetToken).Error
	}); terr != nil {
		return "", errors.Wrap(terr, errors.CodeDatabaseError, "failed to create password reset token")
	}

	s.dispatchPasswordResetEmail(ctx, user.Email, rawToken)

	return rawToken, nil
}

// ResetPassword consumes a reset token, updates the password hash, and purges all
// active password reset tokens for the user (ASVS L1 token invalidation).
func (s *authService) ResetPassword(ctx context.Context, req db.PasswordResetConfirmRequest) (*db.User, error) {
	if err := crypto.ValidatePassword(req.NewPassword, s.cfg.PasswordMinLength, s.cfg.PasswordMaxLength); err != nil {
		return nil, err
	}

	tokenHash, err := crypto.HashToken(req.Token)
	if err != nil {
		return nil, errors.ErrInvalidToken
	}

	// Cheap existence/expiry gate before the expensive Argon2id hash: unknown
	// or expired tokens must not trigger a ~64MiB hashing operation.
	var tok db.PasswordResetToken
	if err := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash[:]).First(&tok).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.ErrInvalidToken
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query password reset token")
	}

	if time.Now().UTC().After(tok.ExpiresAt) {
		_ = s.db.WithContext(ctx).Where("token_hash = ?", tokenHash[:]).Delete(&db.PasswordResetToken{}).Error
		return nil, errors.ErrTokenExpired
	}

	newHash, err := crypto.HashPassword(req.NewPassword, s.hashParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalError, "failed to hash password")
	}

	var resetUser db.User
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var lockedUser db.User
		if err := lockForUpdate(tx).Select("id").Where("id = ?", tok.UserID).First(&lockedUser).Error; err != nil {
			return err
		}

		res := tx.Where("token_hash = ? AND expires_at > ?", tokenHash[:], time.Now().UTC()).Delete(&db.PasswordResetToken{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			var count int64
			if err := tx.Model(&db.PasswordResetToken{}).Where("token_hash = ?", tokenHash[:]).Count(&count).Error; err != nil {
				return err
			}
			if count > 0 {
				_ = tx.Where("token_hash = ?", tokenHash[:]).Delete(&db.PasswordResetToken{}).Error
				return errors.ErrTokenExpired
			}
			return errors.ErrInvalidToken
		}

		if err := tx.Model(&db.User{}).Where("id = ?", tok.UserID).Updates(map[string]any{
			"password_hash":      newHash,
			"credential_version": gorm.Expr("credential_version + 1"),
		}).Error; err != nil {
			return err
		}

		if err := tx.Where("user_id = ?", tok.UserID).Delete(&db.PasswordResetToken{}).Error; err != nil {
			return err
		}

		if err := tx.Where("user_id = ?", tok.UserID).Delete(&db.Session{}).Error; err != nil {
			return err
		}
		// Load inside the transaction: a post-commit read failure would report
		// an error for an already-consumed token, making retry impossible.
		// Here the read failure rolls back instead, preserving retry.
		return tx.Where("id = ?", tok.UserID).First(&resetUser).Error
	})
	if err != nil {
		var appErr *errors.Error
		if errors.As(err, &appErr) && (appErr.Code() == errors.CodeInvalidToken || appErr.Code() == errors.CodeTokenExpired) {
			return nil, err
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to reset password")
	}

	return &resetUser, nil
}

// emailHookTimeout returns the bound for email hook execution, defaulting to
// 10s when the configuration carries no positive timeout.
func (s *authService) emailHookTimeout() time.Duration {
	if s.cfg.EmailDispatchTimeout > 0 {
		return s.cfg.EmailDispatchTimeout
	}
	return 10 * time.Second
}

// tryAcquireEmailSlot non-blockingly acquires a dispatch slot so request
// handlers never stall on a saturated semaphore; it reports whether the
// caller must release the slot after dispatch.
func (s *authService) tryAcquireEmailSlot(recipient string) bool {
	if s.emailSem == nil {
		return false
	}
	select {
	case s.emailSem <- struct{}{}:
		return true
	default:
		slog.Info("email: dispatch queue saturated, parking bounded retry", slog.String("recipient", recipient))
		return false
	}
}

// dispatchEmailAsync runs send on a semaphore slot without blocking the caller.
// When the semaphore is saturated it parks a bounded waiter that retries
// acquisition, so verification and reset work is retained instead of silently
// dropped; the request path still returns immediately.
func (s *authService) dispatchEmailAsync(ctx context.Context, recipient, token, op string, send func(context.Context, string, string) error) {
	detached := context.Background()
	if ctx != nil {
		detached = context.WithoutCancel(ctx)
	}
	run := func() {
		timeoutCtx, cancel := context.WithTimeout(detached, s.emailHookTimeout())
		defer cancel()
		if s.emailSem != nil {
			defer func() { <-s.emailSem }()
		}
		defer func() {
			if r := recover(); r != nil {
				slog.ErrorContext(timeoutCtx, "email: panic recovered in email dispatch",
					slog.String("operation", op),
					slog.String("recipient", recipient),
					slog.Any("panic", r),
				)
			}
		}()
		if err := send(timeoutCtx, recipient, token); err != nil {
			slog.WarnContext(timeoutCtx, "email: failed to send email",
				slog.String("operation", op),
				slog.String("recipient", recipient),
				slog.String("error", err.Error()),
			)
		}
	}
	if s.emailSem == nil {
		go run()
		return
	}
	if s.tryAcquireEmailSlot(recipient) {
		go run()
		return
	}
	// Bound pending dispatch work: only a fixed number of goroutines may park
	// waiting for a slot; overflow is dropped instead of accumulating.
	if s.emailPendingSem != nil {
		select {
		case s.emailPendingSem <- struct{}{}:
		default:
			slog.Warn("email: dispatch queue overflow, dropping",
				slog.String("operation", op),
				slog.String("recipient", recipient),
			)
			return
		}
	}
	go func() {
		if s.emailPendingSem != nil {
			defer func() { <-s.emailPendingSem }()
		}
		wait, cancel := context.WithTimeout(context.Background(), s.emailHookTimeout())
		defer cancel()
		select {
		case s.emailSem <- struct{}{}:
			run()
		case <-wait.Done():
			slog.Warn("email: dispatch queue saturated, giving up",
				slog.String("operation", op),
				slog.String("recipient", recipient),
			)
		}
	}()
}

func (s *authService) dispatchVerificationEmail(ctx context.Context, recipient, token string) {
	if s.hooks.SendVerificationEmail == nil {
		return
	}
	s.dispatchEmailAsync(ctx, recipient, token, "verification", s.hooks.SendVerificationEmail)
}

func (s *authService) dispatchPasswordResetEmail(ctx context.Context, recipient, token string) {
	if s.hooks.SendPasswordResetEmail == nil {
		return
	}
	s.dispatchEmailAsync(ctx, recipient, token, "password reset", s.hooks.SendPasswordResetEmail)
}
