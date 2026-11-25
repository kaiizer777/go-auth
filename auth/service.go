package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/google/uuid"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
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
	store             db.Store
	hooks             email.Hooks
	dummyHash         string
	hashParams        crypto.HashParams
	emailSem          chan struct{}
	emailPendingSem   chan struct{}
	recoveryMu        sync.Mutex
	onPreRecoveryLock func()
}

// NewWithStore constructs a new concrete auth Service using an abstract db.Store.
func NewWithStore(cfg config.Config, store db.Store, hooks email.Hooks) (Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, errors.Wrap(err, errors.CodeInvalidConfig, "invalid config")
	}
	if store == nil {
		return nil, errors.New(errors.CodeDatabaseError, "store is required", nil)
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
		store:           store,
		hooks:           hooks,
		dummyHash:       dummyHash,
		hashParams:      hashParams,
		emailSem:        make(chan struct{}, emailDispatchSemaphoreSize),
		emailPendingSem: make(chan struct{}, emailDispatchPendingSize),
	}, nil
}

// New constructs a new concrete auth Service using a GORM database connection.
func New(cfg config.Config, database *gorm.DB, hooks email.Hooks) (Service, error) {
	if database == nil {
		return nil, errors.New(errors.CodeDatabaseError, "database connection is required", nil)
	}
	return NewWithStore(cfg, gormstore.New(database), hooks)
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

	existing, err := s.store.Users().GetByEmail(ctx, req.Email)
	if err == nil && existing != nil {
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
			latest, rerr := s.store.Users().GetByID(ctx, existing.ID)
			if rerr == nil && latest != nil {
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
				if terr := s.store.Transaction(ctx, func(txStore db.Store) error {
					user, err := txStore.Users().GetByIDForUpdate(ctx, existing.ID)
					if err != nil {
						return err
					}
					if user.EmailVerified {
						return nil
					}
					if err := txStore.Users().UpdatePassword(ctx, user.ID, passwordHash); err != nil {
						return err
					}
					if _, err := txStore.Users().IncrementCredentialVersion(ctx, user.ID); err != nil {
						return err
					}
					if err := purgeUnverifiedLinks(ctx, txStore, user.ID); err != nil {
						return err
					}
					if err := txStore.VerificationTokens().DeleteByUserID(ctx, user.ID); err != nil {
						return err
					}
					if err := txStore.Sessions().DeleteByUserID(ctx, user.ID); err != nil {
						return err
					}
					tok := db.VerificationToken{
						TokenHash: tokenHash[:],
						UserID:    user.ID,
						ExpiresAt: now.Add(s.cfg.VerificationTokenExpiry),
						CreatedAt: now,
					}
					if err := txStore.VerificationTokens().Create(ctx, &tok); err != nil {
						return err
					}
					updated = true
					return nil
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
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
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

	err = s.store.Transaction(ctx, func(txStore db.Store) error {
		if err := txStore.Users().Create(ctx, &user); err != nil {
			return err
		}
		tok.UserID = user.ID
		return txStore.VerificationTokens().Create(ctx, &tok)
	})
	if err != nil {
		if existingUser, queryErr := s.store.Users().GetByEmail(ctx, req.Email); queryErr == nil && existingUser != nil {
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

	user, err := s.store.Users().GetByEmail(ctx, req.Email)
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

	return user, nil
}

// Logout invalidates the active session by hashed token.
func (s *authService) Logout(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(sessionID))
	idHash := hex.EncodeToString(sum[:])
	if _, err := s.store.Sessions().DeleteByIDHash(ctx, idHash); err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete session")
	}
	return nil
}

// VerifyEmail consumes a single-use verification token and marks the account verified.
// The claim also invalidates the account's unverified OAuth links: they were
// built from a provider claim nobody proved, and the proven owner takes the
// account back.
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
	err = s.store.Transaction(ctx, func(txStore db.Store) error {
		tok, err := txStore.VerificationTokens().GetByTokenHash(ctx, tokenHash[:])
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errors.ErrInvalidToken
			}
			return errors.Wrap(err, errors.CodeDatabaseError, "failed to query verification token")
		}

		if time.Now().UTC().After(tok.ExpiresAt) {
			isExpired = true
			_, err := txStore.VerificationTokens().Delete(ctx, tokenHash[:])
			return err
		}

		if _, err := txStore.Users().GetByIDForUpdate(ctx, tok.UserID); err != nil {
			return err
		}

		rows, err := txStore.VerificationTokens().Delete(ctx, tokenHash[:])
		if err != nil {
			return err
		}
		if rows == 0 {
			return errors.ErrInvalidToken
		}

		if err := txStore.Users().SetEmailVerified(ctx, tok.UserID, true); err != nil {
			return err
		}
		if _, err := txStore.Users().IncrementCredentialVersion(ctx, tok.UserID); err != nil {
			return err
		}
		if err := purgeUnverifiedLinks(ctx, txStore, tok.UserID); err != nil {
			return err
		}
		if err := txStore.VerificationTokens().DeleteByUserID(ctx, tok.UserID); err != nil {
			return err
		}
		if err := txStore.Sessions().DeleteByUserID(ctx, tok.UserID); err != nil {
			return err
		}
		u, uerr := txStore.Users().GetByID(ctx, tok.UserID)
		if uerr != nil {
			return uerr
		}
		verifiedUser = *u
		return nil
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

// RequestPasswordReset initiates a password reset flow, generating a single-use token.
// Non-existent emails trigger anti-enumeration parity operations and return silent success.
func (s *authService) RequestPasswordReset(ctx context.Context, req db.PasswordResetRequest) (string, error) {
	if err := req.Validate(); err != nil {
		return "", err
	}

	user, err := s.store.Users().GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_, _, _ = crypto.GenerateToken()
			// Anti-enumeration timing parity: perform a simulated DB query to equalize latency with found branch
			var dummyToken []byte
			_, _ = s.store.PasswordResetTokens().GetByTokenHash(ctx, dummyToken)
			return "", nil
		}
		return "", errors.Wrap(err, errors.CodeDatabaseError, "failed to query user")
	}

	var rawToken string
	// Invalidate prior unconsumed reset tokens. Serialize per-user via a row lock
	// on the user record so concurrent requests under READ COMMITTED cannot race.
	if terr := s.store.Transaction(ctx, func(txStore db.Store) error {
		if _, err := txStore.Users().GetByIDForUpdate(ctx, user.ID); err != nil {
			return err
		}
		if err := txStore.PasswordResetTokens().DeleteByUserID(ctx, user.ID); err != nil {
			return err
		}

		tok, tokenHash, gerr := crypto.GenerateToken()
		if gerr != nil {
			return errors.Wrap(gerr, errors.CodeInternalError, "failed to generate password reset token")
		}
		rawToken = tok

		now := time.Now().UTC()
		resetToken := db.PasswordResetToken{
			TokenHash: tokenHash[:],
			UserID:    user.ID,
			ExpiresAt: now.Add(s.cfg.PasswordResetTokenExpiry),
			CreatedAt: now,
		}

		return txStore.PasswordResetTokens().Create(ctx, &resetToken)
	}); terr != nil {
		return "", errors.Wrap(terr, errors.CodeDatabaseError, "failed to create password reset token")
	}

	s.dispatchPasswordResetEmail(ctx, user.Email, rawToken)

	return rawToken, nil
}

// ResetPassword consumes a reset token, updates the password hash, and purges all
// active password reset tokens for the user (ASVS L1 token invalidation). A
// consumed token also proves the caller reads the mailbox, so the account is
// marked email-verified and its unverified OAuth links are deleted: an attested
// link keeps working, a link built from an unverified provider claim does not.
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
	tok, err := s.store.PasswordResetTokens().GetByTokenHash(ctx, tokenHash[:])
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.ErrInvalidToken
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query password reset token")
	}

	if time.Now().UTC().After(tok.ExpiresAt) {
		_, _ = s.store.PasswordResetTokens().Delete(ctx, tokenHash[:])
		return nil, errors.ErrTokenExpired
	}

	newHash, err := crypto.HashPassword(req.NewPassword, s.hashParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalError, "failed to hash password")
	}

	var resetUser db.User
	err = s.store.Transaction(ctx, func(txStore db.Store) error {
		if _, err := txStore.Users().GetByIDForUpdate(ctx, tok.UserID); err != nil {
			return err
		}

		consumed, err := txStore.PasswordResetTokens().ConsumeToken(ctx, tokenHash[:], time.Now().UTC())
		if err != nil {
			return err
		}
		if !consumed {
			if countTok, _ := txStore.PasswordResetTokens().GetByTokenHash(ctx, tokenHash[:]); countTok != nil {
				_, _ = txStore.PasswordResetTokens().Delete(ctx, tokenHash[:])
				return errors.ErrTokenExpired
			}
			return errors.ErrInvalidToken
		}

		if err := txStore.Users().UpdatePassword(ctx, tok.UserID, newHash); err != nil {
			return err
		}
		// A consumed reset token proves the caller reads the mailbox, so the
		// address is now locally verified: claimed for link attachment, and no
		// unverified provider link may keep minting sessions on this account.
		if err := txStore.Users().SetEmailVerified(ctx, tok.UserID, true); err != nil {
			return err
		}
		if _, err := txStore.Users().IncrementCredentialVersion(ctx, tok.UserID); err != nil {
			return err
		}

		if err := purgeUnverifiedLinks(ctx, txStore, tok.UserID); err != nil {
			return err
		}

		if err := txStore.PasswordResetTokens().DeleteByUserID(ctx, tok.UserID); err != nil {
			return err
		}

		if err := txStore.Sessions().DeleteByUserID(ctx, tok.UserID); err != nil {
			return err
		}

		u, err := txStore.Users().GetByID(ctx, tok.UserID)
		if err != nil {
			return err
		}
		resetUser = *u
		return nil
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

// purgeUnverifiedLinks deletes the oauth links whose provider never attested the
// address. It runs when the account's address becomes locally proven: from then
// on an unverified link is untrusted, so it is removed instead of left behind to
// be rejected on its next callback. Attested links are legitimate login methods
// and are never touched.
func purgeUnverifiedLinks(ctx context.Context, store db.Store, userID uuid.UUID) error {
	links, err := store.OAuthAccounts().GetByUserID(ctx, userID)
	if err != nil {
		return err
	}
	for _, link := range links {
		if link == nil || link.Verified {
			continue
		}
		if err := store.OAuthAccounts().Delete(ctx, link.ID); err != nil {
			return err
		}
	}
	return nil
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
