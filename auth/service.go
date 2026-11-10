package auth

import (
	"context"
	"log"
	"time"

	"gorm.io/gorm"

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
	VerifyEmail(ctx context.Context, req db.VerifyEmailRequest) error
	RequestPasswordReset(ctx context.Context, req db.PasswordResetRequest) (string, error)
	ResetPassword(ctx context.Context, req db.PasswordResetConfirmRequest) error
}

type authService struct {
	cfg        config.Config
	db         *gorm.DB
	hooks      email.Hooks
	dummyHash  string
	hashParams crypto.HashParams
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
		cfg:        cfg,
		db:         database,
		hooks:      hooks,
		dummyHash:  dummyHash,
		hashParams: hashParams,
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
		// Anti-enumeration parity: perform dummy hashing and scheduling
		_, _ = crypto.HashPassword(req.Password, s.hashParams)
		go func() {}()
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
			return nil, errors.New(errors.CodeInvalidCredentials, "invalid email or password", nil)
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query user")
	}

	match, err := crypto.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !match {
		return nil, errors.New(errors.CodeInvalidCredentials, "invalid email or password", nil)
	}

	if s.cfg.RequireEmailVerification && !user.EmailVerified {
		return nil, errors.New(errors.CodeEmailNotVerified, "email address has not been verified", nil)
	}

	return &user, nil
}

// Logout invalidates the active session. Stubbed for Phase 4 session management.
func (s *authService) Logout(ctx context.Context, sessionID string) error {
	return nil
}

// VerifyEmail consumes a single-use verification token and marks the account verified.
func (s *authService) VerifyEmail(ctx context.Context, req db.VerifyEmailRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}

	tokenHash, err := crypto.HashToken(req.Token)
	if err != nil {
		return errors.New(errors.CodeInvalidToken, "invalid token", err)
	}

	var tok db.VerificationToken
	if err := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash[:]).First(&tok).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New(errors.CodeInvalidToken, "invalid token", nil)
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to query verification token")
	}

	if time.Now().UTC().After(tok.ExpiresAt) {
		_ = s.db.WithContext(ctx).Where("token_hash = ?", tokenHash[:]).Delete(&db.VerificationToken{}).Error
		return errors.New(errors.CodeTokenExpired, "verification token has expired", nil)
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Where("token_hash = ?", tokenHash[:]).Delete(&db.VerificationToken{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errors.New(errors.CodeInvalidToken, "invalid token", nil)
		}
		return tx.Model(&db.User{}).Where("id = ?", tok.UserID).Update("email_verified", true).Error
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to verify email")
	}

	return nil
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
			go func() {}()
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

	if err := s.db.WithContext(ctx).Create(&resetToken).Error; err != nil {
		return "", errors.Wrap(err, errors.CodeDatabaseError, "failed to create password reset token")
	}

	s.dispatchPasswordResetEmail(ctx, user.Email, rawToken)

	return rawToken, nil
}

// ResetPassword consumes a reset token, updates the password hash, and purges all
// active password reset tokens for the user (ASVS L1 token invalidation).
func (s *authService) ResetPassword(ctx context.Context, req db.PasswordResetConfirmRequest) error {
	if err := crypto.ValidatePassword(req.NewPassword, s.cfg.PasswordMinLength, s.cfg.PasswordMaxLength); err != nil {
		return err
	}

	tokenHash, err := crypto.HashToken(req.Token)
	if err != nil {
		return errors.New(errors.CodeInvalidToken, "invalid token", err)
	}

	var tok db.PasswordResetToken
	if err := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash[:]).First(&tok).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New(errors.CodeInvalidToken, "invalid token", nil)
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to query password reset token")
	}

	if time.Now().UTC().After(tok.ExpiresAt) {
		_ = s.db.WithContext(ctx).Where("token_hash = ?", tokenHash[:]).Delete(&db.PasswordResetToken{}).Error
		return errors.New(errors.CodeTokenExpired, "password reset token has expired", nil)
	}

	newHash, err := crypto.HashPassword(req.NewPassword, s.hashParams)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalError, "failed to hash password")
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Where("token_hash = ?", tokenHash[:]).Delete(&db.PasswordResetToken{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errors.New(errors.CodeInvalidToken, "invalid token", nil)
		}

		if err := tx.Model(&db.User{}).Where("id = ?", tok.UserID).Update("password_hash", newHash).Error; err != nil {
			return err
		}

		return tx.Where("user_id = ?", tok.UserID).Delete(&db.PasswordResetToken{}).Error
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to reset password")
	}

	return nil
}

func (s *authService) dispatchVerificationEmail(ctx context.Context, recipient, token string) {
	if s.hooks.SendVerificationEmail == nil {
		go func() {}()
		return
	}
	detachedCtx := context.Background()
	if ctx != nil {
		detachedCtx = context.WithoutCancel(ctx)
	}
	go func() {
		if err := s.hooks.SendVerificationEmail(detachedCtx, recipient, token); err != nil {
			log.Printf("email: failed to send verification email to %s: %v", recipient, err)
		}
	}()
}

func (s *authService) dispatchPasswordResetEmail(ctx context.Context, recipient, token string) {
	if s.hooks.SendPasswordResetEmail == nil {
		go func() {}()
		return
	}
	detachedCtx := context.Background()
	if ctx != nil {
		detachedCtx = context.WithoutCancel(ctx)
	}
	go func() {
		if err := s.hooks.SendPasswordResetEmail(detachedCtx, recipient, token); err != nil {
			log.Printf("email: failed to send password reset email to %s: %v", recipient, err)
		}
	}()
}
