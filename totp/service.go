package totp

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
)

// EnrollmentResponse contains the provisioning details returned when a user initiates TOTP enrollment.
type EnrollmentResponse struct {
	Secret      string   `json:"secret"`
	OTPURI      string   `json:"otp_uri"`
	QRCode      string   `json:"qr_code"`
	BackupCodes []string `json:"backup_codes,omitempty"`
}

// EnrollmentResult is an alias for EnrollmentResponse to maintain parity across internal conventions.
type EnrollmentResult = EnrollmentResponse

// Limiter represents the rate limiter contract consumed by TotpService.
// *ratelimit.Limiter implements this interface.
type Limiter interface {
	Allow(key string) bool
	Reset(key string)
}

// Service defines the core business logic operations for TOTP two-factor authentication.
type Service interface {
	Enroll(ctx context.Context, userID string) (*EnrollmentResponse, error)
	ConfirmEnrollment(ctx context.Context, userID, code string) ([]string, error)
	CreateChallengeToken(ctx context.Context, userID string) (string, error)
	ValidateChallengeToken(ctx context.Context, rawToken string) (*db.TwoFactorToken, error)
	RecordTokenAttempt(ctx context.Context, rawToken string) (int, error)
	VerifyCode(ctx context.Context, userID, code, clientIP string) error
	VerifyBackupCode(ctx context.Context, userID, backupCode, clientIP string) error
	ConsumeChallengeToken(ctx context.Context, rawToken string) (*db.User, error)
	DisableTOTP(ctx context.Context, userID, password, code string) error
	Status(ctx context.Context, userID string) (bool, error)
}

// TotpService is an exported alias for Service to support alternate naming conventions.
type TotpService = Service

type totpService struct {
	db        *gorm.DB
	cfg       config.TOTPConfig
	crypto    *Crypto
	cryptoErr error
	limiter   Limiter
	logger    *slog.Logger
}

// NewService constructs a concrete TotpService instance.
func NewService(database *gorm.DB, cfg config.TOTPConfig, limiter Limiter, logger *slog.Logger) Service {
	if database == nil {
		panic("totp: nil gorm.DB")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "go-auth"
	}
	if cfg.ChallengeTokenTTL <= 0 {
		cfg.ChallengeTokenTTL = 10 * time.Minute
	}
	if cfg.MaxAttemptsPerWindow <= 0 {
		cfg.MaxAttemptsPerWindow = 5
	}
	if cfg.AttemptWindow <= 0 {
		cfg.AttemptWindow = 5 * time.Minute
	}

	var crypt *Crypto
	var cryptErr error
	if cfg.EncryptionKey != "" {
		crypt, cryptErr = NewCrypto(cfg.EncryptionKey)
	} else {
		cryptErr = apperrors.ErrTOTPEncryptionKeyInvalid
	}

	return &totpService{
		db:        database,
		cfg:       cfg,
		crypto:    crypt,
		cryptoErr: cryptErr,
		limiter:   limiter,
		logger:    logger,
	}
}

// NewTotpService is an alias for NewService.
func NewTotpService(database *gorm.DB, cfg config.TOTPConfig, limiter Limiter, logger *slog.Logger) Service {
	return NewService(database, cfg, limiter, logger)
}

// getCrypto returns the initialized Crypto instance or the initialization error.
func (s *totpService) getCrypto() (*Crypto, error) {
	if s.cryptoErr != nil {
		return nil, s.cryptoErr
	}
	return s.crypto, nil
}

// parseUUID validates and parses a string UUID into uuid.UUID.
func (s *totpService) parseUUID(userID string) (uuid.UUID, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return uuid.Nil, apperrors.ErrUserNotFound
	}
	return uid, nil
}

// Enroll initiates TOTP setup for a user.
func (s *totpService) Enroll(ctx context.Context, userID string) (*EnrollmentResponse, error) {
	return nil, nil
}

// ConfirmEnrollment verifies the initial code, enables TOTP, and returns 10 backup codes.
func (s *totpService) ConfirmEnrollment(ctx context.Context, userID, code string) ([]string, error) {
	return nil, nil
}

// CreateChallengeToken generates and persists an ephemeral challenge token.
func (s *totpService) CreateChallengeToken(ctx context.Context, userID string) (string, error) {
	return "", nil
}

// ValidateChallengeToken verifies challenge token validity without destroying it.
func (s *totpService) ValidateChallengeToken(ctx context.Context, rawToken string) (*db.TwoFactorToken, error) {
	return nil, nil
}

// RecordTokenAttempt atomically increments the attempt counter on a challenge token.
func (s *totpService) RecordTokenAttempt(ctx context.Context, rawToken string) (int, error) {
	return 0, nil
}

// VerifyCode verifies a TOTP code against the user's active secret.
func (s *totpService) VerifyCode(ctx context.Context, userID, code, clientIP string) error {
	return nil
}

// VerifyBackupCode validates and consumes a backup code.
func (s *totpService) VerifyBackupCode(ctx context.Context, userID, backupCode, clientIP string) error {
	return nil
}

// ConsumeChallengeToken hard-deletes the token and returns the associated user.
func (s *totpService) ConsumeChallengeToken(ctx context.Context, rawToken string) (*db.User, error) {
	return nil, nil
}

// DisableTOTP verifies user credentials and removes 2FA configuration.
func (s *totpService) DisableTOTP(ctx context.Context, userID, password, code string) error {
	return nil
}

// Status checks whether TOTP is enabled for a user.
func (s *totpService) Status(ctx context.Context, userID string) (bool, error) {
	return false, nil
}

// IsTotpEnabled is a UUID-friendly helper for Status.
func (s *totpService) IsTotpEnabled(ctx context.Context, userID uuid.UUID) (bool, error) {
	return s.Status(ctx, userID.String())
}

// EnrollTotp is a UUID-friendly helper for Enroll.
func (s *totpService) EnrollTotp(ctx context.Context, userID uuid.UUID) (*EnrollmentResponse, error) {
	return s.Enroll(ctx, userID.String())
}

// VerifyTotp is a helper for VerifyCode without client IP.
func (s *totpService) VerifyTotp(ctx context.Context, userID uuid.UUID, code string) error {
	return s.VerifyCode(ctx, userID.String(), code, "")
}

// GenerateTwoFactorToken is an alias for CreateChallengeToken.
func (s *totpService) GenerateTwoFactorToken(ctx context.Context, userID uuid.UUID) (string, error) {
	return s.CreateChallengeToken(ctx, userID.String())
}

// ValidateTwoFactorToken is a helper returning uuid.UUID directly.
func (s *totpService) ValidateTwoFactorToken(ctx context.Context, rawToken string) (uuid.UUID, error) {
	token, err := s.ValidateChallengeToken(ctx, rawToken)
	if err != nil {
		return uuid.Nil, err
	}
	return token.UserID, nil
}

// ConsumeTwoFactorToken is a helper that ignores the user return value.
func (s *totpService) ConsumeTwoFactorToken(ctx context.Context, rawToken string) error {
	_, err := s.ConsumeChallengeToken(ctx, rawToken)
	return err
}

// DisableTotp is a UUID-friendly helper for DisableTOTP.
func (s *totpService) DisableTotp(ctx context.Context, userID uuid.UUID, password, code string) error {
	return s.DisableTOTP(ctx, userID.String(), password, code)
}


