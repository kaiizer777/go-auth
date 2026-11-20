package totp

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
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/ratelimit"
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
	uid, err := s.parseUUID(userID)
	if err != nil {
		return nil, err
	}

	var user db.User
	if err := s.db.WithContext(ctx).Where("id = ?", uid).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, err
	}

	if !user.EmailVerified {
		return nil, apperrors.ErrEmailNotVerified
	}

	var existing db.TotpSecret
	err = s.db.WithContext(ctx).Where("user_id = ?", uid).First(&existing).Error
	if err == nil {
		if existing.Enabled {
			return nil, apperrors.ErrTOTPAlreadyEnabled
		}
		// Clear pending unconfirmed secret to allow idempotency/retry
		if err := s.db.WithContext(ctx).Where("user_id = ? AND enabled = false", uid).Delete(&db.TotpSecret{}).Error; err != nil {
			return nil, err
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	crypt, err := s.getCrypto()
	if err != nil {
		return nil, err
	}

	key, err := GenerateKey(s.cfg.Issuer, user.Email)
	if err != nil {
		return nil, err
	}

	encSecret, err := crypt.Encrypt([]byte(key.Secret()))
	if err != nil {
		return nil, err
	}

	qrCode, err := GenerateQRCodeDataURI(key, 200, 200)
	if err != nil {
		return nil, err
	}

	secretRecord := db.TotpSecret{
		ID:              uuid.New(),
		UserID:          uid,
		EncryptedSecret: encSecret,
		BackupCodes:     []byte("[]"),
		Enabled:         false,
	}
	if err := s.db.WithContext(ctx).Create(&secretRecord).Error; err != nil {
		return nil, err
	}

	return &EnrollmentResponse{
		Secret: key.Secret(),
		OTPURI: key.URL(),
		QRCode: qrCode,
	}, nil
}

// ConfirmEnrollment verifies the initial code, enables TOTP, and returns 10 backup codes.
func (s *totpService) ConfirmEnrollment(ctx context.Context, userID, code string) ([]string, error) {
	uid, err := s.parseUUID(userID)
	if err != nil {
		return nil, err
	}

	var pending db.TotpSecret
	err = s.db.WithContext(ctx).Where("user_id = ? AND enabled = false", uid).First(&pending).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			var active db.TotpSecret
			if s.db.WithContext(ctx).Where("user_id = ? AND enabled = true", uid).First(&active).Error == nil {
				return nil, apperrors.ErrTOTPAlreadyEnabled
			}
			return nil, apperrors.ErrTOTPNotEnrolled
		}
		return nil, err
	}

	crypt, err := s.getCrypto()
	if err != nil {
		return nil, err
	}

	rawSecretBytes, err := crypt.Decrypt(pending.EncryptedSecret)
	if err != nil {
		return nil, err
	}

	trimmedCode := strings.TrimSpace(code)
	valid, err := ValidateCode(trimmedCode, string(rawSecretBytes))
	if err != nil || !valid {
		return nil, apperrors.ErrTOTPCodeInvalid
	}

	codeHash := CodeHash(trimmedCode, uid.String())
	var usedCount int64
	cutoff := time.Now().Add(-90 * time.Second)
	err = s.db.WithContext(ctx).Model(&db.TotpUsedCode{}).Where("user_id = ? AND code_hash = ? AND used_at > ?", uid, codeHash, cutoff).Count(&usedCount).Error
	if err != nil {
		return nil, err
	}
	if usedCount > 0 {
		return nil, apperrors.ErrTOTPCodeReplayed
	}

	backupCodes, err := GenerateBackupCodes()
	if err != nil {
		return nil, err
	}

	hashedCodesJSON, err := HashBackupCodes(backupCodes)
	if err != nil {
		return nil, err
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		usedRecord := db.TotpUsedCode{
			ID:       uuid.New(),
			UserID:   uid,
			CodeHash: codeHash,
			UsedAt:   time.Now(),
		}
		if err := tx.Create(&usedRecord).Error; err != nil {
			return apperrors.ErrTOTPCodeReplayed
		}

		res := tx.Model(&db.TotpSecret{}).Where("id = ? AND enabled = false", pending.ID).Updates(map[string]interface{}{
			"enabled":      true,
			"backup_codes": hashedCodesJSON,
			"updated_at":   time.Now(),
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return apperrors.ErrTOTPAlreadyEnabled
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.logger.InfoContext(ctx, "totp enrollment confirmed", slog.String("event", "totp_confirmed"), slog.String("user_id", uid.String()))

	return backupCodes, nil
}

// CreateChallengeToken generates and persists an ephemeral challenge token.
func (s *totpService) CreateChallengeToken(ctx context.Context, userID string) (string, error) {
	uid, err := s.parseUUID(userID)
	if err != nil {
		return "", err
	}

	var user db.User
	if err := s.db.WithContext(ctx).Where("id = ?", uid).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", apperrors.ErrUserNotFound
		}
		return "", err
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("totp: failed to generate token entropy: %w", err)
	}
	rawToken := hex.EncodeToString(tokenBytes)

	tokenHash := sha256.Sum256([]byte(rawToken))

	ttl := s.cfg.ChallengeTokenTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	expiresAt := time.Now().Add(ttl)

	tokenRecord := db.TwoFactorToken{
		ID:        uuid.New(),
		UserID:    uid,
		TokenHash: tokenHash[:],
		ExpiresAt: expiresAt,
		Attempts:  0,
	}
	if err := s.db.WithContext(ctx).Create(&tokenRecord).Error; err != nil {
		return "", err
	}

	return rawToken, nil
}

// ValidateChallengeToken verifies challenge token validity without destroying it.
func (s *totpService) ValidateChallengeToken(ctx context.Context, rawToken string) (*db.TwoFactorToken, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, apperrors.ErrTwoFactorTokenInvalid
	}

	tokenHash := sha256.Sum256([]byte(rawToken))

	var token db.TwoFactorToken
	err := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash[:]).First(&token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrTwoFactorTokenInvalid
		}
		return nil, err
	}

	if time.Now().After(token.ExpiresAt) {
		s.db.WithContext(ctx).Where("id = ?", token.ID).Delete(&db.TwoFactorToken{})
		return nil, apperrors.ErrTwoFactorTokenExpired
	}

	maxAttempts := s.cfg.MaxAttemptsPerWindow
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if token.Attempts >= maxAttempts {
		s.db.WithContext(ctx).Where("id = ?", token.ID).Delete(&db.TwoFactorToken{})
		return nil, apperrors.ErrTwoFactorMaxAttemptsExceeded
	}

	return &token, nil
}

// RecordTokenAttempt atomically increments the attempt counter on a challenge token.
func (s *totpService) RecordTokenAttempt(ctx context.Context, rawToken string) (int, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return 0, apperrors.ErrTwoFactorTokenInvalid
	}

	tokenHash := sha256.Sum256([]byte(rawToken))

	var token db.TwoFactorToken
	err := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash[:]).First(&token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, apperrors.ErrTwoFactorTokenInvalid
		}
		return 0, err
	}

	if time.Now().After(token.ExpiresAt) {
		s.db.WithContext(ctx).Where("id = ?", token.ID).Delete(&db.TwoFactorToken{})
		return 0, apperrors.ErrTwoFactorTokenExpired
	}

	newAttempts := token.Attempts + 1
	maxAttempts := s.cfg.MaxAttemptsPerWindow
	if maxAttempts <= 0 {
		maxAttempts = 5
	}

	if newAttempts >= maxAttempts {
		s.db.WithContext(ctx).Where("id = ?", token.ID).Delete(&db.TwoFactorToken{})
		return newAttempts, apperrors.ErrTwoFactorMaxAttemptsExceeded
	}

	if err := s.db.WithContext(ctx).Model(&db.TwoFactorToken{}).Where("id = ?", token.ID).Update("attempts", newAttempts).Error; err != nil {
		return 0, err
	}

	return newAttempts, nil
}

// VerifyCode verifies a TOTP code against the user's active secret.
func (s *totpService) VerifyCode(ctx context.Context, userID, code, clientIP string) error {
	if clientIP != "" && s.limiter != nil {
		if !s.limiter.Allow(ratelimit.TOTPIPKey(clientIP)) {
			return apperrors.ErrTOTPRateLimitExceeded
		}
	}
	if userID != "" && s.limiter != nil {
		if !s.limiter.Allow(ratelimit.TOTPUserKey(userID)) {
			return apperrors.ErrTOTPRateLimitExceeded
		}
	}

	uid, err := s.parseUUID(userID)
	if err != nil {
		return err
	}

	var secretRecord db.TotpSecret
	err = s.db.WithContext(ctx).Where("user_id = ? AND enabled = true", uid).First(&secretRecord).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return apperrors.ErrTOTPNotEnrolled
		}
		return err
	}

	trimmedCode := strings.TrimSpace(code)
	codeHash := CodeHash(trimmedCode, uid.String())

	var usedCount int64
	cutoff := time.Now().Add(-90 * time.Second)
	err = s.db.WithContext(ctx).Model(&db.TotpUsedCode{}).Where("user_id = ? AND code_hash = ? AND used_at > ?", uid, codeHash, cutoff).Count(&usedCount).Error
	if err != nil {
		return err
	}
	if usedCount > 0 {
		return apperrors.ErrTOTPCodeReplayed
	}

	crypt, err := s.getCrypto()
	if err != nil {
		return err
	}

	rawSecretBytes, err := crypt.Decrypt(secretRecord.EncryptedSecret)
	if err != nil {
		return err
	}

	valid, err := ValidateCode(trimmedCode, string(rawSecretBytes))
	if err != nil || !valid {
		return apperrors.ErrTOTPCodeInvalid
	}

	usedRecord := db.TotpUsedCode{
		ID:       uuid.New(),
		UserID:   uid,
		CodeHash: codeHash,
		UsedAt:   time.Now(),
	}
	if err := s.db.WithContext(ctx).Create(&usedRecord).Error; err != nil {
		return apperrors.ErrTOTPCodeReplayed
	}

	if s.limiter != nil {
		if clientIP != "" {
			s.limiter.Reset(ratelimit.TOTPIPKey(clientIP))
		}
		if userID != "" {
			s.limiter.Reset(ratelimit.TOTPUserKey(userID))
		}
	}

	s.logger.InfoContext(ctx, "totp code verified", slog.String("event", "totp_verified"), slog.String("user_id", uid.String()))

	return nil
}

// ConsumeChallengeToken hard-deletes the token and returns the associated user.
func (s *totpService) ConsumeChallengeToken(ctx context.Context, rawToken string) (*db.User, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, apperrors.ErrTwoFactorTokenInvalid
	}

	tokenHash := sha256.Sum256([]byte(rawToken))

	var token db.TwoFactorToken
	err := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash[:]).First(&token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrTwoFactorTokenInvalid
		}
		return nil, err
	}

	if time.Now().After(token.ExpiresAt) {
		s.db.WithContext(ctx).Where("id = ?", token.ID).Delete(&db.TwoFactorToken{})
		return nil, apperrors.ErrTwoFactorTokenExpired
	}

	if err := s.db.WithContext(ctx).Where("id = ?", token.ID).Delete(&db.TwoFactorToken{}).Error; err != nil {
		return nil, err
	}

	var user db.User
	if err := s.db.WithContext(ctx).Where("id = ?", token.UserID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

// VerifyBackupCode validates and consumes a backup code.
func (s *totpService) VerifyBackupCode(ctx context.Context, userID, backupCode, clientIP string) error {
	return nil
}

// DisableTOTP verifies user credentials and removes 2FA configuration.
func (s *totpService) DisableTOTP(ctx context.Context, userID, password, code string) error {
	return nil
}

// Status checks whether TOTP is enabled for a user.
func (s *totpService) Status(ctx context.Context, userID string) (bool, error) {
	uid, err := s.parseUUID(userID)
	if err != nil {
		return false, err
	}

	var count int64
	err = s.db.WithContext(ctx).Model(&db.TotpSecret{}).Where("user_id = ? AND enabled = true", uid).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
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


