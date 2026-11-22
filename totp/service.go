package totp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
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

	// UUID-friendly helper methods
	IsTotpEnabled(ctx context.Context, userID uuid.UUID) (bool, error)
	EnrollTotp(ctx context.Context, userID uuid.UUID) (*EnrollmentResponse, error)
	VerifyTotp(ctx context.Context, userID uuid.UUID, code string) error
	GenerateTwoFactorToken(ctx context.Context, userID uuid.UUID) (string, error)
	ValidateTwoFactorToken(ctx context.Context, rawToken string) (uuid.UUID, error)
	ConsumeTwoFactorToken(ctx context.Context, rawToken string) error
	DisableTotp(ctx context.Context, userID uuid.UUID, password, code string) error
}

// TotpService is an exported alias for Service to support alternate naming conventions.
type TotpService = Service

type totpService struct {
	store     db.Store
	cfg       config.TOTPConfig
	crypto    *Crypto
	cryptoErr error
	limiter   Limiter
	logger    *slog.Logger
}

// NewServiceWithStore constructs a concrete TotpService instance backed by db.Store.
func NewServiceWithStore(store db.Store, cfg config.TOTPConfig, limiter Limiter, logger *slog.Logger) Service {
	if store == nil {
		panic("totp: nil db.Store")
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
		store:     store,
		cfg:       cfg,
		crypto:    crypt,
		cryptoErr: cryptErr,
		limiter:   limiter,
		logger:    logger,
	}
}

// NewService constructs a concrete TotpService instance backed by a GORM DB.
func NewService(database *gorm.DB, cfg config.TOTPConfig, limiter Limiter, logger *slog.Logger) Service {
	if database == nil {
		panic("totp: nil gorm.DB")
	}
	return NewServiceWithStore(gormstore.New(database), cfg, limiter, logger)
}

// NewTotpService is an alias for NewService.
func NewTotpService(database *gorm.DB, cfg config.TOTPConfig, limiter Limiter, logger *slog.Logger) Service {
	return NewService(database, cfg, limiter, logger)
}

// NewTotpServiceWithStore is an alias for NewServiceWithStore.
func NewTotpServiceWithStore(store db.Store, cfg config.TOTPConfig, limiter Limiter, logger *slog.Logger) Service {
	return NewServiceWithStore(store, cfg, limiter, logger)
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

	user, err := s.store.Users().GetByID(ctx, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, err
	}

	if !user.EmailVerified {
		return nil, apperrors.ErrEmailNotVerified
	}

	existing, err := s.store.Totp().GetSecretByUserID(ctx, uid)
	if err == nil {
		if existing.Enabled {
			return nil, apperrors.ErrTOTPAlreadyEnabled
		}
		// Clear pending unconfirmed secret to allow idempotency/retry
		if err := s.store.Totp().DeleteUnconfirmedSecret(ctx, uid); err != nil {
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
	if err := s.store.Totp().CreateSecret(ctx, &secretRecord); err != nil {
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
	if userID != "" && s.limiter != nil {
		if !s.limiter.Allow(ratelimit.TOTPUserKey(userID)) {
			return nil, apperrors.ErrTOTPRateLimitExceeded
		}
	}

	uid, err := s.parseUUID(userID)
	if err != nil {
		return nil, err
	}

	pending, err := s.store.Totp().GetSecretByUserID(ctx, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrTOTPNotEnrolled
		}
		return nil, err
	}
	if pending.Enabled {
		return nil, apperrors.ErrTOTPAlreadyEnabled
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
	cutoff := time.Now().Add(-90 * time.Second)
	used, err := s.store.Totp().HasUsedCode(ctx, uid, codeHash, cutoff)
	if err != nil {
		return nil, err
	}
	if used {
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

	err = s.store.Transaction(ctx, func(txStore db.Store) error {
		// Evict expired replay records outside sliding 90s window to avoid cyclic collision lockout
		if err := txStore.Totp().PruneUsedCodes(ctx, uid, cutoff); err != nil {
			return err
		}

		usedRecord := db.TotpUsedCode{
			ID:       uuid.New(),
			UserID:   uid,
			CodeHash: codeHash,
			UsedAt:   time.Now(),
		}
		if err := txStore.Totp().RecordUsedCode(ctx, &usedRecord); err != nil {
			if isTOTPReplayError(err) {
				return apperrors.ErrTOTPCodeReplayed
			}
			return err
		}

		return txStore.Totp().EnableSecret(ctx, pending.ID, hashedCodesJSON)
	})
	if err != nil {
		return nil, err
	}

	if s.limiter != nil && userID != "" {
		s.limiter.Reset(ratelimit.TOTPUserKey(userID))
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

	_, err = s.store.Users().GetByID(ctx, uid)
	if err != nil {
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
	if err := s.store.Totp().CreateTwoFactorToken(ctx, &tokenRecord); err != nil {
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

	token, err := s.store.Totp().GetTwoFactorToken(ctx, tokenHash[:])
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrTwoFactorTokenInvalid
		}
		return nil, err
	}

	if time.Now().After(token.ExpiresAt) {
		_, _ = s.store.Totp().DeleteTwoFactorToken(ctx, token.ID)
		return nil, apperrors.ErrTwoFactorTokenExpired
	}

	maxAttempts := s.cfg.MaxAttemptsPerWindow
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if token.Attempts >= maxAttempts {
		_, _ = s.store.Totp().DeleteTwoFactorToken(ctx, token.ID)
		return nil, apperrors.ErrTwoFactorMaxAttemptsExceeded
	}

	return token, nil
}

// RecordTokenAttempt atomically increments the attempt counter on a challenge token.
func (s *totpService) RecordTokenAttempt(ctx context.Context, rawToken string) (int, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return 0, apperrors.ErrTwoFactorTokenInvalid
	}

	tokenHash := sha256.Sum256([]byte(rawToken))
	maxAttempts := s.cfg.MaxAttemptsPerWindow
	if maxAttempts <= 0 {
		maxAttempts = 5
	}

	return s.store.Totp().IncrementTwoFactorAttempts(ctx, tokenHash[:], maxAttempts, time.Now().UTC())
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

	secretRecord, err := s.store.Totp().GetSecretByUserID(ctx, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return apperrors.ErrTOTPNotEnrolled
		}
		return err
	}
	if !secretRecord.Enabled {
		return apperrors.ErrTOTPNotEnrolled
	}

	trimmedCode := strings.TrimSpace(code)
	codeHash := CodeHash(trimmedCode, uid.String())

	cutoff := time.Now().Add(-90 * time.Second)
	used, err := s.store.Totp().HasUsedCode(ctx, uid, codeHash, cutoff)
	if err != nil {
		return err
	}
	if used {
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

	err = s.store.Transaction(ctx, func(txStore db.Store) error {
		// Evict expired replay records outside sliding 90s window to avoid cyclic collision lockout
		if err := txStore.Totp().PruneUsedCodes(ctx, uid, cutoff); err != nil {
			return err
		}

		usedRecord := db.TotpUsedCode{
			ID:       uuid.New(),
			UserID:   uid,
			CodeHash: codeHash,
			UsedAt:   time.Now(),
		}
		if err := txStore.Totp().RecordUsedCode(ctx, &usedRecord); err != nil {
			if isTOTPReplayError(err) {
				return apperrors.ErrTOTPCodeReplayed
			}
			return err
		}
		return nil
	})
	if err != nil {
		return err
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

	token, err := s.store.Totp().GetTwoFactorToken(ctx, tokenHash[:])
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrTwoFactorTokenInvalid
		}
		return nil, err
	}

	maxAttempts := s.cfg.MaxAttemptsPerWindow
	if maxAttempts <= 0 {
		maxAttempts = 5
	}

	now := time.Now().UTC()
	if now.After(token.ExpiresAt) {
		_, _ = s.store.Totp().DeleteTwoFactorToken(ctx, token.ID)
		return nil, apperrors.ErrTwoFactorTokenExpired
	}
	if token.Attempts >= maxAttempts {
		_, _ = s.store.Totp().DeleteTwoFactorToken(ctx, token.ID)
		return nil, apperrors.ErrTwoFactorMaxAttemptsExceeded
	}

	consumed, err := s.store.Totp().ConsumeTwoFactorToken(ctx, tokenHash[:], maxAttempts, now)
	if err != nil {
		return nil, err
	}
	if !consumed {
		return nil, apperrors.ErrTwoFactorTokenInvalid
	}

	user, err := s.store.Users().GetByID(ctx, token.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

// VerifyBackupCode validates and consumes a backup code.
func (s *totpService) VerifyBackupCode(ctx context.Context, userID, backupCode, clientIP string) error {
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

	trimmedCode := strings.TrimSpace(backupCode)
	if trimmedCode == "" {
		return apperrors.ErrBackupCodeInvalid
	}

	err = s.store.Transaction(ctx, func(txStore db.Store) error {
		secretRecord, err := txStore.Totp().GetSecretByUserIDForUpdate(ctx, uid)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return apperrors.ErrTOTPNotEnrolled
			}
			return err
		}

		var currentCodes []string
		if err := json.Unmarshal(secretRecord.BackupCodes, &currentCodes); err != nil {
			return err
		}

		updatedJSON, matched, err := VerifyAndConsumeBackupCode(secretRecord.BackupCodes, trimmedCode)
		if err != nil {
			return err
		}
		if !matched {
			return apperrors.ErrBackupCodeInvalid
		}

		var updatedCodes []string
		if err := json.Unmarshal(updatedJSON, &updatedCodes); err != nil {
			return err
		}

		ok, err := txStore.Totp().UpdateBackupCodesCAS(ctx, uid, currentCodes, updatedCodes)
		if err != nil {
			return err
		}
		if !ok {
			return apperrors.ErrBackupCodeInvalid
		}

		return nil
	})
	if err != nil {
		return err
	}

	if s.limiter != nil {
		if clientIP != "" {
			s.limiter.Reset(ratelimit.TOTPIPKey(clientIP))
		}
		if userID != "" {
			s.limiter.Reset(ratelimit.TOTPUserKey(userID))
		}
	}

	s.logger.InfoContext(ctx, "backup code consumed", slog.String("event", "backup_code_used"), slog.String("user_id", uid.String()))

	return nil
}

// DisableTOTP verifies user credentials and removes 2FA configuration.
func (s *totpService) DisableTOTP(ctx context.Context, userID, password, code string) error {
	uid, err := s.parseUUID(userID)
	if err != nil {
		return err
	}

	user, err := s.store.Users().GetByID(ctx, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return apperrors.ErrUserNotFound
		}
		return err
	}

	secretRecord, err := s.store.Totp().GetSecretByUserID(ctx, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return apperrors.ErrTOTPNotEnrolled
		}
		return err
	}
	if !secretRecord.Enabled {
		return apperrors.ErrTOTPNotEnrolled
	}

	trimmedCode := strings.TrimSpace(code)
	if password == "" && trimmedCode == "" {
		return apperrors.ErrInvalidCredentials
	}

	var authed bool
	if password != "" {
		match, err := crypto.VerifyPassword(password, user.PasswordHash)
		if err == nil && match {
			authed = true
		}
	}

	var codeUsed bool
	var codeHash []byte
	if !authed && trimmedCode != "" {
		crypt, err := s.getCrypto()
		if err == nil {
			rawSecretBytes, err := crypt.Decrypt(secretRecord.EncryptedSecret)
			if err == nil {
				valid, err := ValidateCode(trimmedCode, string(rawSecretBytes))
				if err == nil && valid {
					codeHash = CodeHash(trimmedCode, uid.String())
					cutoff := time.Now().Add(-90 * time.Second)
					used, err := s.store.Totp().HasUsedCode(ctx, uid, codeHash, cutoff)
					if err != nil {
						return err
					}
					if used {
						return apperrors.ErrTOTPCodeReplayed
					}
					authed = true
					codeUsed = true
				}
			}
		}
	}

	if !authed {
		return apperrors.ErrInvalidCredentials
	}

	err = s.store.Transaction(ctx, func(txStore db.Store) error {
		if err := txStore.Totp().DeleteSecret(ctx, uid); err != nil {
			return err
		}
		cutoff := time.Now().Add(-90 * time.Second)
		if err := txStore.Totp().PruneUsedCodes(ctx, uid, cutoff); err != nil {
			return err
		}
		if codeUsed {
			usedRecord := db.TotpUsedCode{
				ID:       uuid.New(),
				UserID:   uid,
				CodeHash: codeHash,
				UsedAt:   time.Now(),
			}
			if err := txStore.Totp().RecordUsedCode(ctx, &usedRecord); err != nil {
				if isTOTPReplayError(err) {
					return apperrors.ErrTOTPCodeReplayed
				}
				return err
			}
		}
		return txStore.Totp().DeleteTwoFactorTokensByUserID(ctx, uid)
	})
	if err != nil {
		return err
	}

	s.logger.InfoContext(ctx, "totp disabled", slog.String("event", "totp_disabled"), slog.String("user_id", uid.String()))

	return nil
}

// Status checks whether TOTP is enabled for a user.
func (s *totpService) Status(ctx context.Context, userID string) (bool, error) {
	uid, err := s.parseUUID(userID)
	if err != nil {
		return false, err
	}

	return s.store.Totp().IsTotpEnabled(ctx, uid)
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

func isTOTPReplayError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, apperrors.ErrTOTPCodeReplayed) || errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	var myErr *mysqlDriver.MySQLError
	if errors.As(err, &myErr) && myErr.Number == 1062 {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "1062") ||
		strings.Contains(msg, "11000") ||
		strings.Contains(msg, "23505") ||
		strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate entry")
}
