package gormstore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
)

func lockForUpdate(tx *gorm.DB) *gorm.DB {
	if tx.Dialector != nil && strings.Contains(strings.ToLower(tx.Name()), "sqlite") {
		return tx
	}
	return tx.Clauses(clause.Locking{Strength: "UPDATE"})
}

type userStore struct {
	db *gorm.DB
}

func (s *userStore) Create(ctx context.Context, user *db.User) error {
	err := s.db.WithContext(ctx).Create(user).Error
	if err != nil {
		return db.NormalizeMySQLError(err)
	}
	return nil
}

func (s *userStore) GetByID(ctx context.Context, id uuid.UUID) (*db.User, error) {
	var u db.User
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *userStore) GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*db.User, error) {
	var u db.User
	if err := lockForUpdate(s.db.WithContext(ctx)).Where("id = ?", id).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *userStore) GetByEmail(ctx context.Context, email string) (*db.User, error) {
	var u db.User
	if err := s.db.WithContext(ctx).Where("LOWER(email) = LOWER(?)", email).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *userStore) Update(ctx context.Context, user *db.User) error {
	return s.db.WithContext(ctx).Save(user).Error
}

func (s *userStore) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	return s.db.WithContext(ctx).Model(&db.User{}).Where("id = ?", id).Update("password_hash", passwordHash).Error
}

func (s *userStore) IncrementCredentialVersion(ctx context.Context, userID uuid.UUID) (uint32, error) {
	res := s.db.WithContext(ctx).Model(&db.User{}).Where("id = ?", userID).Update("credential_version", gorm.Expr("credential_version + 1"))
	if res.Error != nil {
		return 0, res.Error
	}
	if res.RowsAffected == 0 {
		return 0, nil
	}
	var u db.User
	if err := s.db.WithContext(ctx).Select("credential_version").Where("id = ?", userID).First(&u).Error; err != nil {
		return 0, err
	}
	return uint32(u.CredentialVersion), nil
}

func (s *userStore) SetEmailVerified(ctx context.Context, id uuid.UUID, verified bool) error {
	return s.db.WithContext(ctx).Model(&db.User{}).Where("id = ?", id).Update("email_verified", verified).Error
}

func (s *userStore) Delete(ctx context.Context, id uuid.UUID) error {
	return s.db.WithContext(ctx).Where("id = ?", id).Delete(&db.User{}).Error
}

type sessionStore struct {
	db *gorm.DB
}

func (s *sessionStore) Create(ctx context.Context, session *db.Session) error {
	return s.db.WithContext(ctx).Create(session).Error
}

func (s *sessionStore) GetByID(ctx context.Context, id uuid.UUID) (*db.Session, error) {
	var sess db.Session
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&sess).Error; err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *sessionStore) GetByIDHash(ctx context.Context, idHash string) (*db.Session, error) {
	var sess db.Session
	if err := s.db.WithContext(ctx).Where("id_hash = ?", idHash).First(&sess).Error; err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *sessionStore) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*db.Session, error) {
	var sessions []*db.Session
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("last_active_at DESC").Limit(50).Find(&sessions).Error; err != nil {
		return nil, err
	}
	return sessions, nil
}

func (s *sessionStore) UpdateLastActive(ctx context.Context, id uuid.UUID, lastActive time.Time) error {
	return s.db.WithContext(ctx).Model(&db.Session{}).Where("id = ? AND last_active_at < ?", id, lastActive).Update("last_active_at", lastActive).Error
}

func (s *sessionStore) Delete(ctx context.Context, id uuid.UUID) error {
	return s.db.WithContext(ctx).Where("id = ?", id).Delete(&db.Session{}).Error
}

func (s *sessionStore) DeleteByIDHash(ctx context.Context, idHash string) (int64, error) {
	res := s.db.WithContext(ctx).Where("id_hash = ?", idHash).Delete(&db.Session{})
	return res.RowsAffected, res.Error
}

func (s *sessionStore) DeleteIfStale(ctx context.Context, id uuid.UUID, lastActive time.Time) (int64, error) {
	res := s.db.WithContext(ctx).Where("id = ? AND last_active_at <= ?", id, lastActive).Delete(&db.Session{})
	return res.RowsAffected, res.Error
}

func (s *sessionStore) DeleteIfStaleByIDHash(ctx context.Context, idHash string, lastActive time.Time) (int64, error) {
	res := s.db.WithContext(ctx).Where("id_hash = ? AND last_active_at <= ?", idHash, lastActive).Delete(&db.Session{})
	return res.RowsAffected, res.Error
}

func (s *sessionStore) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	return s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&db.Session{}).Error
}

func (s *sessionStore) DeleteExpired(ctx context.Context, now time.Time, idleCutoff time.Time) (int64, error) {
	res := s.db.WithContext(ctx).Where("absolute_expires_at <= ? OR last_active_at <= ?", now, idleCutoff).Delete(&db.Session{})
	return res.RowsAffected, res.Error
}

func (s *sessionStore) DeleteExpiredByUserID(ctx context.Context, userID uuid.UUID, now time.Time, idleCutoff time.Time) error {
	return s.db.WithContext(ctx).Where("user_id = ? AND (absolute_expires_at <= ? OR last_active_at <= ?)", userID, now, idleCutoff).Delete(&db.Session{}).Error
}

type verificationTokenStore struct {
	db *gorm.DB
}

func (s *verificationTokenStore) Create(ctx context.Context, token *db.VerificationToken) error {
	return s.db.WithContext(ctx).Create(token).Error
}

func (s *verificationTokenStore) GetByTokenHash(ctx context.Context, tokenHash []byte) (*db.VerificationToken, error) {
	var tok db.VerificationToken
	if err := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&tok).Error; err != nil {
		return nil, err
	}
	return &tok, nil
}

func (s *verificationTokenStore) Delete(ctx context.Context, tokenHash []byte) error {
	return s.db.WithContext(ctx).Where("token_hash = ?", tokenHash).Delete(&db.VerificationToken{}).Error
}

func (s *verificationTokenStore) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	return s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&db.VerificationToken{}).Error
}

type passwordResetTokenStore struct {
	db *gorm.DB
}

func (s *passwordResetTokenStore) Create(ctx context.Context, token *db.PasswordResetToken) error {
	return s.db.WithContext(ctx).Create(token).Error
}

func (s *passwordResetTokenStore) GetByTokenHash(ctx context.Context, tokenHash []byte) (*db.PasswordResetToken, error) {
	var tok db.PasswordResetToken
	if err := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&tok).Error; err != nil {
		return nil, err
	}
	return &tok, nil
}

func (s *passwordResetTokenStore) Delete(ctx context.Context, tokenHash []byte) error {
	return s.db.WithContext(ctx).Where("token_hash = ?", tokenHash).Delete(&db.PasswordResetToken{}).Error
}

func (s *passwordResetTokenStore) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	return s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&db.PasswordResetToken{}).Error
}

func (s *passwordResetTokenStore) ConsumeToken(ctx context.Context, tokenHash []byte, now time.Time) (bool, error) {
	res := s.db.WithContext(ctx).Where("token_hash = ? AND expires_at > ?", tokenHash, now).Delete(&db.PasswordResetToken{})
	return res.RowsAffected > 0, res.Error
}

type oauthAccountStore struct {
	db *gorm.DB
}

func (s *oauthAccountStore) Create(ctx context.Context, account *db.OAuthAccount) error {
	err := s.db.WithContext(ctx).Create(account).Error
	if err != nil {
		return db.NormalizeMySQLError(err)
	}
	return nil
}

func (s *oauthAccountStore) GetByProvider(ctx context.Context, providerID, providerUserID string) (*db.OAuthAccount, error) {
	var acc db.OAuthAccount
	if err := s.db.WithContext(ctx).Where("provider_id = ? AND provider_user_id = ?", providerID, providerUserID).First(&acc).Error; err != nil {
		return nil, err
	}
	return &acc, nil
}

func (s *oauthAccountStore) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*db.OAuthAccount, error) {
	var accounts []*db.OAuthAccount
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Find(&accounts).Error; err != nil {
		return nil, err
	}
	return accounts, nil
}

func (s *oauthAccountStore) Delete(ctx context.Context, id uuid.UUID) error {
	return s.db.WithContext(ctx).Where("id = ?", id).Delete(&db.OAuthAccount{}).Error
}

func (s *oauthAccountStore) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	return s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&db.OAuthAccount{}).Error
}

type totpStore struct {
	db *gorm.DB
}

func (s *totpStore) CreateSecret(ctx context.Context, secret *db.TotpSecret) error {
	err := s.db.WithContext(ctx).Create(secret).Error
	if err != nil {
		return db.NormalizeMySQLError(err)
	}
	return nil
}

func (s *totpStore) GetSecretByUserID(ctx context.Context, userID uuid.UUID) (*db.TotpSecret, error) {
	var sec db.TotpSecret
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).First(&sec).Error; err != nil {
		return nil, err
	}
	return &sec, nil
}

func (s *totpStore) GetSecretByUserIDForUpdate(ctx context.Context, userID uuid.UUID) (*db.TotpSecret, error) {
	var sec db.TotpSecret
	if err := lockForUpdate(s.db.WithContext(ctx)).Where("user_id = ? AND enabled = true", userID).First(&sec).Error; err != nil {
		return nil, err
	}
	return &sec, nil
}

func (s *totpStore) EnableSecret(ctx context.Context, secretID uuid.UUID, backupCodesJSON []byte) error {
	res := s.db.WithContext(ctx).Model(&db.TotpSecret{}).Where("id = ? AND enabled = false", secretID).Updates(map[string]any{
		"enabled":      true,
		"backup_codes": backupCodesJSON,
		"updated_at":   time.Now().UTC(),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return apperrors.ErrTOTPAlreadyEnabled
	}
	return nil
}

func (s *totpStore) UpdateBackupCodes(ctx context.Context, userID uuid.UUID, backupCodes []string) error {
	rawJSON, err := json.Marshal(backupCodes)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Model(&db.TotpSecret{}).Where("user_id = ? AND enabled = true", userID).Updates(map[string]any{
		"backup_codes": rawJSON,
		"updated_at":   time.Now().UTC(),
	}).Error
}

func (s *totpStore) UpdateBackupCodesJSON(ctx context.Context, secretID uuid.UUID, backupCodesJSON []byte) error {
	res := s.db.WithContext(ctx).Model(&db.TotpSecret{}).Where("id = ? AND enabled = true", secretID).Updates(map[string]any{
		"backup_codes": backupCodesJSON,
		"updated_at":   time.Now().UTC(),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return apperrors.ErrTOTPNotEnrolled
	}
	return nil
}

func (s *totpStore) DeleteSecret(ctx context.Context, userID uuid.UUID) error {
	return s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&db.TotpSecret{}).Error
}

func (s *totpStore) DeleteUnconfirmedSecret(ctx context.Context, userID uuid.UUID) error {
	return s.db.WithContext(ctx).Where("user_id = ? AND enabled = false", userID).Delete(&db.TotpSecret{}).Error
}

func (s *totpStore) IsTotpEnabled(ctx context.Context, userID uuid.UUID) (bool, error) {
	var count int64
	if err := s.db.WithContext(ctx).Model(&db.TotpSecret{}).Where("user_id = ? AND enabled = true", userID).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *totpStore) HasUsedCode(ctx context.Context, userID uuid.UUID, codeHash []byte, since time.Time) (bool, error) {
	var count int64
	if err := s.db.WithContext(ctx).Model(&db.TotpUsedCode{}).Where("user_id = ? AND code_hash = ? AND used_at > ?", userID, codeHash, since).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *totpStore) RecordUsedCode(ctx context.Context, usedCode *db.TotpUsedCode) error {
	err := s.db.WithContext(ctx).Create(usedCode).Error
	if err != nil {
		return db.NormalizeMySQLError(err)
	}
	return nil
}

func (s *totpStore) PruneUsedCodes(ctx context.Context, userID uuid.UUID, before time.Time) error {
	return s.db.WithContext(ctx).Where("user_id = ? AND used_at < ?", userID, before).Delete(&db.TotpUsedCode{}).Error
}

func (s *totpStore) CreateTwoFactorToken(ctx context.Context, token *db.TwoFactorToken) error {
	return s.db.WithContext(ctx).Create(token).Error
}

func (s *totpStore) GetTwoFactorToken(ctx context.Context, tokenHash []byte) (*db.TwoFactorToken, error) {
	var tok db.TwoFactorToken
	if err := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&tok).Error; err != nil {
		return nil, err
	}
	return &tok, nil
}

func (s *totpStore) IncrementTwoFactorAttempts(ctx context.Context, tokenHash []byte, maxAttempts int, now time.Time) (int, error) {
	var newAttempts int
	var resErr error
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var token db.TwoFactorToken
		query := lockForUpdate(tx)
		if err := query.Where("token_hash = ?", tokenHash).First(&token).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				resErr = apperrors.ErrTwoFactorTokenInvalid
				return nil
			}
			return err
		}
		if now.After(token.ExpiresAt) {
			_ = tx.Where("id = ?", token.ID).Delete(&db.TwoFactorToken{}).Error
			resErr = apperrors.ErrTwoFactorTokenExpired
			return nil
		}
		if maxAttempts <= 0 {
			maxAttempts = 5
		}
		newAttempts = token.Attempts + 1
		if newAttempts >= maxAttempts {
			_ = tx.Where("id = ?", token.ID).Delete(&db.TwoFactorToken{}).Error
			resErr = apperrors.ErrTwoFactorMaxAttemptsExceeded
			return nil
		}
		return tx.Model(&db.TwoFactorToken{}).Where("id = ?", token.ID).Update("attempts", gorm.Expr("attempts + 1")).Error
	})
	if err != nil {
		return 0, err
	}
	if resErr != nil {
		return newAttempts, resErr
	}
	return newAttempts, nil
}

func (s *totpStore) DeleteTwoFactorToken(ctx context.Context, id uuid.UUID) (int64, error) {
	res := s.db.WithContext(ctx).Where("id = ?", id).Delete(&db.TwoFactorToken{})
	return res.RowsAffected, res.Error
}

func (s *totpStore) DeleteTwoFactorTokensByUserID(ctx context.Context, userID uuid.UUID) error {
	return s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&db.TwoFactorToken{}).Error
}

type gormStore struct {
	db                 *gorm.DB
	users              *userStore
	sessions           *sessionStore
	verificationTokens *verificationTokenStore
	passwordReset      *passwordResetTokenStore
	oauthAccounts      *oauthAccountStore
	totp               *totpStore
}

// New constructs a GORM-backed implementation of db.Store.
func New(database *gorm.DB) db.Store {
	if database == nil {
		return nil
	}
	return &gormStore{
		db:                 database,
		users:              &userStore{db: database},
		sessions:           &sessionStore{db: database},
		verificationTokens: &verificationTokenStore{db: database},
		passwordReset:      &passwordResetTokenStore{db: database},
		oauthAccounts:      &oauthAccountStore{db: database},
		totp:               &totpStore{db: database},
	}
}

func (s *gormStore) Users() db.UserStore                             { return s.users }
func (s *gormStore) Sessions() db.SessionStore                       { return s.sessions }
func (s *gormStore) VerificationTokens() db.VerificationTokenStore   { return s.verificationTokens }
func (s *gormStore) PasswordResetTokens() db.PasswordResetTokenStore { return s.passwordReset }
func (s *gormStore) OAuthAccounts() db.OAuthAccountStore             { return s.oauthAccounts }
func (s *gormStore) Totp() db.TotpStore                              { return s.totp }

func (s *gormStore) Transaction(ctx context.Context, fn func(txStore db.Store) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(New(tx))
	})
}

func (s *gormStore) Ping(ctx context.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

func (s *gormStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (s *gormStore) DB() *gorm.DB {
	return s.db
}
