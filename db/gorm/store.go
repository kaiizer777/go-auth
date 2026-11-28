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
	res := s.db.WithContext(ctx).Model(&db.User{}).Where("id = ?", user.ID).Select("*").Omit("id", "created_at").Updates(user)
	if res.Error != nil {
		return db.NormalizeMySQLError(res.Error)
	}
	if res.RowsAffected == 0 {
		return apperrors.New(apperrors.CodeUserNotFound, "user not found", gorm.ErrRecordNotFound)
	}
	return nil
}

func (s *userStore) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	return s.db.WithContext(ctx).Model(&db.User{}).Where("id = ?", id).Update("password_hash", passwordHash).Error
}

func (s *userStore) IncrementCredentialVersion(ctx context.Context, userID uuid.UUID) (uint32, error) {
	var newVersion uint32
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var u db.User
		if err := lockForUpdate(tx).Select("credential_version").Where("id = ?", userID).First(&u).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		newVersion = uint32(u.CredentialVersion + 1)
		return tx.Model(&db.User{}).Where("id = ?", userID).Update("credential_version", newVersion).Error
	})
	if err != nil {
		return 0, err
	}
	return newVersion, nil
}

func (s *userStore) SetEmailVerified(ctx context.Context, id uuid.UUID, verified bool) error {
	return s.db.WithContext(ctx).Model(&db.User{}).Where("id = ?", id).Update("email_verified", verified).Error
}

func (s *userStore) Delete(ctx context.Context, id uuid.UUID) error {
	// One transaction so a failure cannot release the account's addresses while
	// the account survives. The schema FK already cascades; the explicit delete
	// keeps the invariant true for a store whose schema was built by AutoMigrate,
	// which creates no foreign keys.
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", id).Delete(&db.User{}).Error; err != nil {
			return err
		}
		return tx.Where("owner_user_id = ?", id).Delete(&db.ClaimedEmail{}).Error
	})
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

func (s *verificationTokenStore) Delete(ctx context.Context, tokenHash []byte) (int64, error) {
	res := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash).Delete(&db.VerificationToken{})
	return res.RowsAffected, res.Error
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

func (s *passwordResetTokenStore) Delete(ctx context.Context, tokenHash []byte) (int64, error) {
	res := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash).Delete(&db.PasswordResetToken{})
	return res.RowsAffected, res.Error
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

func (s *oauthAccountStore) GetByProvider(ctx context.Context, providerID, providerTenantID, providerUserID string) (*db.OAuthAccount, error) {
	var acc db.OAuthAccount
	if err := s.db.WithContext(ctx).Where("provider_id = ? AND provider_tenant_id = ? AND provider_user_id = ?", providerID, providerTenantID, providerUserID).First(&acc).Error; err != nil {
		return nil, err
	}
	return &acc, nil
}

func (s *oauthAccountStore) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*db.OAuthAccount, error) {
	var accounts []*db.OAuthAccount
	// Most recently updated first: a user can hold two links for one provider
	// and the newest is the one a single-row lookup must resolve.
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("updated_at DESC").Find(&accounts).Error; err != nil {
		return nil, err
	}
	return accounts, nil
}

func (s *oauthAccountStore) UpdateProviderUserID(ctx context.Context, id uuid.UUID, providerUserID string) error {
	res := s.db.WithContext(ctx).Model(&db.OAuthAccount{}).Where("id = ?", id).Update("provider_user_id", providerUserID)
	if err := res.Error; err != nil {
		return db.NormalizeMySQLError(err)
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (s *oauthAccountStore) Delete(ctx context.Context, id uuid.UUID) error {
	return s.db.WithContext(ctx).Where("id = ?", id).Delete(&db.OAuthAccount{}).Error
}

func (s *oauthAccountStore) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	return s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&db.OAuthAccount{}).Error
}

// oauthTokenUpdates builds the column payload both write paths share. updated_at
// is always restamped, so the row changes unless a retry lands inside the same
// timestamp precision with an identical record.
func oauthTokenUpdates(rec db.OAuthTokenRecord) map[string]any {
	return map[string]any{
		"access_token_ciphertext":   rec.AccessTokenCiphertext,
		"refresh_token_ciphertext":  rec.RefreshTokenCiphertext,
		"refresh_token_fingerprint": rec.RefreshTokenFingerprint,
		"token_scope":               rec.TokenScope,
		"token_expires_at":          rec.TokenExpiresAt,
		"updated_at":                time.Now().UTC(),
	}
}

func (s *oauthAccountStore) SaveOAuthTokens(ctx context.Context, id uuid.UUID, rec db.OAuthTokenRecord) error {
	res := s.db.WithContext(ctx).Model(&db.OAuthAccount{}).Where("id = ?", id).Updates(oauthTokenUpdates(rec))
	if err := res.Error; err != nil {
		return db.NormalizeMySQLError(err)
	}
	if res.RowsAffected > 0 {
		return nil
	}
	// MySQL reports 0 affected rows for an UPDATE that changes nothing (identical
	// tokens saved inside the same microsecond), so zero rows alone cannot prove
	// the account is missing. CAS needs no equivalent: there a no-op reports a
	// miss and the caller re-reads the winner's token, which is the same outcome.
	var exists int64
	if err := s.db.WithContext(ctx).Model(&db.OAuthAccount{}).Where("id = ?", id).Count(&exists).Error; err != nil {
		return db.NormalizeMySQLError(err)
	}
	if exists == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (s *oauthAccountStore) SaveOAuthTokensCAS(ctx context.Context, id uuid.UUID, expectedFingerprint string, rec db.OAuthTokenRecord) (bool, error) {
	if expectedFingerprint == "" {
		return false, nil
	}
	res := s.db.WithContext(ctx).Model(&db.OAuthAccount{}).
		Where("id = ? AND refresh_token_fingerprint = ?", id, expectedFingerprint).
		Updates(oauthTokenUpdates(rec))
	if err := res.Error; err != nil {
		return false, db.NormalizeMySQLError(err)
	}
	return res.RowsAffected > 0, nil
}

func (s *oauthAccountStore) SaveOAuthTokensIfUnset(ctx context.Context, id uuid.UUID, rec db.OAuthTokenRecord) (bool, error) {
	res := s.db.WithContext(ctx).Model(&db.OAuthAccount{}).
		Where("id = ? AND refresh_token_fingerprint = ?", id, "").
		Updates(oauthTokenUpdates(rec))
	if err := res.Error; err != nil {
		return false, db.NormalizeMySQLError(err)
	}
	return res.RowsAffected > 0, nil
}

// oauthAccessUpdates is the column payload for an access-only write: the refresh
// columns are deliberately absent so a tokenless grant cannot erase them.
func oauthAccessUpdates(rec db.OAuthTokenRecord) map[string]any {
	return map[string]any{
		"access_token_ciphertext": rec.AccessTokenCiphertext,
		"token_scope":             rec.TokenScope,
		"token_expires_at":        rec.TokenExpiresAt,
		"updated_at":              time.Now().UTC(),
	}
}

func (s *oauthAccountStore) SaveOAuthAccess(ctx context.Context, id uuid.UUID, rec db.OAuthTokenRecord) error {
	res := s.db.WithContext(ctx).Model(&db.OAuthAccount{}).Where("id = ?", id).Updates(oauthAccessUpdates(rec))
	if err := res.Error; err != nil {
		return db.NormalizeMySQLError(err)
	}
	if res.RowsAffected > 0 {
		return nil
	}
	// Same MySQL no-op caveat as SaveOAuthTokens: zero affected rows alone does
	// not prove the account is missing.
	var exists int64
	if err := s.db.WithContext(ctx).Model(&db.OAuthAccount{}).Where("id = ?", id).Count(&exists).Error; err != nil {
		return db.NormalizeMySQLError(err)
	}
	if exists == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// SaveOAuthAccessCAS writes the access columns only while the stored access
// ciphertext still matches the value the caller read. A miss reports false: a
// newer access envelope is stored, and MySQL would also report one for a write
// that changed nothing, which is the same outcome.
func (s *oauthAccountStore) SaveOAuthAccessCAS(ctx context.Context, id uuid.UUID, expectedCiphertext string, rec db.OAuthTokenRecord) (bool, error) {
	res := s.db.WithContext(ctx).Model(&db.OAuthAccount{}).
		Where("id = ? AND access_token_ciphertext = ?", id, expectedCiphertext).
		Updates(oauthAccessUpdates(rec))
	if err := res.Error; err != nil {
		return false, db.NormalizeMySQLError(err)
	}
	return res.RowsAffected > 0, nil
}

// ClearOAuthRefresh empties the refresh columns only, guarded on the fingerprint
// the caller read: the access envelope has its own writers and is never touched.
func (s *oauthAccountStore) ClearOAuthRefresh(ctx context.Context, id uuid.UUID, expectedFingerprint string) (bool, error) {
	if expectedFingerprint == "" {
		return false, nil
	}
	res := s.db.WithContext(ctx).Model(&db.OAuthAccount{}).
		Where("id = ? AND refresh_token_fingerprint = ?", id, expectedFingerprint).
		Updates(map[string]any{
			"refresh_token_ciphertext":  "",
			"refresh_token_fingerprint": "",
			"updated_at":                time.Now().UTC(),
		})
	if err := res.Error; err != nil {
		return false, db.NormalizeMySQLError(err)
	}
	return res.RowsAffected > 0, nil
}

// SaveOAuthRefreshIfUnset stores a rotated refresh pair over a row holding none,
// then fills the access columns only while the row still holds no access
// envelope, so a concurrent access-only winner keeps its own. Each guard lives
// in its own WHERE clause, which every backend evaluates against the original
// row: no assignment may read a column the same statement writes, because MySQL
// applies single-table SET assignments left to right against already-updated
// values.
//
// The two statements run sequentially, so the access write is skipped when the
// refresh guard misses — a stored refresh grant owns the row and the caller lost
// — and a failed access write reports (true, error): the refresh pair landed and
// the row keeps a usable grant.
func (s *oauthAccountStore) SaveOAuthRefreshIfUnset(ctx context.Context, id uuid.UUID, rec db.OAuthTokenRecord) (bool, error) {
	if rec.RefreshTokenFingerprint == "" {
		return false, nil
	}
	res := s.db.WithContext(ctx).Model(&db.OAuthAccount{}).
		Where("id = ? AND refresh_token_fingerprint = ?", id, "").
		Updates(map[string]any{
			"refresh_token_ciphertext":  rec.RefreshTokenCiphertext,
			"refresh_token_fingerprint": rec.RefreshTokenFingerprint,
			"updated_at":                time.Now().UTC(),
		})
	if err := res.Error; err != nil {
		return false, db.NormalizeMySQLError(err)
	}
	if res.RowsAffected == 0 {
		return false, nil
	}
	if rec.AccessTokenCiphertext == "" {
		return true, nil
	}
	access := s.db.WithContext(ctx).Model(&db.OAuthAccount{}).
		Where("id = ? AND access_token_ciphertext = ?", id, "").
		Updates(oauthAccessUpdates(rec))
	if err := access.Error; err != nil {
		return true, db.NormalizeMySQLError(err)
	}
	return true, nil
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

// totpRewrapRow is the explicit projection the sweep reads. secret_kid is not on
// db.TotpSecret on purpose: a modelled field would join every SELECT and every
// INSERT, and a down-migrated database would then break all TOTP traffic.
type totpRewrapRow struct {
	ID              uuid.UUID `gorm:"column:id"`
	UserID          uuid.UUID `gorm:"column:user_id"`
	EncryptedSecret []byte    `gorm:"column:encrypted_secret"`
	SecretKid       string    `gorm:"column:secret_kid"`
}

func (s *totpStore) ListSecretsForRewrap(ctx context.Context, afterID uuid.UUID, limit int) ([]db.TotpSecretRewrap, error) {
	if limit <= 0 {
		return nil, nil
	}

	var rows []totpRewrapRow
	err := s.db.WithContext(ctx).
		Table("totp_secrets").
		Select("id, user_id, encrypted_secret, secret_kid").
		Where("id > ?", afterID.String()).
		Order("id ASC").
		Limit(limit).
		Scan(&rows).Error
	if err != nil {
		return nil, db.NormalizeMySQLError(err)
	}

	secrets := make([]db.TotpSecretRewrap, 0, len(rows))
	for _, row := range rows {
		secrets = append(secrets, db.TotpSecretRewrap{
			ID:              row.ID,
			UserID:          row.UserID,
			EncryptedSecret: row.EncryptedSecret,
			SecretKid:       row.SecretKid,
		})
	}
	return secrets, nil
}

func (s *totpStore) UpdateSecretForRewrap(ctx context.Context, id uuid.UUID, expectedCiphertext, newCiphertext []byte, newKid string) (bool, error) {
	res := s.db.WithContext(ctx).Exec(
		"UPDATE totp_secrets SET encrypted_secret = ?, secret_kid = ?, updated_at = ? WHERE id = ? AND encrypted_secret = ?",
		newCiphertext, newKid, time.Now().UTC(), id.String(), expectedCiphertext,
	)
	if res.Error != nil {
		return false, db.NormalizeMySQLError(res.Error)
	}
	return res.RowsAffected > 0, nil
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

func (s *totpStore) UpdateBackupCodesCAS(ctx context.Context, userID uuid.UUID, expectedCodes []string, newCodes []string) (bool, error) {
	expectedJSON, err := json.Marshal(expectedCodes)
	if err != nil {
		return false, err
	}
	newJSON, err := json.Marshal(newCodes)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()

	var res *gorm.DB
	switch s.db.Name() {
	case "postgres":
		res = s.db.WithContext(ctx).Exec(
			"UPDATE totp_secrets SET backup_codes = CAST(? AS jsonb), updated_at = ? WHERE user_id = ? AND enabled = true AND (backup_codes = CAST(? AS jsonb) OR CAST(backup_codes AS TEXT) = ?)",
			string(newJSON), now, userID.String(), string(expectedJSON), string(expectedJSON),
		)
	case "mysql":
		res = s.db.WithContext(ctx).Exec(
			"UPDATE totp_secrets SET backup_codes = CAST(? AS JSON), updated_at = ? WHERE user_id = ? AND enabled = true AND (backup_codes = CAST(? AS JSON) OR backup_codes = ?)",
			string(newJSON), now, userID.String(), string(expectedJSON), string(expectedJSON),
		)
	default:
		res = s.db.WithContext(ctx).Exec(
			"UPDATE totp_secrets SET backup_codes = ?, updated_at = ? WHERE user_id = ? AND enabled = true AND (backup_codes = ? OR backup_codes = ?)",
			string(newJSON), now, userID.String(), string(expectedJSON), expectedJSON,
		)
	}

	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
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

func (s *totpStore) ConsumeTwoFactorToken(ctx context.Context, tokenHash []byte, maxAttempts int, now time.Time) (bool, error) {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	res := s.db.WithContext(ctx).
		Where("token_hash = ? AND expires_at > ? AND attempts < ?", tokenHash, now.UTC(), maxAttempts).
		Delete(&db.TwoFactorToken{})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (s *totpStore) DeleteTwoFactorToken(ctx context.Context, id uuid.UUID) (int64, error) {
	res := s.db.WithContext(ctx).Where("id = ?", id).Delete(&db.TwoFactorToken{})
	return res.RowsAffected, res.Error
}

func (s *totpStore) DeleteTwoFactorTokensByUserID(ctx context.Context, userID uuid.UUID) error {
	return s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&db.TwoFactorToken{}).Error
}

type claimedEmailStore struct {
	db *gorm.DB
}

func (s *claimedEmailStore) Claim(ctx context.Context, email string, ownerID uuid.UUID, verified bool) error {
	return db.ClaimWithin(ctx, s.db, email, ownerID, verified)
}

func (s *claimedEmailStore) Get(ctx context.Context, email string) (*db.ClaimedEmail, error) {
	key := db.NormalizeEmail(email)
	if key == "" {
		return nil, gorm.ErrRecordNotFound
	}
	var claim db.ClaimedEmail
	if err := s.db.WithContext(ctx).Where("email = ?", key).First(&claim).Error; err != nil {
		return nil, err
	}
	return &claim, nil
}

func (s *claimedEmailStore) Release(ctx context.Context, email string, ownerID uuid.UUID) error {
	key := db.NormalizeEmail(email)
	if key == "" {
		return nil
	}
	return s.db.WithContext(ctx).Where("email = ? AND owner_user_id = ?", key, ownerID).Delete(&db.ClaimedEmail{}).Error
}

func (s *claimedEmailStore) ReleaseByUserID(ctx context.Context, ownerID uuid.UUID) error {
	return s.db.WithContext(ctx).Where("owner_user_id = ?", ownerID).Delete(&db.ClaimedEmail{}).Error
}

type gormStore struct {
	db                 *gorm.DB
	users              *userStore
	sessions           *sessionStore
	verificationTokens *verificationTokenStore
	passwordReset      *passwordResetTokenStore
	oauthAccounts      *oauthAccountStore
	totp               *totpStore
	claimedEmails      *claimedEmailStore
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
		claimedEmails:      &claimedEmailStore{db: database},
	}
}

func (s *gormStore) Users() db.UserStore                             { return s.users }
func (s *gormStore) Sessions() db.SessionStore                       { return s.sessions }
func (s *gormStore) VerificationTokens() db.VerificationTokenStore   { return s.verificationTokens }
func (s *gormStore) PasswordResetTokens() db.PasswordResetTokenStore { return s.passwordReset }
func (s *gormStore) OAuthAccounts() db.OAuthAccountStore             { return s.oauthAccounts }
func (s *gormStore) Totp() db.TotpStore                              { return s.totp }
func (s *gormStore) ClaimedEmails() db.ClaimedEmailStore             { return s.claimedEmails }

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
