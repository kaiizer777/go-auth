package mongostore

import (
	"time"

	"github.com/google/uuid"
	"github.com/kaiizer777/go-auth/db"
)

// UserDoc represents a user account document in the "users" collection.
type UserDoc struct {
	ID                string    `bson:"_id"`
	Email             string    `bson:"email"`
	PasswordHash      string    `bson:"password_hash"`
	CredentialVersion int       `bson:"credential_version"`
	EmailVerified     bool      `bson:"email_verified"`
	CreatedAt         time.Time `bson:"created_at"`
	UpdatedAt         time.Time `bson:"updated_at"`
}

func userDocFromDomain(u *db.User) *UserDoc {
	if u == nil {
		return nil
	}
	id := u.ID
	if id == uuid.Nil {
		id = uuid.New()
		u.ID = id
	}
	createdAt := u.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
		u.CreatedAt = createdAt
	}
	updatedAt := u.UpdatedAt.UTC()
	if updatedAt.IsZero() {
		updatedAt = createdAt
		u.UpdatedAt = updatedAt
	}
	return &UserDoc{
		ID:                id.String(),
		Email:             u.Email,
		PasswordHash:      u.PasswordHash,
		CredentialVersion: u.CredentialVersion,
		EmailVerified:     u.EmailVerified,
		CreatedAt:         createdAt,
		UpdatedAt:         updatedAt,
	}
}

func (d *UserDoc) toDomain() *db.User {
	if d == nil {
		return nil
	}
	id, _ := uuid.Parse(d.ID)
	return &db.User{
		ID:                id,
		Email:             d.Email,
		PasswordHash:      d.PasswordHash,
		CredentialVersion: d.CredentialVersion,
		EmailVerified:     d.EmailVerified,
		CreatedAt:         d.CreatedAt.UTC(),
		UpdatedAt:         d.UpdatedAt.UTC(),
	}
}

// SessionDoc represents an authenticated session document in the "sessions" collection.
type SessionDoc struct {
	ID                string         `bson:"_id"`
	UserID            string         `bson:"user_id"`
	IDHash            string         `bson:"id_hash"`
	SessionType       db.SessionType `bson:"session_type"`
	IPAddress         string         `bson:"ip_address"`
	UserAgent         string         `bson:"user_agent"`
	CredentialVersion int            `bson:"credential_version"`
	LastActiveAt      time.Time      `bson:"last_active_at"`
	AbsoluteExpiresAt time.Time      `bson:"absolute_expires_at"`
	CreatedAt         time.Time      `bson:"created_at"`
}

func sessionDocFromDomain(s *db.Session) *SessionDoc {
	if s == nil {
		return nil
	}
	id := s.ID
	if id == uuid.Nil {
		id = uuid.New()
		s.ID = id
	}
	createdAt := s.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
		s.CreatedAt = createdAt
	}
	return &SessionDoc{
		ID:                id.String(),
		UserID:            s.UserID.String(),
		IDHash:            s.IDHash,
		SessionType:       s.SessionType,
		IPAddress:         s.IPAddress,
		UserAgent:         s.UserAgent,
		CredentialVersion: s.CredentialVersion,
		LastActiveAt:      s.LastActiveAt.UTC(),
		AbsoluteExpiresAt: s.AbsoluteExpiresAt.UTC(),
		CreatedAt:         createdAt,
	}
}

func (d *SessionDoc) toDomain() *db.Session {
	if d == nil {
		return nil
	}
	id, _ := uuid.Parse(d.ID)
	userID, _ := uuid.Parse(d.UserID)
	return &db.Session{
		ID:                id,
		UserID:            userID,
		IDHash:            d.IDHash,
		SessionType:       d.SessionType,
		IPAddress:         d.IPAddress,
		UserAgent:         d.UserAgent,
		CredentialVersion: d.CredentialVersion,
		LastActiveAt:      d.LastActiveAt.UTC(),
		AbsoluteExpiresAt: d.AbsoluteExpiresAt.UTC(),
		CreatedAt:         d.CreatedAt.UTC(),
	}
}

// VerificationTokenDoc represents an email verification token document in the "verification_tokens" collection.
type VerificationTokenDoc struct {
	TokenHash []byte    `bson:"_id"`
	UserID    string    `bson:"user_id"`
	ExpiresAt time.Time `bson:"expires_at"`
	CreatedAt time.Time `bson:"created_at"`
}

func verificationTokenDocFromDomain(v *db.VerificationToken) *VerificationTokenDoc {
	if v == nil {
		return nil
	}
	createdAt := v.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
		v.CreatedAt = createdAt
	}
	return &VerificationTokenDoc{
		TokenHash: v.TokenHash,
		UserID:    v.UserID.String(),
		ExpiresAt: v.ExpiresAt.UTC(),
		CreatedAt: createdAt,
	}
}

func (d *VerificationTokenDoc) toDomain() *db.VerificationToken {
	if d == nil {
		return nil
	}
	userID, _ := uuid.Parse(d.UserID)
	return &db.VerificationToken{
		TokenHash: d.TokenHash,
		UserID:    userID,
		ExpiresAt: d.ExpiresAt.UTC(),
		CreatedAt: d.CreatedAt.UTC(),
	}
}

// PasswordResetTokenDoc represents a password reset token document in the "password_reset_tokens" collection.
type PasswordResetTokenDoc struct {
	TokenHash []byte    `bson:"_id"`
	UserID    string    `bson:"user_id"`
	ExpiresAt time.Time `bson:"expires_at"`
	CreatedAt time.Time `bson:"created_at"`
}

func passwordResetTokenDocFromDomain(p *db.PasswordResetToken) *PasswordResetTokenDoc {
	if p == nil {
		return nil
	}
	createdAt := p.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
		p.CreatedAt = createdAt
	}
	return &PasswordResetTokenDoc{
		TokenHash: p.TokenHash,
		UserID:    p.UserID.String(),
		ExpiresAt: p.ExpiresAt.UTC(),
		CreatedAt: createdAt,
	}
}

func (d *PasswordResetTokenDoc) toDomain() *db.PasswordResetToken {
	if d == nil {
		return nil
	}
	userID, _ := uuid.Parse(d.UserID)
	return &db.PasswordResetToken{
		TokenHash: d.TokenHash,
		UserID:    userID,
		ExpiresAt: d.ExpiresAt.UTC(),
		CreatedAt: d.CreatedAt.UTC(),
	}
}

// OAuthAccountDoc represents a federated identity document in the "oauth_accounts" collection.
// A document written before the verified flag existed decodes as false: missing
// fields land on the Go zero value, which is the fail-closed default. Startup
// re-derives the flag from the owning user (BackfillOAuthAccountVerified), so a
// legacy link on a locally verified account keeps signing in.
//
// provider_tenant_id scopes the identity to the tenant that issued it; it is
// part of the unique index, so a pairwise subject can exist once per tenant.
type OAuthAccountDoc struct {
	ID               string    `bson:"_id"`
	UserID           string    `bson:"user_id"`
	ProviderID       string    `bson:"provider_id"`
	ProviderTenantID string    `bson:"provider_tenant_id"`
	ProviderUserID   string    `bson:"provider_user_id"`
	Email            string    `bson:"email"`
	Verified         bool      `bson:"verified"`
	CreatedAt        time.Time `bson:"created_at"`
	UpdatedAt        time.Time `bson:"updated_at"`
}

func oauthAccountDocFromDomain(o *db.OAuthAccount) *OAuthAccountDoc {
	if o == nil {
		return nil
	}
	id := o.ID
	if id == uuid.Nil {
		id = uuid.New()
		o.ID = id
	}
	createdAt := o.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
		o.CreatedAt = createdAt
	}
	updatedAt := o.UpdatedAt.UTC()
	if updatedAt.IsZero() {
		updatedAt = createdAt
		o.UpdatedAt = updatedAt
	}
	return &OAuthAccountDoc{
		ID:               id.String(),
		UserID:           o.UserID.String(),
		ProviderID:       o.ProviderID,
		ProviderTenantID: o.ProviderTenantID,
		ProviderUserID:   o.ProviderUserID,
		Email:            o.Email,
		Verified:         o.Verified,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
	}
}

func (d *OAuthAccountDoc) toDomain() *db.OAuthAccount {
	if d == nil {
		return nil
	}
	id, _ := uuid.Parse(d.ID)
	userID, _ := uuid.Parse(d.UserID)
	return &db.OAuthAccount{
		ID:               id,
		UserID:           userID,
		ProviderID:       d.ProviderID,
		ProviderTenantID: d.ProviderTenantID,
		ProviderUserID:   d.ProviderUserID,
		Email:            d.Email,
		Verified:         d.Verified,
		CreatedAt:        d.CreatedAt.UTC(),
		UpdatedAt:        d.UpdatedAt.UTC(),
	}
}

// TotpSecretDoc represents an enrolled TOTP configuration document in the "totp_secrets" collection.
type TotpSecretDoc struct {
	ID              string    `bson:"_id"`
	UserID          string    `bson:"user_id"`
	EncryptedSecret []byte    `bson:"encrypted_secret"`
	BackupCodes     []byte    `bson:"backup_codes"`
	Enabled         bool      `bson:"enabled"`
	CreatedAt       time.Time `bson:"created_at"`
	UpdatedAt       time.Time `bson:"updated_at"`
}

func totpSecretDocFromDomain(t *db.TotpSecret) *TotpSecretDoc {
	if t == nil {
		return nil
	}
	id := t.ID
	if id == uuid.Nil {
		id = uuid.New()
		t.ID = id
	}
	createdAt := t.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
		t.CreatedAt = createdAt
	}
	updatedAt := t.UpdatedAt.UTC()
	if updatedAt.IsZero() {
		updatedAt = createdAt
		t.UpdatedAt = updatedAt
	}
	backupCodes := t.BackupCodes
	if backupCodes == nil {
		backupCodes = []byte("[]")
	}
	return &TotpSecretDoc{
		ID:              id.String(),
		UserID:          t.UserID.String(),
		EncryptedSecret: t.EncryptedSecret,
		BackupCodes:     backupCodes,
		Enabled:         t.Enabled,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}
}

func (d *TotpSecretDoc) toDomain() *db.TotpSecret {
	if d == nil {
		return nil
	}
	id, _ := uuid.Parse(d.ID)
	userID, _ := uuid.Parse(d.UserID)
	return &db.TotpSecret{
		ID:              id,
		UserID:          userID,
		EncryptedSecret: d.EncryptedSecret,
		BackupCodes:     d.BackupCodes,
		Enabled:         d.Enabled,
		CreatedAt:       d.CreatedAt.UTC(),
		UpdatedAt:       d.UpdatedAt.UTC(),
	}
}

// TotpUsedCodeDoc tracks consumed TOTP verification codes in the "totp_used_codes" collection.
type TotpUsedCodeDoc struct {
	ID       string    `bson:"_id"`
	UserID   string    `bson:"user_id"`
	CodeHash []byte    `bson:"code_hash"`
	UsedAt   time.Time `bson:"used_at"`
}

func totpUsedCodeDocFromDomain(c *db.TotpUsedCode) *TotpUsedCodeDoc {
	if c == nil {
		return nil
	}
	id := c.ID
	if id == uuid.Nil {
		id = uuid.New()
		c.ID = id
	}
	usedAt := c.UsedAt.UTC()
	if usedAt.IsZero() {
		usedAt = time.Now().UTC()
		c.UsedAt = usedAt
	}
	return &TotpUsedCodeDoc{
		ID:       id.String(),
		UserID:   c.UserID.String(),
		CodeHash: c.CodeHash,
		UsedAt:   usedAt,
	}
}

func (d *TotpUsedCodeDoc) toDomain() *db.TotpUsedCode {
	if d == nil {
		return nil
	}
	id, _ := uuid.Parse(d.ID)
	userID, _ := uuid.Parse(d.UserID)
	return &db.TotpUsedCode{
		ID:       id,
		UserID:   userID,
		CodeHash: d.CodeHash,
		UsedAt:   d.UsedAt.UTC(),
	}
}

// TwoFactorTokenDoc represents an ephemeral challenge token document in the "two_factor_tokens" collection.
type TwoFactorTokenDoc struct {
	ID        string    `bson:"_id"`
	UserID    string    `bson:"user_id"`
	TokenHash []byte    `bson:"token_hash"`
	ExpiresAt time.Time `bson:"expires_at"`
	Attempts  int       `bson:"attempts"`
}

func twoFactorTokenDocFromDomain(t *db.TwoFactorToken) *TwoFactorTokenDoc {
	if t == nil {
		return nil
	}
	id := t.ID
	if id == uuid.Nil {
		id = uuid.New()
		t.ID = id
	}
	return &TwoFactorTokenDoc{
		ID:        id.String(),
		UserID:    t.UserID.String(),
		TokenHash: t.TokenHash,
		ExpiresAt: t.ExpiresAt.UTC(),
		Attempts:  t.Attempts,
	}
}

func (d *TwoFactorTokenDoc) toDomain() *db.TwoFactorToken {
	if d == nil {
		return nil
	}
	id, _ := uuid.Parse(d.ID)
	userID, _ := uuid.Parse(d.UserID)
	return &db.TwoFactorToken{
		ID:        id,
		UserID:    userID,
		TokenHash: d.TokenHash,
		ExpiresAt: d.ExpiresAt.UTC(),
		Attempts:  d.Attempts,
	}
}
