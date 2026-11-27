package db

import (
	"log/slog"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents an authenticated account record in the database.
type User struct {
	ID                uuid.UUID `gorm:"primaryKey;type:varchar(36)"`
	Email             string    `gorm:"type:varchar(255);uniqueIndex;not null"`
	PasswordHash      string    `gorm:"type:text;not null" json:"-"`
	CredentialVersion int       `gorm:"not null;default:0"`
	EmailVerified     bool      `gorm:"default:false;not null"`
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// BeforeCreate hook generates a new UUID if none is set.
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// LogValue implements slog.LogValuer to prevent credential leakage in logs.
func (u User) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", u.ID.String()),
		slog.String("email", u.Email),
		slog.String("password_hash", "[REDACTED]"),
		slog.Int("credential_version", u.CredentialVersion),
		slog.Bool("email_verified", u.EmailVerified),
		slog.Time("created_at", u.CreatedAt),
		slog.Time("updated_at", u.UpdatedAt),
	)
}

// TableName returns the table name for User.
func (User) TableName() string { return "users" }

// SessionType represents the session transport type enum.
type SessionType string

const (
	SessionTypeCookie SessionType = "cookie"
	SessionTypeBearer SessionType = "bearer"
)

// Session represents an active authenticated user session.
type Session struct {
	ID                uuid.UUID   `gorm:"primaryKey;type:varchar(36)"`
	UserID            uuid.UUID   `gorm:"type:varchar(36);not null;index:idx_sessions_user_id"`
	IDHash            string      `gorm:"column:id_hash;type:char(64);uniqueIndex;not null" json:"-"`
	SessionType       SessionType `gorm:"type:varchar(10);not null;default:'cookie'"`
	IPAddress         string      `gorm:"type:varchar(45);not null;default:''"`
	UserAgent         string      `gorm:"type:text;not null;default:''"`
	CredentialVersion int         `gorm:"not null;default:0"`
	LastActiveAt      time.Time   `gorm:"not null"`
	AbsoluteExpiresAt time.Time   `gorm:"not null"`
	CreatedAt         time.Time   `gorm:"autoCreateTime"`
}

// BeforeCreate hook generates a new UUID if none is set.
func (s *Session) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

// TableName returns the table name for Session.
func (Session) TableName() string { return "sessions" }

// LogValue implements slog.LogValuer to prevent session hash leakage in logs.
func (s Session) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", s.ID.String()),
		slog.String("user_id", s.UserID.String()),
		slog.String("id_hash", "[REDACTED]"),
		slog.String("session_type", string(s.SessionType)),
		slog.String("ip_address", s.IPAddress),
		slog.String("user_agent", s.UserAgent),
		slog.Int("credential_version", s.CredentialVersion),
		slog.Time("last_active_at", s.LastActiveAt),
		slog.Time("absolute_expires_at", s.AbsoluteExpiresAt),
		slog.Time("created_at", s.CreatedAt),
	)
}

// VerificationToken represents an email verification token record.
type VerificationToken struct {
	TokenHash []byte    `gorm:"primaryKey;column:token_hash" json:"-"`
	UserID    uuid.UUID `gorm:"type:varchar(36);not null;index:idx_verification_tokens_user_id"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

// TableName returns the table name for VerificationToken.
func (VerificationToken) TableName() string { return "verification_tokens" }

// LogValue implements slog.LogValuer to prevent token hash leakage in logs.
func (v VerificationToken) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("token_hash", "[REDACTED]"),
		slog.String("user_id", v.UserID.String()),
		slog.Time("expires_at", v.ExpiresAt),
		slog.Time("created_at", v.CreatedAt),
	)
}

// PasswordResetToken represents a single-use password reset token record.
type PasswordResetToken struct {
	TokenHash []byte    `gorm:"primaryKey;column:token_hash" json:"-"`
	UserID    uuid.UUID `gorm:"type:varchar(36);not null;index:idx_password_reset_tokens_user_id"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

// TableName returns the table name for PasswordResetToken.
func (PasswordResetToken) TableName() string { return "password_reset_tokens" }

// LogValue implements slog.LogValuer to prevent token hash leakage in logs.
func (p PasswordResetToken) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("token_hash", "[REDACTED]"),
		slog.String("user_id", p.UserID.String()),
		slog.Time("expires_at", p.ExpiresAt),
		slog.Time("created_at", p.CreatedAt),
	)
}

// OAuthAccount represents an external federated identity linked to a user.
// Uniqueness of (provider_id, provider_tenant_id, provider_user_id) is enforced
// by the uq_oauth_accounts_provider_tenant_uid composite unique index (migration
// 000011), not by the single-column indexes below. ProviderTenantID scopes an
// identity to the tenant that issued it: a pairwise subject is only unique
// within its tenant. Providers without a tenant namespace store "".
//
// Verified records that the provider attested Email for this identity. An
// unverified link may only sign in the account it was created on, and only
// while that account still holds no proven credential; it can never merge,
// recover, or resolve by email. Legacy rows decode as false (fail-closed).
//
// The token columns hold opaque AES-256-GCM envelopes, never plaintext: this
// package is plaintext-blind and does no crypto. AccessTokenCiphertext and
// RefreshTokenCiphertext are the sealed envelopes, RefreshTokenFingerprint is
// the hex SHA-256 fingerprint of the stored refresh token, and TokenExpiresAt is
// nil while no token is stored.
type OAuthAccount struct {
	ID                      uuid.UUID `gorm:"primaryKey;type:varchar(36)"`
	UserID                  uuid.UUID `gorm:"type:varchar(36);not null;index"`
	ProviderID              string    `gorm:"type:varchar(32);not null"`
	ProviderTenantID        string    `gorm:"type:varchar(64);not null"`
	ProviderUserID          string    `gorm:"type:varchar(255);not null"`
	Email                   string    `gorm:"type:varchar(255);not null;index"`
	Verified                bool      `gorm:"not null;default:false"`
	AccessTokenCiphertext   string    `gorm:"type:text;not null;default:''" json:"-"`
	RefreshTokenCiphertext  string    `gorm:"type:text;not null;default:''" json:"-"`
	RefreshTokenFingerprint string    `gorm:"type:varchar(64);not null;default:''" json:"-"`
	TokenExpiresAt          *time.Time
	TokenScope              string `gorm:"type:text;not null;default:''"`
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

// BeforeCreate hook generates a new UUID if none is set.
func (o *OAuthAccount) BeforeCreate(tx *gorm.DB) error {
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}
	return nil
}

// TableName returns the table name for OAuthAccount.
func (OAuthAccount) TableName() string { return "oauth_accounts" }

// LogValue implements slog.LogValuer to prevent federated identifier and token
// leakage in logs.
func (o OAuthAccount) LogValue() slog.Value {
	// A nil expiry is the honest "no token stored" state; a zero time.Time
	// would render as year 1 and read like a real expiry.
	expiresAt := slog.Any("token_expires_at", nil)
	if o.TokenExpiresAt != nil {
		expiresAt = slog.Time("token_expires_at", o.TokenExpiresAt.UTC())
	}
	return slog.GroupValue(
		slog.String("id", o.ID.String()),
		slog.String("user_id", o.UserID.String()),
		slog.String("provider_id", o.ProviderID),
		slog.String("provider_tenant_id", o.ProviderTenantID),
		slog.String("provider_user_id", "[REDACTED]"),
		slog.String("email", o.Email),
		slog.Bool("verified", o.Verified),
		slog.String("access_token_ciphertext", "[REDACTED]"),
		slog.String("refresh_token_ciphertext", "[REDACTED]"),
		slog.String("refresh_token_fingerprint", "[REDACTED]"),
		expiresAt,
		slog.String("token_scope", o.TokenScope),
		slog.Time("created_at", o.CreatedAt),
		slog.Time("updated_at", o.UpdatedAt),
	)
}

// TotpSecret represents an enrolled TOTP two-factor configuration for a user.
type TotpSecret struct {
	ID              uuid.UUID `gorm:"primaryKey;type:varchar(36)"`
	UserID          uuid.UUID `gorm:"type:varchar(36);not null;uniqueIndex:uq_totp_secrets_user_id"`
	EncryptedSecret []byte    `gorm:"not null" json:"-"`
	BackupCodes     []byte    `gorm:"not null;default:'[]'" json:"-"`
	Enabled         bool      `gorm:"not null;default:false"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// BeforeCreate hook generates a new UUID if none is set.
func (t *TotpSecret) BeforeCreate(tx *gorm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	return nil
}

// TableName returns the table name for TotpSecret.
func (TotpSecret) TableName() string { return "totp_secrets" }

// LogValue implements slog.LogValuer to prevent TOTP secret and backup code leakage in logs.
func (t TotpSecret) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", t.ID.String()),
		slog.String("user_id", t.UserID.String()),
		slog.String("encrypted_secret", "[REDACTED]"),
		slog.String("backup_codes", "[REDACTED]"),
		slog.Bool("enabled", t.Enabled),
		slog.Time("created_at", t.CreatedAt),
		slog.Time("updated_at", t.UpdatedAt),
	)
}

// TotpUsedCode tracks consumed TOTP verification codes to enforce single-use replay protection.
type TotpUsedCode struct {
	ID       uuid.UUID `gorm:"primaryKey;type:varchar(36)"`
	UserID   uuid.UUID `gorm:"type:varchar(36);not null;uniqueIndex:uq_totp_used_codes_user_code,composite:user_code"`
	CodeHash []byte    `gorm:"not null;uniqueIndex:uq_totp_used_codes_user_code,composite:user_code" json:"-"`
	UsedAt   time.Time `gorm:"not null;index:idx_totp_used_codes_user_used_at"`
}

// BeforeCreate hook generates a new UUID if none is set.
func (c *TotpUsedCode) BeforeCreate(tx *gorm.DB) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	return nil
}

// TableName returns the table name for TotpUsedCode.
func (TotpUsedCode) TableName() string { return "totp_used_codes" }

// LogValue implements slog.LogValuer to prevent code hash leakage in logs.
func (c TotpUsedCode) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", c.ID.String()),
		slog.String("user_id", c.UserID.String()),
		slog.String("code_hash", "[REDACTED]"),
		slog.Time("used_at", c.UsedAt),
	)
}

// TwoFactorToken represents an ephemeral challenge token issued pending 2FA completion.
// INVARIANT: Soft deletes are strictly banned on security tokens; hard delete only.
type TwoFactorToken struct {
	ID        uuid.UUID `gorm:"primaryKey;type:varchar(36)"`
	UserID    uuid.UUID `gorm:"type:varchar(36);not null;index:idx_two_factor_tokens_user_id"`
	TokenHash []byte    `gorm:"uniqueIndex:uq_two_factor_tokens_token_hash;not null" json:"-"`
	ExpiresAt time.Time `gorm:"not null;index:idx_two_factor_tokens_expires_at"`
	Attempts  int       `gorm:"not null;default:0"`
}

// BeforeCreate hook generates a new UUID if none is set.
func (t *TwoFactorToken) BeforeCreate(tx *gorm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	return nil
}

// TableName returns the table name for TwoFactorToken.
func (TwoFactorToken) TableName() string { return "two_factor_tokens" }

// LogValue implements slog.LogValuer to prevent challenge token hash leakage in logs.
func (t TwoFactorToken) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", t.ID.String()),
		slog.String("user_id", t.UserID.String()),
		slog.String("token_hash", "[REDACTED]"),
		slog.Time("expires_at", t.ExpiresAt),
		slog.Int("attempts", t.Attempts),
	)
}
