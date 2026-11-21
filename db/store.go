package db

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// UserStore defines storage operations for user account persistence and lifecycle.
type UserStore interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, user *User) error
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	IncrementCredentialVersion(ctx context.Context, userID uuid.UUID) (uint32, error)
	SetEmailVerified(ctx context.Context, id uuid.UUID, verified bool) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// SessionStore defines storage operations for authenticated session persistence.
type SessionStore interface {
	Create(ctx context.Context, session *Session) error
	GetByID(ctx context.Context, id uuid.UUID) (*Session, error)
	GetByIDHash(ctx context.Context, idHash string) (*Session, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*Session, error)
	UpdateLastActive(ctx context.Context, id uuid.UUID, lastActive time.Time) error
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByIDHash(ctx context.Context, idHash string) (int64, error)
	DeleteIfStale(ctx context.Context, id uuid.UUID, lastActive time.Time) (int64, error)
	DeleteIfStaleByIDHash(ctx context.Context, idHash string, lastActive time.Time) (int64, error)
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context, now time.Time, idleCutoff time.Time) (int64, error)
	DeleteExpiredByUserID(ctx context.Context, userID uuid.UUID, now time.Time, idleCutoff time.Time) error
}

// VerificationTokenStore defines storage operations for email verification tokens.
type VerificationTokenStore interface {
	Create(ctx context.Context, token *VerificationToken) error
	GetByTokenHash(ctx context.Context, tokenHash []byte) (*VerificationToken, error)
	Delete(ctx context.Context, tokenHash []byte) (int64, error)
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
}

// PasswordResetTokenStore defines storage operations for password reset tokens.
// Token creation and invalidation are serialized per-user inside transactional boundaries
// to guarantee atomic replacement of active reset tokens.
type PasswordResetTokenStore interface {
	Create(ctx context.Context, token *PasswordResetToken) error
	GetByTokenHash(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error)
	Delete(ctx context.Context, tokenHash []byte) (int64, error)
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	ConsumeToken(ctx context.Context, tokenHash []byte, now time.Time) (bool, error)
}

// OAuthAccountStore defines storage operations for external identity provider links.
type OAuthAccountStore interface {
	Create(ctx context.Context, account *OAuthAccount) error
	GetByProvider(ctx context.Context, providerID, providerUserID string) (*OAuthAccount, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*OAuthAccount, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
}

// TotpStore defines storage operations for RFC 6238 TOTP two-factor authentication.
type TotpStore interface {
	CreateSecret(ctx context.Context, secret *TotpSecret) error
	GetSecretByUserID(ctx context.Context, userID uuid.UUID) (*TotpSecret, error)
	GetSecretByUserIDForUpdate(ctx context.Context, userID uuid.UUID) (*TotpSecret, error)
	EnableSecret(ctx context.Context, secretID uuid.UUID, backupCodesJSON []byte) error
	UpdateBackupCodes(ctx context.Context, userID uuid.UUID, backupCodes []string) error
	UpdateBackupCodesJSON(ctx context.Context, secretID uuid.UUID, backupCodesJSON []byte) error
	UpdateBackupCodesCAS(ctx context.Context, userID uuid.UUID, expectedCodes []string, newCodes []string) (bool, error)
	DeleteSecret(ctx context.Context, userID uuid.UUID) error
	DeleteUnconfirmedSecret(ctx context.Context, userID uuid.UUID) error
	IsTotpEnabled(ctx context.Context, userID uuid.UUID) (bool, error)

	HasUsedCode(ctx context.Context, userID uuid.UUID, codeHash []byte, since time.Time) (bool, error)
	RecordUsedCode(ctx context.Context, usedCode *TotpUsedCode) error
	PruneUsedCodes(ctx context.Context, userID uuid.UUID, before time.Time) error

	CreateTwoFactorToken(ctx context.Context, token *TwoFactorToken) error
	GetTwoFactorToken(ctx context.Context, tokenHash []byte) (*TwoFactorToken, error)
	IncrementTwoFactorAttempts(ctx context.Context, tokenHash []byte, maxAttempts int, now time.Time) (int, error)
	ConsumeTwoFactorToken(ctx context.Context, tokenHash []byte, maxAttempts int, now time.Time) (bool, error)
	DeleteTwoFactorToken(ctx context.Context, id uuid.UUID) (int64, error)
	DeleteTwoFactorTokensByUserID(ctx context.Context, userID uuid.UUID) error
}

// Store is the composite storage abstraction interface.
type Store interface {
	Users() UserStore
	Sessions() SessionStore
	VerificationTokens() VerificationTokenStore
	PasswordResetTokens() PasswordResetTokenStore
	OAuthAccounts() OAuthAccountStore
	Totp() TotpStore

	Transaction(ctx context.Context, fn func(txStore Store) error) error
	Ping(ctx context.Context) error
	Close() error
}
