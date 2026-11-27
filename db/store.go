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

// OAuthTokenRecord is the opaque token payload written by OAuthAccountStore.
// It carries sealed envelopes and the rotation fingerprint only: this package
// holds no plaintext token and performs no crypto, so a credential cannot be
// stored through this type. A nil TokenExpiresAt means "no expiry stored" and
// an all-empty record clears the tokens.
type OAuthTokenRecord struct {
	AccessTokenCiphertext   string
	RefreshTokenCiphertext  string
	RefreshTokenFingerprint string
	TokenScope              string
	TokenExpiresAt          *time.Time
}

// OAuthAccountStore defines storage operations for external identity provider links.
// Identities are keyed by (provider, tenant, provider user id): a pairwise
// subject is only unique within the tenant that issued it.
type OAuthAccountStore interface {
	Create(ctx context.Context, account *OAuthAccount) error
	GetByProvider(ctx context.Context, providerID, providerTenantID, providerUserID string) (*OAuthAccount, error)
	// GetByUserID returns every link the user holds, most recently updated
	// first. A user may hold more than one link for one provider, so callers
	// that resolve a single row take the first match for that provider.
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*OAuthAccount, error)
	UpdateProviderUserID(ctx context.Context, id uuid.UUID, providerUserID string) error
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error

	// SaveOAuthTokens overwrites every token field on the account. It reports
	// the backend not-found error when no account holds id.
	SaveOAuthTokens(ctx context.Context, id uuid.UUID, rec OAuthTokenRecord) error
	// SaveOAuthTokensCAS writes the record only when the stored refresh-token
	// fingerprint equals expectedFingerprint, reporting whether it won. A miss
	// is (false, nil): another writer rotated first and the caller re-reads. An
	// empty expectation never matches, so a tokenless account cannot be
	// overwritten by a refresh that has no stored fingerprint to prove.
	SaveOAuthTokensCAS(ctx context.Context, id uuid.UUID, expectedFingerprint string, rec OAuthTokenRecord) (bool, error)
	// SaveOAuthTokensIfUnset writes the record only while the account holds no
	// refresh token, reporting whether it won. It is the guarded write for a
	// first grant: a row that already stored one is never overwritten.
	SaveOAuthTokensIfUnset(ctx context.Context, id uuid.UUID, rec OAuthTokenRecord) (bool, error)
	// SaveOAuthAccess writes only the access fields (ciphertext, expiry, scope)
	// and leaves the refresh columns untouched, so a grant that carries no
	// refresh token cannot erase one another writer stored. It reports the
	// backend not-found error when no account holds id.
	SaveOAuthAccess(ctx context.Context, id uuid.UUID, rec OAuthTokenRecord) error
	// ClearOAuthRefresh empties only the refresh columns (ciphertext,
	// fingerprint) when the stored fingerprint equals expectedFingerprint, and
	// never writes the access, scope, or expiry columns, so a discard cannot
	// restore an envelope another writer already replaced. A miss is
	// (false, nil): another writer owns the grant. An empty expectation never
	// matches.
	ClearOAuthRefresh(ctx context.Context, id uuid.UUID, expectedFingerprint string) (bool, error)
	// SaveOAuthRefreshIfUnset writes the record's refresh columns only while the
	// account holds no refresh token, and its access columns only while the
	// account holds no access token, so a concurrent access-only winner keeps
	// its envelope. A miss is (false, nil): a refresh grant is already stored.
	// An empty rec fingerprint never matches the guard and is never written. A
	// backend that cannot apply both groups in one statement reports an error
	// after the refresh pair landed as (true, error): the pair stands, and the
	// caller retries or serves the stored grant.
	SaveOAuthRefreshIfUnset(ctx context.Context, id uuid.UUID, rec OAuthTokenRecord) (bool, error)
	// SaveOAuthAccessCAS writes only the access fields when the stored access
	// ciphertext equals expectedCiphertext, so an older grant cannot replace a
	// newer access envelope. An empty expectation asserts only that the access
	// column is still empty, which is a value it can prove. A miss is
	// (false, nil).
	SaveOAuthAccessCAS(ctx context.Context, id uuid.UUID, expectedCiphertext string, rec OAuthTokenRecord) (bool, error)
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
