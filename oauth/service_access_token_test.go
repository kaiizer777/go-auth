package oauth

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
)

// otherTokenKEK seals under a kid the service keyring does not hold: the shape a
// row takes when a key is removed before its envelopes expire.
const otherTokenKEK = "old-kid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// stubRefreshProvider is a Provider that can also renew grants, with a scripted
// result and a call counter.
type stubRefreshProvider struct {
	*stubProvider
	mu           sync.Mutex
	refreshCalls int
	refreshFn    func(ctx context.Context, refreshToken string) (*OAuthToken, error)
}

func (p *stubRefreshProvider) RefreshToken(ctx context.Context, refreshToken string) (*OAuthToken, error) {
	p.mu.Lock()
	p.refreshCalls++
	fn := p.refreshFn
	p.mu.Unlock()
	if fn != nil {
		return fn(ctx, refreshToken)
	}
	return nil, errors.ErrOAuthTokenExchangeFailed
}

func (p *stubRefreshProvider) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshCalls
}

// tokenAccessEnv seeds one linked account carrying grant and returns the
// database, a service wired to provider, and the row and its owner. The row is
// written directly: these tests cover the accessor, not the login path.
func tokenAccessEnv(t *testing.T, provider Provider, grant *OAuthToken, expiresAt *time.Time) (*gorm.DB, *service, db.OAuthAccount, db.User) {
	t.Helper()
	database := serviceTestDB(t)
	svc := NewService(database, nil, map[string]Provider{"google": provider}, serviceTestConfig()).(*service)
	owner := db.User{ID: uuid.New(), Email: "access-owner@example.com", PasswordHash: "hash", EmailVerified: true}
	if err := database.Create(&owner).Error; err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	link := db.OAuthAccount{
		ID:             uuid.New(),
		UserID:         owner.ID,
		ProviderID:     "google",
		ProviderUserID: "sub-token",
		Email:          owner.Email,
		Verified:       true,
	}
	rec, err := svc.sealedTokens(link.ProviderID, link.ID.String(), grant)
	if err != nil {
		t.Fatalf("seal grant: %v", err)
	}
	rec.TokenExpiresAt = expiresAt
	applyTokenRecord(&link, rec)
	if err := database.Create(&link).Error; err != nil {
		t.Fatalf("seed link: %v", err)
	}
	return database, svc, link, owner
}

func reloadTokenLink(t *testing.T, database *gorm.DB, id uuid.UUID) db.OAuthAccount {
	t.Helper()
	var link db.OAuthAccount
	if err := database.Where("id = ?", id.String()).First(&link).Error; err != nil {
		t.Fatalf("reload link: %v", err)
	}
	return link
}

func setTokenColumn(t *testing.T, database *gorm.DB, id uuid.UUID, column, value string) {
	t.Helper()
	if err := database.Model(&db.OAuthAccount{}).Where("id = ?", id.String()).Update(column, value).Error; err != nil {
		t.Fatalf("set %s: %v", column, err)
	}
}

func sealWith(t *testing.T, keySpec string, seal func(*crypto.TokenSealer) (string, error)) string {
	t.Helper()
	ring, err := crypto.ParseKeyring(keySpec)
	if err != nil {
		t.Fatalf("parse keyring: %v", err)
	}
	envelope, err := seal(crypto.NewTokenSealer(ring))
	if err != nil {
		t.Fatalf("seal envelope: %v", err)
	}
	return envelope
}

// tamperCiphertext re-encodes an envelope's body under a well-formed tag-shaped
// value: it parses, then fails authentication.
func tamperCiphertext(t *testing.T, envelope string) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(envelope), &doc); err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	doc["ct"] = strings.Repeat("A", 44)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return string(out)
}

// requireSanitized asserts the accessor withheld every provider credential it
// is not allowed to return. Raw is the whole provider body, refresh token
// included, so a non-nil map is a credential leak.
func requireSanitized(t *testing.T, token *OAuthToken) {
	t.Helper()
	if token == nil {
		t.Fatal("token = nil")
	}
	if token.RefreshToken != "" {
		t.Fatalf("RefreshToken = %q; want empty", token.RefreshToken)
	}
	if token.IDToken != "" {
		t.Fatalf("IDToken = %q; want empty", token.IDToken)
	}
	if token.Raw != nil {
		t.Fatalf("Raw = %v; want nil", token.Raw)
	}
}

func requireSameGrant(t *testing.T, before, after db.OAuthAccount) {
	t.Helper()
	if before.AccessTokenCiphertext != after.AccessTokenCiphertext ||
		before.RefreshTokenCiphertext != after.RefreshTokenCiphertext ||
		before.RefreshTokenFingerprint != after.RefreshTokenFingerprint ||
		before.TokenScope != after.TokenScope ||
		!sameExpiry(before.TokenExpiresAt, after.TokenExpiresAt) {
		t.Fatal("stored grant changed; want it untouched")
	}
}

func sameExpiry(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func TestLinkedAccountToken_ReadPath(t *testing.T) {
	ctx := context.Background()

	t.Run("fresh token is returned without a refresh", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		expiresAt := time.Now().UTC().Add(time.Hour)
		_, svc, _, owner := tokenAccessEnv(t, provider, tokenTestGrant(), &expiresAt)

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v", err)
		}
		if token.AccessToken != tokenTestAccess {
			t.Fatalf("AccessToken = %q; want %q", token.AccessToken, tokenTestAccess)
		}
		if token.TokenType != tokenTypeBearer {
			t.Fatalf("TokenType = %q; want %q", token.TokenType, tokenTypeBearer)
		}
		if !token.ExpiresAt.Equal(expiresAt) {
			t.Fatalf("ExpiresAt = %v; want %v", token.ExpiresAt, expiresAt)
		}
		if token.ExpiresIn < 3500 || token.ExpiresIn > 3600 {
			t.Fatalf("ExpiresIn = %d; want the remaining lifetime", token.ExpiresIn)
		}
		requireSanitized(t, token)
		if provider.calls() != 0 {
			t.Fatalf("refresh calls = %d; want 0 for a fresh token", provider.calls())
		}
	})

	t.Run("nil expiry counts as fresh", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		_, svc, _, owner := tokenAccessEnv(t, provider, tokenTestGrant(), nil)

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v", err)
		}
		if token.AccessToken != tokenTestAccess {
			t.Fatalf("AccessToken = %q; want %q", token.AccessToken, tokenTestAccess)
		}
		if !token.ExpiresAt.IsZero() || token.ExpiresIn != 0 {
			t.Fatalf("expiry = (%v, %d); want unknown", token.ExpiresAt, token.ExpiresIn)
		}
		requireSanitized(t, token)
		if provider.calls() != 0 {
			t.Fatalf("refresh calls = %d; want 0", provider.calls())
		}
	})

	t.Run("empty access envelope returns no token", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		_, svc, _, owner := tokenAccessEnv(t, provider, nil, nil)

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v", err)
		}
		if token == nil || token.AccessToken != "" {
			t.Fatalf("token = %+v; want an empty token", token)
		}
		requireSanitized(t, token)
		if provider.calls() != 0 {
			t.Fatalf("refresh calls = %d; want 0", provider.calls())
		}
	})

	t.Run("unlinked provider is not linked", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		_, svc, _, owner := tokenAccessEnv(t, provider, tokenTestGrant(), nil)

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "github")
		requireCode(t, err, errors.CodeOAuthAccountNotLinked, http.StatusNotFound)
	})

	t.Run("another user's link is not visible", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, _, _ := tokenAccessEnv(t, provider, tokenTestGrant(), nil)
		other := db.User{ID: uuid.New(), Email: "other-owner@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&other).Error; err != nil {
			t.Fatalf("seed other user: %v", err)
		}

		if _, err := svc.LinkedAccountToken(ctx, other.ID, "google"); !stderrors.Is(err, errors.ErrOAuthAccountNotLinked) {
			t.Fatalf("err = %v; want ErrOAuthAccountNotLinked", err)
		}
	})

	t.Run("provider id is canonicalized", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		_, svc, _, owner := tokenAccessEnv(t, provider, tokenTestGrant(), nil)

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "  GOOGLE ")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v", err)
		}
		if token.AccessToken != tokenTestAccess {
			t.Fatalf("AccessToken = %q; want %q", token.AccessToken, tokenTestAccess)
		}
	})

	t.Run("unknown kid returns key not found and never mutates", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		expiresAt := time.Now().UTC().Add(time.Hour)
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), &expiresAt)
		setTokenColumn(t, database, link.ID, "access_token_ciphertext", sealWith(t, otherTokenKEK, func(s *crypto.TokenSealer) (string, error) {
			return s.SealAccessToken(link.ProviderID, link.ID.String(), tokenTestAccess)
		}))
		before := reloadTokenLink(t, database, link.ID)

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthTokenDecryptionFailed, http.StatusInternalServerError)
		if !stderrors.Is(err, errors.ErrOAuthTokenKeyNotFound) {
			t.Fatalf("err = %v; want ErrOAuthTokenKeyNotFound", err)
		}
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
	})

	t.Run("tampered tag returns corrupt and never mutates", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		expiresAt := time.Now().UTC().Add(time.Hour)
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), &expiresAt)
		setTokenColumn(t, database, link.ID, "access_token_ciphertext", tamperCiphertext(t, link.AccessTokenCiphertext))
		before := reloadTokenLink(t, database, link.ID)

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthTokenDecryptionFailed, http.StatusInternalServerError)
		if !stderrors.Is(err, errors.ErrOAuthTokenCorrupt) {
			t.Fatalf("err = %v; want ErrOAuthTokenCorrupt", err)
		}
		if strings.Contains(err.Error(), tokenTestAccess) {
			t.Fatalf("error text = %q; want no token", err.Error())
		}
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
	})

	t.Run("malformed envelope clears the grant", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		expiresAt := time.Now().UTC().Add(time.Hour)
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), &expiresAt)
		setTokenColumn(t, database, link.ID, "access_token_ciphertext", "{not-json")

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthReauthRequired, http.StatusUnauthorized)

		cleared := reloadTokenLink(t, database, link.ID)
		if cleared.AccessTokenCiphertext != "" || cleared.RefreshTokenCiphertext != "" ||
			cleared.RefreshTokenFingerprint != "" || cleared.TokenScope != "" || cleared.TokenExpiresAt != nil {
			t.Fatalf("grant = %+v; want cleared", cleared)
		}
	})

	t.Run("malformed envelope without a fingerprint is not cleared", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		expiresAt := time.Now().UTC().Add(time.Hour)
		database, svc, link, owner := tokenAccessEnv(t, provider, &OAuthToken{AccessToken: tokenTestAccess}, &expiresAt)
		setTokenColumn(t, database, link.ID, "access_token_ciphertext", "{not-json")
		before := reloadTokenLink(t, database, link.ID)

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthReauthRequired, http.StatusUnauthorized)
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
	})
}
