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

// keyringlessService builds a service over store with no token keyring: the
// shape an embedder gets when OAuth.TokenKEK is unset.
func keyringlessService(store db.Store, provider Provider) Service {
	cfg := serviceTestConfig()
	cfg.OAuth.TokenKEK = ""
	return NewServiceWithStore(store, nil, map[string]Provider{"google": provider}, cfg)
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

	t.Run("nil keyring reports KEK missing and never mutates", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		expiresAt := time.Now().UTC().Add(time.Hour)
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), &expiresAt)
		before := reloadTokenLink(t, database, link.ID)

		_, err := keyringlessService(svc.store, provider).LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeInvalidConfig, http.StatusInternalServerError)
		if !stderrors.Is(err, errors.ErrOAuthTokenKEKMissing) {
			t.Fatalf("err = %v; want ErrOAuthTokenKEKMissing", err)
		}
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
	})

	t.Run("nil keyring refuses an expired grant before the exchange", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		before := reloadTokenLink(t, database, link.ID)

		_, err := keyringlessService(svc.store, provider).LinkedAccountToken(ctx, owner.ID, "google")
		if !stderrors.Is(err, errors.ErrOAuthTokenKEKMissing) {
			t.Fatalf("err = %v; want ErrOAuthTokenKEKMissing", err)
		}
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
		if provider.calls() != 0 {
			t.Fatalf("refresh calls = %d; want 0", provider.calls())
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

func staleExpiry() *time.Time {
	expired := time.Now().UTC().Add(-time.Minute)
	return &expired
}

// rotateGrant swaps the stored grant the way a concurrent writer that won the
// CAS would. It fails unless the rotation wins, so a test can never mistake a
// missed rotation for convergence.
func rotateGrant(t *testing.T, svc *service, link db.OAuthAccount, grant *OAuthToken) {
	t.Helper()
	rec, err := svc.sealedTokens(link.ProviderID, link.ID.String(), grant)
	if err != nil {
		t.Fatalf("seal winner grant: %v", err)
	}
	won, err := svc.store.OAuthAccounts().SaveOAuthTokensCAS(context.Background(), link.ID, link.RefreshTokenFingerprint, rec)
	if err != nil || !won {
		t.Fatalf("rotate grant: won=%v err=%v", won, err)
	}
}

func requireClearedGrant(t *testing.T, link db.OAuthAccount) {
	t.Helper()
	if link.AccessTokenCiphertext != "" || link.RefreshTokenCiphertext != "" ||
		link.RefreshTokenFingerprint != "" || link.TokenScope != "" || link.TokenExpiresAt != nil {
		t.Fatalf("grant = %+v; want cleared", link)
	}
}

// readCountingOAuthStore signals every account read, so the concurrency test
// can tell that both callers finished their pre-read.
type readCountingOAuthStore struct {
	db.OAuthAccountStore
	mu     sync.Mutex
	reads  int
	onRead func(count int)
}

func (s *readCountingOAuthStore) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*db.OAuthAccount, error) {
	s.mu.Lock()
	s.reads++
	reads := s.reads
	s.mu.Unlock()
	if s.onRead != nil {
		s.onRead(reads)
	}
	return s.OAuthAccountStore.GetByUserID(ctx, userID)
}

func TestLinkedAccountToken_Refresh(t *testing.T) {
	ctx := context.Background()

	t.Run("expired grant refreshes and stores the rotated pair", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		var presented string
		provider.refreshFn = func(_ context.Context, refreshToken string) (*OAuthToken, error) {
			presented = refreshToken
			return &OAuthToken{
				AccessToken:  "rotated-access",
				RefreshToken: "rotated-refresh",
				TokenType:    "bearer",
				ExpiresIn:    7200,
				Raw:          map[string]any{"access_token": "rotated-access", "refresh_token": "rotated-refresh"},
			}, nil
		}

		before := time.Now().UTC()
		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v", err)
		}
		if presented != tokenTestRefresh {
			t.Fatalf("presented refresh token = %q; want %q", presented, tokenTestRefresh)
		}
		if token.AccessToken != "rotated-access" || token.ExpiresIn != 7200 {
			t.Fatalf("token = %+v; want the rotated access token", token)
		}
		// Providers answer token_type in their own casing (X sends "bearer");
		// the accessor reports one canonical scheme either way.
		if token.TokenType != tokenTypeBearer {
			t.Fatalf("TokenType = %q; want %q after a refresh", token.TokenType, tokenTypeBearer)
		}
		if token.ExpiresAt.Before(before.Add(7200*time.Second)) || token.ExpiresAt.After(time.Now().UTC().Add(7200*time.Second)) {
			t.Fatalf("ExpiresAt = %v; want now+7200s", token.ExpiresAt)
		}
		requireSanitized(t, token)

		stored := reloadTokenLink(t, database, link.ID)
		requireStoredGrant(t, stored, "rotated-access", "rotated-refresh")
		want, ferr := tokenTestSealer(t).RefreshTokenFingerprint("rotated-refresh")
		if ferr != nil {
			t.Fatalf("fingerprint: %v", ferr)
		}
		if stored.RefreshTokenFingerprint != want {
			t.Fatalf("fingerprint = %q; want %q", stored.RefreshTokenFingerprint, want)
		}
		if stored.AccessTokenCiphertext == link.AccessTokenCiphertext {
			t.Fatal("access ciphertext unchanged; the rotated token was not stored")
		}
		if provider.calls() != 1 {
			t.Fatalf("refresh calls = %d; want 1", provider.calls())
		}
	})

	t.Run("refresh response without a refresh token keeps the presented one", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return &OAuthToken{AccessToken: "rotated-access", ExpiresIn: 3600}, nil
		}

		if _, err := svc.LinkedAccountToken(ctx, owner.ID, "google"); err != nil {
			t.Fatalf("LinkedAccountToken = %v", err)
		}

		stored := reloadTokenLink(t, database, link.ID)
		requireStoredGrant(t, stored, "rotated-access", tokenTestRefresh)
		if stored.RefreshTokenFingerprint != link.RefreshTokenFingerprint {
			t.Fatalf("fingerprint = %q; want the presented token's %q", stored.RefreshTokenFingerprint, link.RefreshTokenFingerprint)
		}
	})

	t.Run("expiry inside the leeway refreshes", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		expiresAt := time.Now().UTC().Add(30 * time.Second)
		_, svc, _, owner := tokenAccessEnv(t, provider, tokenTestGrant(), &expiresAt)
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return &OAuthToken{AccessToken: "early-access", RefreshToken: "early-refresh", ExpiresIn: 3600}, nil
		}

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v", err)
		}
		if token.AccessToken != "early-access" {
			t.Fatalf("AccessToken = %q; want early-access", token.AccessToken)
		}
		if provider.calls() != 1 {
			t.Fatalf("refresh calls = %d; want 1", provider.calls())
		}
	})

	t.Run("expiry at the leeway boundary refreshes", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		expiresAt := time.Now().UTC().Add(tokenRefreshLeeway)
		_, svc, _, owner := tokenAccessEnv(t, provider, tokenTestGrant(), &expiresAt)
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return &OAuthToken{AccessToken: "boundary-access", RefreshToken: "boundary-refresh", ExpiresIn: 3600}, nil
		}

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v", err)
		}
		if token.AccessToken != "boundary-access" {
			t.Fatalf("AccessToken = %q; want boundary-access", token.AccessToken)
		}
	})

	t.Run("missing refresh token requires reauth", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, &OAuthToken{AccessToken: tokenTestAccess}, staleExpiry())
		before := reloadTokenLink(t, database, link.ID)

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthReauthRequired, http.StatusUnauthorized)
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
		if provider.calls() != 0 {
			t.Fatalf("refresh calls = %d; want 0", provider.calls())
		}
	})

	t.Run("provider without refresh capability is unsupported", func(t *testing.T) {
		provider := &stubProvider{id: "google"}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		before := reloadTokenLink(t, database, link.ID)

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthRefreshUnsupported, http.StatusNotImplemented)
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
	})

	t.Run("invalid_grant clears the grant", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return nil, errors.ErrOAuthGrantRejected
		}

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthReauthRequired, http.StatusUnauthorized)
		requireClearedGrant(t, reloadTokenLink(t, database, link.ID))
	})

	// A genuine two-goroutine race cannot be reproduced here: serviceTestDB
	// pins MaxOpenConns(1), and a single in-process service already serialises
	// its own refreshes through the singleflight. The CAS is therefore driven
	// deterministically instead: the service pre-reads a stale row, the row is
	// rotated behind its back, and the CAS must lose. Do not turn this into a
	// sleep or a goroutine race; the forced rotation is the point.
	t.Run("invalid_grant with a lost CAS serves the winner", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			rotateGrant(t, svc, link, &OAuthToken{AccessToken: "winner-access", RefreshToken: "winner-refresh", ExpiresIn: 3600})
			return nil, errors.ErrOAuthGrantRejected
		}

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v; want the winner's token", err)
		}
		if token.AccessToken != "winner-access" {
			t.Fatalf("AccessToken = %q; want winner-access", token.AccessToken)
		}
		requireSanitized(t, token)

		stored := reloadTokenLink(t, database, link.ID)
		requireStoredGrant(t, stored, "winner-access", "winner-refresh")
		want, ferr := tokenTestSealer(t).RefreshTokenFingerprint("winner-refresh")
		if ferr != nil {
			t.Fatalf("fingerprint: %v", ferr)
		}
		if stored.RefreshTokenFingerprint != want {
			t.Fatalf("fingerprint = %q; want the winner's %q", stored.RefreshTokenFingerprint, want)
		}
	})

	t.Run("refresh CAS loss serves the winner", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			rotateGrant(t, svc, link, &OAuthToken{AccessToken: "winner-access", RefreshToken: "winner-refresh", ExpiresIn: 3600})
			return &OAuthToken{AccessToken: "loser-access", RefreshToken: "loser-refresh", ExpiresIn: 3600}, nil
		}

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v", err)
		}
		if token.AccessToken != "winner-access" {
			t.Fatalf("AccessToken = %q; want winner-access", token.AccessToken)
		}
		requireSanitized(t, token)

		stored := reloadTokenLink(t, database, link.ID)
		requireStoredGrant(t, stored, "winner-access", "winner-refresh")
		if stored.RefreshTokenFingerprint == link.RefreshTokenFingerprint {
			t.Fatal("fingerprint unchanged; the loser's write landed")
		}
	})

	t.Run("transport failure keeps the grant and reports exchange failed", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		before := reloadTokenLink(t, database, link.ID)
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return nil, errors.New(errors.CodeOAuthProviderError, "oauth token request failed", stderrors.New("dial tcp: i/o timeout"))
		}

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthTokenExchangeFailed, http.StatusBadGateway)
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
	})

	t.Run("rate limit propagates retry-after", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		before := reloadTokenLink(t, database, link.ID)
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return nil, &RateLimitError{RetryAfter: 7, Err: errors.ErrOAuthRateLimitExceeded}
		}

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthRateLimitExceeded, http.StatusTooManyRequests)
		if retryAfter, ok := RetryAfterFromError(err); !ok || retryAfter != 7 {
			t.Fatalf("retry after = (%d, %v); want (7, true)", retryAfter, ok)
		}
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
	})

	t.Run("unknown kid on the refresh envelope never mutates", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		setTokenColumn(t, database, link.ID, "refresh_token_ciphertext", sealWith(t, otherTokenKEK, func(s *crypto.TokenSealer) (string, error) {
			return s.SealRefreshToken(link.ProviderID, link.ID.String(), tokenTestRefresh)
		}))
		before := reloadTokenLink(t, database, link.ID)

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthTokenDecryptionFailed, http.StatusInternalServerError)
		if !stderrors.Is(err, errors.ErrOAuthTokenKeyNotFound) {
			t.Fatalf("err = %v; want ErrOAuthTokenKeyNotFound", err)
		}
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
		if provider.calls() != 0 {
			t.Fatalf("refresh calls = %d; want 0", provider.calls())
		}
	})

	t.Run("malformed refresh envelope clears the grant", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		setTokenColumn(t, database, link.ID, "refresh_token_ciphertext", "{not-json")

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthReauthRequired, http.StatusUnauthorized)
		requireClearedGrant(t, reloadTokenLink(t, database, link.ID))
	})

	t.Run("oversize refreshed access token persists nothing", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		before := reloadTokenLink(t, database, link.ID)
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return &OAuthToken{AccessToken: strings.Repeat("z", 4097), RefreshToken: "rotated-refresh", ExpiresIn: 3600}, nil
		}

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeInternalError, http.StatusInternalServerError)
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
	})

	t.Run("concurrent callers share one refresh", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		_, svc, _, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())

		entries := make(chan struct{}, 4)
		release := make(chan struct{})
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			entries <- struct{}{}
			<-release
			return &OAuthToken{AccessToken: "shared-access", RefreshToken: "shared-refresh", ExpiresIn: 3600}, nil
		}
		secondRead := make(chan struct{})
		var readOnce sync.Once
		base := svc.store
		svc.store = &wrappedTxStore{Store: base, oauth: &readCountingOAuthStore{
			OAuthAccountStore: base.OAuthAccounts(),
			onRead: func(count int) {
				if count == 2 {
					readOnce.Do(func() { close(secondRead) })
				}
			},
		}}

		results := make([]*OAuthToken, 2)
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i], errs[i] = svc.LinkedAccountToken(context.Background(), owner.ID, "google")
			}(i)
		}
		<-entries
		<-secondRead
		// Duplicate suppression is only observable as the absence of a second
		// provider entry while the first is parked, so this watches a bounded
		// window: a call that failed to join the flight enters immediately.
		select {
		case <-entries:
			t.Fatal("second refresh started; the callers did not collapse onto one flight")
		case <-time.After(200 * time.Millisecond):
		}
		close(release)
		wg.Wait()

		for i := range results {
			if errs[i] != nil {
				t.Fatalf("caller %d = %v", i, errs[i])
			}
			if results[i] == nil || results[i].AccessToken != "shared-access" {
				t.Fatalf("caller %d token = %+v; want shared-access", i, results[i])
			}
			requireSanitized(t, results[i])
		}
		if results[0] == results[1] {
			t.Fatal("callers share one token value; want a copy per caller")
		}
		if provider.calls() != 1 {
			t.Fatalf("refresh calls = %d; want 1", provider.calls())
		}
	})
}
