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

	t.Run("most recently updated link wins", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		expiresAt := time.Now().UTC().Add(time.Hour)
		database, svc, older, owner := tokenAccessEnv(t, provider,
			&OAuthToken{AccessToken: "older-access", RefreshToken: "older-refresh", ExpiresIn: 3600}, &expiresAt)
		older = reloadTokenLink(t, database, older.ID)

		// Written second, so an unordered read (insertion order) would serve the
		// older grant first.
		newer := older
		newer.ID = uuid.New()
		newer.ProviderUserID = "sub-token-newer"
		rec, err := svc.sealedTokens(newer.ProviderID, newer.ID.String(),
			&OAuthToken{AccessToken: "newer-access", RefreshToken: "newer-refresh", ExpiresIn: 3600})
		if err != nil {
			t.Fatalf("seal newer grant: %v", err)
		}
		rec.TokenExpiresAt = &expiresAt
		applyTokenRecord(&newer, rec)
		newer.UpdatedAt = older.UpdatedAt.Add(time.Hour)
		if err := database.Create(&newer).Error; err != nil {
			t.Fatalf("seed newer link: %v", err)
		}

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v", err)
		}
		if token.AccessToken != "newer-access" {
			t.Fatalf("AccessToken = %q; want the most recently updated link's", token.AccessToken)
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

	t.Run("malformed access envelope renews from the stored refresh grant", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		expiresAt := time.Now().UTC().Add(time.Hour)
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), &expiresAt)
		setTokenColumn(t, database, link.ID, "access_token_ciphertext", "{not-json")
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return &OAuthToken{AccessToken: "recovered-access", RefreshToken: "recovered-refresh", ExpiresIn: 3600}, nil
		}

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v; want a renewed token", err)
		}
		if token.AccessToken != "recovered-access" {
			t.Fatalf("AccessToken = %q; want recovered-access", token.AccessToken)
		}
		requireSanitized(t, token)
		requireStoredGrant(t, reloadTokenLink(t, database, link.ID), "recovered-access", "recovered-refresh")
	})

	t.Run("malformed access envelope survives a failed renewal", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		expiresAt := time.Now().UTC().Add(time.Hour)
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), &expiresAt)
		setTokenColumn(t, database, link.ID, "access_token_ciphertext", "{not-json")
		before := reloadTokenLink(t, database, link.ID)
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return nil, errors.New(errors.CodeOAuthProviderError, "oauth token request failed", stderrors.New("dial tcp: i/o timeout"))
		}

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthTokenExchangeFailed, http.StatusBadGateway)
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
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
	if err := rotateGrantFromCallback(svc, link, grant); err != nil {
		t.Fatalf("rotate grant: %v", err)
	}
}

// rotateGrantFromCallback is rotateGrant for a provider callback, which runs on
// the shared flight goroutine: it reports the failure to the caller instead of
// calling t.Fatalf off the test goroutine.
func rotateGrantFromCallback(svc *service, link db.OAuthAccount, grant *OAuthToken) error {
	rec, err := svc.sealedTokens(link.ProviderID, link.ID.String(), grant)
	if err != nil {
		return err
	}
	won, err := svc.store.OAuthAccounts().SaveOAuthTokensCAS(context.Background(), link.ID, link.RefreshTokenFingerprint, rec)
	if err != nil {
		return err
	}
	if !won {
		return stderrors.New("rotation lost the CAS")
	}
	return nil
}

// clearGrant wipes the stored grant the way a concurrent invalid_grant does.
func clearGrant(svc *service, link db.OAuthAccount) error {
	won, err := svc.store.OAuthAccounts().SaveOAuthTokensCAS(context.Background(), link.ID, link.RefreshTokenFingerprint, db.OAuthTokenRecord{})
	if err != nil {
		return err
	}
	if !won {
		return stderrors.New("clear lost the CAS")
	}
	return nil
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

// interceptReadOAuthStore runs onRead after a successful identity lookup, so a
// test can land a competing write between a caller's reread and its write.
type interceptReadOAuthStore struct {
	db.OAuthAccountStore
	onRead func(ctx context.Context, row db.OAuthAccount)
}

func (s *interceptReadOAuthStore) GetByProvider(ctx context.Context, providerID, providerTenantID, providerUserID string) (*db.OAuthAccount, error) {
	row, err := s.OAuthAccountStore.GetByProvider(ctx, providerID, providerTenantID, providerUserID)
	if err == nil && row != nil && s.onRead != nil {
		s.onRead(ctx, *row)
	}
	return row, err
}

// failingWriteOAuthStore faults the next guarded token writes of each kind: the
// shape of a transient store fault on the rotation path.
type failingWriteOAuthStore struct {
	db.OAuthAccountStore
	mu              sync.Mutex
	casFailures     int
	ifUnsetFailures int
}

func (s *failingWriteOAuthStore) SaveOAuthTokensCAS(ctx context.Context, id uuid.UUID, expectedFingerprint string, rec db.OAuthTokenRecord) (bool, error) {
	if s.fail(&s.casFailures) {
		return false, stderrors.New("simulated write failure")
	}
	return s.OAuthAccountStore.SaveOAuthTokensCAS(ctx, id, expectedFingerprint, rec)
}

func (s *failingWriteOAuthStore) SaveOAuthTokensIfUnset(ctx context.Context, id uuid.UUID, rec db.OAuthTokenRecord) (bool, error) {
	if s.fail(&s.ifUnsetFailures) {
		return false, stderrors.New("simulated write failure")
	}
	return s.OAuthAccountStore.SaveOAuthTokensIfUnset(ctx, id, rec)
}

// fail consumes one armed fault. Callers hold no lock: the mutex guards both the
// counters and the decrement.
func (s *failingWriteOAuthStore) fail(armed *int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if *armed == 0 {
		return false
	}
	*armed--
	return true
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
		// The refresh grant carries no scope: RFC 6749 §6 keeps the stored one.
		if stored.TokenScope != tokenTestScope {
			t.Fatalf("token scope = %q; want the unchanged grant scope %q", stored.TokenScope, tokenTestScope)
		}
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

	// A provider that answers an absurd expires_in must not hand the caller a
	// credential it caches past any real expiry.
	t.Run("reported lifetime is capped at 24h", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		const providerLifetime = 10 * 365 * 24 * 60 * 60
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return &OAuthToken{AccessToken: "long-access", RefreshToken: "long-refresh", ExpiresIn: providerLifetime}, nil
		}
		wantLifetime := int(maxRefreshedLifetime / time.Second)

		before := time.Now().UTC()
		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v", err)
		}
		if token.ExpiresIn != wantLifetime {
			t.Fatalf("ExpiresIn = %d; want %d", token.ExpiresIn, wantLifetime)
		}
		if token.ExpiresAt.Before(before.Add(maxRefreshedLifetime)) ||
			token.ExpiresAt.After(time.Now().UTC().Add(maxRefreshedLifetime)) {
			t.Fatalf("ExpiresAt = %v; want now+%v", token.ExpiresAt, maxRefreshedLifetime)
		}

		// The stored expiry keeps the provider's value: it schedules the next
		// renewal, so the cap must never reach the column.
		stored := reloadTokenLink(t, database, link.ID)
		if stored.TokenExpiresAt == nil {
			t.Fatal("stored expiry = nil; want the provider's value")
		}
		if got := stored.TokenExpiresAt.Sub(before); got < time.Duration(providerLifetime)*time.Second-time.Second ||
			got > time.Duration(providerLifetime)*time.Second+5*time.Second {
			t.Fatalf("stored lifetime = %v; want the provider's %ds", got, providerLifetime)
		}

		// The next read projects the uncapped stored expiry again, so the cap has
		// to be applied to the read path as well, not only to the rotation.
		again, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("second LinkedAccountToken = %v", err)
		}
		if again.AccessToken != "long-access" || again.ExpiresIn != wantLifetime {
			t.Fatalf("second token = %+v; want the same access token capped at %ds", again, wantLifetime)
		}
		if again.ExpiresAt.After(time.Now().UTC().Add(maxRefreshedLifetime)) {
			t.Fatalf("second ExpiresAt = %v; want it capped at now+%v", again.ExpiresAt, maxRefreshedLifetime)
		}
		if provider.calls() != 1 {
			t.Fatalf("refresh calls = %d; want 1", provider.calls())
		}
	})

	t.Run("reported lifetime below the cap is exact", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		_, svc, _, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return &OAuthToken{AccessToken: "short-access", RefreshToken: "short-refresh", ExpiresIn: 900}, nil
		}

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v", err)
		}
		if token.ExpiresIn != 900 {
			t.Fatalf("ExpiresIn = %d; want 900", token.ExpiresIn)
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
			if err := rotateGrantFromCallback(svc, link, &OAuthToken{AccessToken: "winner-access", RefreshToken: "winner-refresh", ExpiresIn: 3600}); err != nil {
				return nil, err
			}
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
			if err := rotateGrantFromCallback(svc, link, &OAuthToken{AccessToken: "winner-access", RefreshToken: "winner-refresh", ExpiresIn: 3600}); err != nil {
				return nil, err
			}
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

	// A clear that wins the CAS before the rotated pair is persisted empties the
	// row: the pair in hand is then the only grant left and must not be dropped.
	t.Run("a clear that wins before the persist keeps the rotated pair", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			if err := clearGrant(svc, link); err != nil {
				return nil, err
			}
			return &OAuthToken{AccessToken: "rotated-access", RefreshToken: "rotated-refresh", ExpiresIn: 3600}, nil
		}

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v; want the rotated pair", err)
		}
		if token.AccessToken != "rotated-access" {
			t.Fatalf("AccessToken = %q; want rotated-access", token.AccessToken)
		}
		requireSanitized(t, token)

		stored := reloadTokenLink(t, database, link.ID)
		requireStoredGrant(t, stored, "rotated-access", "rotated-refresh")
		want, ferr := tokenTestSealer(t).RefreshTokenFingerprint("rotated-refresh")
		if ferr != nil {
			t.Fatalf("fingerprint: %v", ferr)
		}
		if stored.RefreshTokenFingerprint != want {
			t.Fatalf("fingerprint = %q; want the rotated %q", stored.RefreshTokenFingerprint, want)
		}
	})

	// The clear that emptied the row does not reserve it: a callback can fill it
	// between the reread and the write. That grant is the newer one, so the
	// rotated pair must not replace it.
	t.Run("a grant stored after the reread is served instead of overwritten", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		var landed sync.Once
		base := svc.store
		svc.store = &wrappedTxStore{Store: base, oauth: &interceptReadOAuthStore{
			OAuthAccountStore: base.OAuthAccounts(),
			onRead: func(readCtx context.Context, row db.OAuthAccount) {
				if row.AccessTokenCiphertext != "" || row.RefreshTokenFingerprint != "" {
					return
				}
				landed.Do(func() {
					competitor, serr := svc.sealedTokens(link.ProviderID, link.ID.String(),
						&OAuthToken{AccessToken: "callback-access", RefreshToken: "callback-refresh", ExpiresIn: 3600})
					if serr != nil {
						t.Errorf("seal callback grant: %v", serr)
						return
					}
					if werr := base.OAuthAccounts().SaveOAuthTokens(readCtx, link.ID, competitor); werr != nil {
						t.Errorf("store callback grant: %v", werr)
					}
				})
			},
		}}
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			if err := clearGrant(svc, link); err != nil {
				return nil, err
			}
			return &OAuthToken{AccessToken: "rotated-access", RefreshToken: "rotated-refresh", ExpiresIn: 3600}, nil
		}

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v; want the callback grant", err)
		}
		if token.AccessToken != "callback-access" {
			t.Fatalf("AccessToken = %q; want callback-access", token.AccessToken)
		}
		requireSanitized(t, token)
		requireStoredGrant(t, reloadTokenLink(t, database, link.ID), "callback-access", "callback-refresh")
	})

	// The provider has already spent the presented refresh token when the write
	// runs, so a single store fault must not throw the rotated pair away.
	t.Run("a transient persist failure retries the rotated grant", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		base := svc.store
		svc.store = &wrappedTxStore{Store: base, oauth: &failingWriteOAuthStore{
			OAuthAccountStore: base.OAuthAccounts(),
			casFailures:       1,
		}}
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return &OAuthToken{AccessToken: "rotated-access", RefreshToken: "rotated-refresh", ExpiresIn: 3600}, nil
		}

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v; want the retried persist", err)
		}
		if token.AccessToken != "rotated-access" {
			t.Fatalf("AccessToken = %q; want rotated-access", token.AccessToken)
		}
		requireStoredGrant(t, reloadTokenLink(t, database, link.ID), "rotated-access", "rotated-refresh")
		// The retry repeats only the store write: the spent refresh token is
		// never presented to the provider again.
		if provider.calls() != 1 {
			t.Fatalf("refresh calls = %d; want 1", provider.calls())
		}
	})

	// A clear that won the CAS emptied the row before the pair was persisted, so
	// the recovered pair is the only grant left and needs the same retry.
	t.Run("a transient failure storing past a clear retries the rotated grant", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		base := svc.store
		svc.store = &wrappedTxStore{Store: base, oauth: &failingWriteOAuthStore{
			OAuthAccountStore: base.OAuthAccounts(),
			ifUnsetFailures:   1,
		}}
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			if err := clearGrant(svc, link); err != nil {
				return nil, err
			}
			return &OAuthToken{AccessToken: "rotated-access", RefreshToken: "rotated-refresh", ExpiresIn: 3600}, nil
		}

		token, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		if err != nil {
			t.Fatalf("LinkedAccountToken = %v; want the retried persist", err)
		}
		if token.AccessToken != "rotated-access" {
			t.Fatalf("AccessToken = %q; want rotated-access", token.AccessToken)
		}
		requireStoredGrant(t, reloadTokenLink(t, database, link.ID), "rotated-access", "rotated-refresh")
		if provider.calls() != 1 {
			t.Fatalf("refresh calls = %d; want 1", provider.calls())
		}
	})

	// A write that keeps failing must not be "repaired" by clearing the grant:
	// the previous value stands and the error surfaces.
	t.Run("a persist that keeps failing keeps the previous grant", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		base := svc.store
		svc.store = &wrappedTxStore{Store: base, oauth: &failingWriteOAuthStore{
			OAuthAccountStore: base.OAuthAccounts(),
			casFailures:       persistAttempts + 1,
		}}
		before := reloadTokenLink(t, database, link.ID)
		provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
			return &OAuthToken{AccessToken: "rotated-access", RefreshToken: "rotated-refresh", ExpiresIn: 3600}, nil
		}

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthTokenExchangeFailed, http.StatusBadGateway)
		requireSameGrant(t, before, reloadTokenLink(t, database, link.ID))
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

	t.Run("malformed refresh envelope keeps the access envelope", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, owner := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		setTokenColumn(t, database, link.ID, "refresh_token_ciphertext", "{not-json")
		before := reloadTokenLink(t, database, link.ID)

		_, err := svc.LinkedAccountToken(ctx, owner.ID, "google")
		requireCode(t, err, errors.CodeOAuthReauthRequired, http.StatusUnauthorized)
		stored := reloadTokenLink(t, database, link.ID)
		if stored.AccessTokenCiphertext != before.AccessTokenCiphertext ||
			stored.TokenScope != before.TokenScope ||
			!sameExpiry(stored.TokenExpiresAt, before.TokenExpiresAt) {
			t.Fatal("malformed refresh envelope destroyed the access envelope")
		}
		if stored.RefreshTokenCiphertext != "" || stored.RefreshTokenFingerprint != "" {
			t.Fatalf("refresh columns = (%q, %q); want cleared", stored.RefreshTokenCiphertext, stored.RefreshTokenFingerprint)
		}
		if provider.calls() != 0 {
			t.Fatalf("refresh calls = %d; want 0", provider.calls())
		}
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

// TestRefreshFlightCallerDeadline pins the flight's contract with its waiters: a
// joiner waits under its own context, so an expired caller returns immediately
// and cannot abandon the shared exchange other callers are depending on.
func TestRefreshFlightCallerDeadline(t *testing.T) {
	provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
	_, svc, link, _ := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	provider.refreshFn = func(context.Context, string) (*OAuthToken, error) {
		once.Do(func() { close(entered) })
		<-release
		return &OAuthToken{AccessToken: "shared-access", RefreshToken: "shared-refresh", ExpiresIn: 3600}, nil
	}

	type outcome struct {
		token *OAuthToken
		err   error
	}
	leader := make(chan outcome, 1)
	go func() {
		token, err := svc.refreshAccessToken(context.Background(), link)
		leader <- outcome{token: token, err: err}
	}()
	<-entered

	expired, cancel := context.WithCancel(context.Background())
	cancel()
	joined := make(chan error, 1)
	go func() {
		_, err := svc.refreshAccessToken(expired, link)
		joined <- err
	}()
	select {
	case err := <-joined:
		if !stderrors.Is(err, context.Canceled) {
			t.Fatalf("joiner err = %v; want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("joiner waited for the shared exchange instead of its own context")
	}

	close(release)
	got := <-leader
	if got.err != nil {
		t.Fatalf("leader = %v; want the shared token", got.err)
	}
	if got.token == nil || got.token.AccessToken != "shared-access" {
		t.Fatalf("leader token = %+v; want the shared exchange result", got.token)
	}
	if provider.calls() != 1 {
		t.Fatalf("refresh calls = %d; want one shared exchange", provider.calls())
	}
}

// TestRefreshFlightOutlivesLeaderCancellation pins the flight's detachment from
// the caller that started it: the shared exchange runs under
// context.WithoutCancel, so a leader that abandons its wait cannot cancel the
// rotation its joiners are waiting on.
func TestRefreshFlightOutlivesLeaderCancellation(t *testing.T) {
	provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
	_, svc, link, _ := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())

	entries := make(chan struct{}, 2)
	release := make(chan struct{})
	provider.refreshFn = func(ctx context.Context, _ string) (*OAuthToken, error) {
		entries <- struct{}{}
		<-release
		// A provider call that outlives its caller must still run on a live
		// context; a real HTTP exchange would abort here.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return &OAuthToken{AccessToken: "shared-access", RefreshToken: "shared-refresh", ExpiresIn: 3600}, nil
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leader := make(chan error, 1)
	go func() {
		_, err := svc.refreshAccessToken(leaderCtx, link)
		leader <- err
	}()
	<-entries

	type outcome struct {
		token *OAuthToken
		err   error
	}
	joined := make(chan outcome, 1)
	go func() {
		token, err := svc.refreshAccessToken(context.Background(), link)
		joined <- outcome{token: token, err: err}
	}()
	// singleflight exposes no join signal, so a caller that failed to join is
	// observed as the second provider entry its own exchange would produce.
	select {
	case <-entries:
		close(release)
		t.Fatal("joiner started its own exchange instead of joining the flight")
	case <-time.After(200 * time.Millisecond):
	}

	cancelLeader()
	select {
	case err := <-leader:
		if !stderrors.Is(err, context.Canceled) {
			t.Fatalf("leader err = %v; want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("leader outlived its own cancelled context")
	}

	close(release)
	select {
	case got := <-joined:
		if got.err != nil {
			t.Fatalf("joiner = %v; want the shared token", got.err)
		}
		if got.token == nil || got.token.AccessToken != "shared-access" {
			t.Fatalf("joiner token = %+v; want the shared exchange result", got.token)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("joiner never received the shared result")
	}
	if provider.calls() != 1 {
		t.Fatalf("refresh calls = %d; want one shared exchange", provider.calls())
	}
}

// TestConvergeRejectsForeignGrant pins the owner check on convergence: a lost
// CAS must never serve a row that is not the caller's own link, because a delete
// plus relink can move the provider identity to another row or another user.
func TestConvergeRejectsForeignGrant(t *testing.T) {
	ctx := context.Background()

	t.Run("identity relinked to another user", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, _ := tokenAccessEnv(t, provider, tokenTestGrant(), nil)
		other := db.User{ID: uuid.New(), Email: "other-owner@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&other).Error; err != nil {
			t.Fatalf("seed other user: %v", err)
		}
		rotateGrant(t, svc, link, &OAuthToken{AccessToken: "other-user-access", RefreshToken: "other-refresh", ExpiresIn: 3600})
		if err := database.Model(&db.OAuthAccount{}).Where("id = ?", link.ID.String()).Update("user_id", other.ID.String()).Error; err != nil {
			t.Fatalf("move link owner: %v", err)
		}

		token, err := svc.converge(ctx, link)
		if token != nil {
			t.Fatalf("converge served %+v; want no token for a foreign owner", token)
		}
		requireCode(t, err, errors.CodeOAuthReauthRequired, http.StatusUnauthorized)
	})

	t.Run("identity moved to another row", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, _ := tokenAccessEnv(t, provider, tokenTestGrant(), nil)
		if err := database.Delete(&db.OAuthAccount{}, "id = ?", link.ID.String()).Error; err != nil {
			t.Fatalf("delete stale link: %v", err)
		}
		replacement := db.OAuthAccount{
			ID:               uuid.New(),
			UserID:           link.UserID,
			ProviderID:       link.ProviderID,
			ProviderTenantID: link.ProviderTenantID,
			ProviderUserID:   link.ProviderUserID,
			Email:            link.Email,
			Verified:         true,
		}
		rec, err := svc.sealedTokens(replacement.ProviderID, replacement.ID.String(),
			&OAuthToken{AccessToken: "replacement-access", RefreshToken: "replacement-refresh", ExpiresIn: 3600})
		if err != nil {
			t.Fatalf("seal replacement grant: %v", err)
		}
		applyTokenRecord(&replacement, rec)
		if err := database.Create(&replacement).Error; err != nil {
			t.Fatalf("seed replacement link: %v", err)
		}

		token, err := svc.converge(ctx, link)
		if token != nil {
			t.Fatalf("converge served %+v; want no token for a different row", token)
		}
		requireCode(t, err, errors.CodeOAuthReauthRequired, http.StatusUnauthorized)
	})
}

// TestExchangeRefreshTokenStaleSnapshot pins the in-flight re-read: a snapshot
// another writer already replaced must be served instead of spent, because X
// invalidates a refresh token on use and the stale POST can only be rejected.
func TestExchangeRefreshTokenStaleSnapshot(t *testing.T) {
	ctx := context.Background()

	t.Run("a rotated row is served without spending the stale token", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		_, svc, link, _ := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		rotateGrant(t, svc, link, &OAuthToken{AccessToken: "winner-access", RefreshToken: "winner-refresh", ExpiresIn: 3600})

		token, err := svc.exchangeRefreshToken(ctx, link)
		if err != nil {
			t.Fatalf("exchangeRefreshToken = %v; want the winner's token", err)
		}
		if token.AccessToken != "winner-access" {
			t.Fatalf("AccessToken = %q; want winner-access", token.AccessToken)
		}
		if provider.calls() != 0 {
			t.Fatalf("refresh calls = %d; want none for a replaced snapshot", provider.calls())
		}
	})

	t.Run("a row rewritten with a usable access token is served", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		_, svc, link, _ := tokenAccessEnv(t, provider, tokenTestGrant(), staleExpiry())
		expiresAt := time.Now().UTC().Add(time.Hour)
		rec, err := svc.sealedTokens(link.ProviderID, link.ID.String(),
			&OAuthToken{AccessToken: "inplace-access", RefreshToken: tokenTestRefresh, ExpiresIn: 3600})
		if err != nil {
			t.Fatalf("seal rewritten grant: %v", err)
		}
		rec.TokenExpiresAt = &expiresAt
		if err := svc.store.OAuthAccounts().SaveOAuthTokens(ctx, link.ID, rec); err != nil {
			t.Fatalf("rewrite grant: %v", err)
		}

		token, err := svc.exchangeRefreshToken(ctx, link)
		if err != nil {
			t.Fatalf("exchangeRefreshToken = %v; want the rewritten token", err)
		}
		if token.AccessToken != "inplace-access" {
			t.Fatalf("AccessToken = %q; want inplace-access", token.AccessToken)
		}
		if provider.calls() != 0 {
			t.Fatalf("refresh calls = %d; want none for a fresh row", provider.calls())
		}
	})
}
