package oauth

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

// TestInitiateFlowRequiresTokenSealer pins the fail-closed gate: without a
// keyring no grant could be sealed, so the flow is refused before a state
// cookie is planted.
func TestInitiateFlowRequiresTokenSealer(t *testing.T) {
	cfg := serviceTestConfig()
	cfg.OAuth.TokenKEK = ""
	svc := NewService(serviceTestDB(t), nil, map[string]Provider{"google": &stubProvider{id: "google"}}, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google", nil)
	if _, err := svc.InitiateFlow(rec, req, "google"); !stderrors.Is(err, errors.ErrOAuthTokenKEKMissing) {
		t.Fatalf("InitiateFlow err = %v; want ErrOAuthTokenKEKMissing", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.OAuth.StateCookieName {
			t.Fatal("state cookie planted without a token keyring")
		}
	}
}

// TestHandleCallbackRequiresTokenSealer pins the guard ahead of the exchange:
// the authorization code is not burned and no user, link, or session appears.
func TestHandleCallbackRequiresTokenSealer(t *testing.T) {
	database, cfg, stub, svc := setupServiceTest(t, verifiedInfo())
	state, cookie := mustInitiate(t, svc, cfg, "google")

	noKEK := serviceTestConfig()
	noKEK.OAuth.TokenKEK = ""
	bare := NewService(database, session.NewService(database, noKEK), map[string]Provider{"google": stub}, noKEK)

	rec, req := callbackRequest(state, cookie)
	_, _, _, err := bare.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
	if !stderrors.Is(err, errors.ErrOAuthTokenKEKMissing) {
		t.Fatalf("HandleCallback err = %v; want ErrOAuthTokenKEKMissing", err)
	}
	if stub.exchanges != 0 {
		t.Fatalf("exchange calls = %d; want 0", stub.exchanges)
	}
	requireIdentityRows(t, database, 0, 0, 0)
}

func TestTokenExpiry(t *testing.T) {
	t.Run("no expiry for zero or negative expires_in", func(t *testing.T) {
		for _, expiresIn := range []int{0, -1, -3600} {
			if got := tokenExpiry(&OAuthToken{ExpiresIn: expiresIn}); got != nil {
				t.Fatalf("ExpiresIn %d = %v; want nil", expiresIn, got)
			}
		}
	})

	t.Run("derives now plus expires_in and ignores ExpiresAt", func(t *testing.T) {
		before := time.Now().UTC()
		got := tokenExpiry(&OAuthToken{ExpiresIn: 3600, ExpiresAt: time.Unix(1, 0)})
		after := time.Now().UTC()
		if got == nil {
			t.Fatal("expiry = nil; want now+3600s")
		}
		if got.Before(before.Add(time.Hour)) || got.After(after.Add(time.Hour)) {
			t.Fatalf("expiry = %v; want between %v and %v", got, before.Add(time.Hour), after.Add(time.Hour))
		}
	})

	t.Run("clamps an absurd expires_in to the duration limit instead of overflowing", func(t *testing.T) {
		huge := int64(math.MaxInt64 / 2)
		if int64(int(huge)) != int64(huge) {
			t.Skip("expires_in cannot exceed the clamp on this platform")
		}
		now := time.Now().UTC()
		got := tokenExpiry(&OAuthToken{ExpiresIn: int(huge)})
		if got == nil || !got.After(now) {
			t.Fatalf("expiry = %v; want a timestamp after %v", got, now)
		}
		if got.Before(now.Add(200 * 365 * 24 * time.Hour)) {
			t.Fatalf("expiry = %v; want the clamped horizon, not a wrapped one", got)
		}
	})
}

const (
	tokenTestAccess  = "provider-access-token"
	tokenTestRefresh = "provider-refresh-token"
	tokenTestScope   = "users.read offline.access"
)

func tokenTestGrant() *OAuthToken {
	return &OAuthToken{
		AccessToken:  tokenTestAccess,
		RefreshToken: tokenTestRefresh,
		ExpiresIn:    3600,
		Raw:          map[string]any{"scope": tokenTestScope},
	}
}

func tokenTestSealer(t *testing.T) *crypto.TokenSealer {
	t.Helper()
	ring, err := crypto.ParseKeyring(testTokenKEK)
	if err != nil {
		t.Fatalf("parse keyring: %v", err)
	}
	return crypto.NewTokenSealer(ring)
}

func loadTokenLink(t *testing.T, database *gorm.DB, providerUserID string) db.OAuthAccount {
	t.Helper()
	var link db.OAuthAccount
	if err := database.Where("provider_id = ? AND provider_user_id = ?", "google", providerUserID).First(&link).Error; err != nil {
		t.Fatalf("load link: %v", err)
	}
	return link
}

// openStoredGrant decrypts with the row's own persisted provider id and id: a
// mismatch with the row that actually landed surfaces as an auth failure.
func openStoredGrant(t *testing.T, link db.OAuthAccount) (string, string) {
	t.Helper()
	sealer := tokenTestSealer(t)
	access, err := sealer.OpenAccessToken(link.ProviderID, link.ID.String(), link.AccessTokenCiphertext)
	if err != nil {
		t.Fatalf("open access token against row %v: %v", link.ID, err)
	}
	if link.RefreshTokenCiphertext == "" {
		return access, ""
	}
	refresh, err := sealer.OpenRefreshToken(link.ProviderID, link.ID.String(), link.RefreshTokenCiphertext)
	if err != nil {
		t.Fatalf("open refresh token against row %v: %v", link.ID, err)
	}
	return access, refresh
}

func requireStoredGrant(t *testing.T, link db.OAuthAccount, access, refresh string) {
	t.Helper()
	gotAccess, gotRefresh := openStoredGrant(t, link)
	if gotAccess != access || gotRefresh != refresh {
		t.Fatalf("stored grant = (%q, %q); want (%q, %q)", gotAccess, gotRefresh, access, refresh)
	}
	if link.TokenExpiresAt == nil {
		t.Fatal("token expiry = nil; want now+expires_in")
	}
}

func TestTokenPersistence(t *testing.T) {
	t.Run("fresh registration stores the sealed grant", func(t *testing.T) {
		database, cfg, stub, svc := setupServiceTest(t, verifiedInfo())
		stub.token = tokenTestGrant()

		runCallback(t, svc, cfg)

		link := loadTokenLink(t, database, "sub-123")
		requireStoredGrant(t, link, tokenTestAccess, tokenTestRefresh)
		if link.TokenScope != tokenTestScope {
			t.Fatalf("token scope = %q; want %q", link.TokenScope, tokenTestScope)
		}
		want, err := tokenTestSealer(t).RefreshTokenFingerprint(tokenTestRefresh)
		if err != nil {
			t.Fatalf("fingerprint: %v", err)
		}
		if link.RefreshTokenFingerprint != want {
			t.Fatalf("fingerprint = %q; want %q", link.RefreshTokenFingerprint, want)
		}
	})

	t.Run("explicit attach stores the sealed grant", func(t *testing.T) {
		database, cfg, stub, svc := setupServiceTest(t, &UserInfo{
			ProviderID: "google", ProviderUserID: "sub-attach",
			Email: "provider-owner@personal.example", EmailVerified: true,
		})
		stub.token = tokenTestGrant()
		owner := db.User{ID: uuid.New(), Email: "owner@work.example", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&owner).Error; err != nil {
			t.Fatalf("seed owner: %v", err)
		}
		_, rawSession, err := session.NewService(database, cfg).
			CreateSession(context.Background(), owner.ID, owner.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		state, cookie := initiateLinked(t, svc, cfg, "google", rawSession)
		rec, req := callbackRequestWithSession(state, cookie, cfg, rawSession)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v", err)
		}
		if sess.UserID != owner.ID {
			t.Fatalf("session user = %v; want %v", sess.UserID, owner.ID)
		}
		link := loadTokenLink(t, database, "sub-attach")
		if link.UserID != owner.ID {
			t.Fatalf("link owner = %v; want %v", link.UserID, owner.ID)
		}
		requireStoredGrant(t, link, tokenTestAccess, tokenTestRefresh)
	})

	t.Run("returning login rewrites the rotated grant", func(t *testing.T) {
		database, cfg, stub, svc := setupServiceTest(t, verifiedInfo())
		stub.token = tokenTestGrant()
		runCallback(t, svc, cfg)
		first := loadTokenLink(t, database, "sub-123")

		stub.token = &OAuthToken{AccessToken: "rotated-access", RefreshToken: "rotated-refresh", ExpiresIn: 600}
		runCallback(t, svc, cfg)

		second := loadTokenLink(t, database, "sub-123")
		if second.ID != first.ID {
			t.Fatalf("link id = %v; want the existing row %v", second.ID, first.ID)
		}
		requireStoredGrant(t, second, "rotated-access", "rotated-refresh")
		if second.AccessTokenCiphertext == first.AccessTokenCiphertext {
			t.Fatal("access token ciphertext unchanged; the returning login did not rewrite the grant")
		}
		if second.RefreshTokenFingerprint == first.RefreshTokenFingerprint {
			t.Fatal("refresh fingerprint unchanged; the rotated refresh token was not stored")
		}
	})

	t.Run("returning login without a refresh token keeps the stored one", func(t *testing.T) {
		database, cfg, stub, svc := setupServiceTest(t, verifiedInfo())
		stub.token = tokenTestGrant()
		runCallback(t, svc, cfg)
		first := loadTokenLink(t, database, "sub-123")

		// Providers that issue a refresh token on first consent only answer a
		// later login without one; the stored grant must survive that login.
		stub.token = &OAuthToken{AccessToken: "relogin-access", ExpiresIn: 600}
		runCallback(t, svc, cfg)

		second := loadTokenLink(t, database, "sub-123")
		requireStoredGrant(t, second, "relogin-access", tokenTestRefresh)
		if second.RefreshTokenCiphertext != first.RefreshTokenCiphertext {
			t.Fatal("refresh envelope rewritten by a grant that carried no refresh token")
		}
		if second.RefreshTokenFingerprint != first.RefreshTokenFingerprint {
			t.Fatalf("fingerprint = %q; want the stored %q", second.RefreshTokenFingerprint, first.RefreshTokenFingerprint)
		}
		if second.AccessTokenCiphertext == first.AccessTokenCiphertext {
			t.Fatal("access token ciphertext unchanged; the login grant was not stored")
		}
		// The scope-less grant must not blank the granted scope either.
		if second.TokenScope != tokenTestScope {
			t.Fatalf("token scope = %q; want the unchanged %q", second.TokenScope, tokenTestScope)
		}
	})

	t.Run("refresh-less login does not overwrite a concurrent rotation", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, _ := tokenAccessEnv(t, provider, tokenTestGrant(), nil)
		rotateGrant(t, svc, link, &OAuthToken{AccessToken: "winner-access", RefreshToken: "winner-refresh", ExpiresIn: 3600})
		won := reloadTokenLink(t, database, link.ID)

		// The login read the row before the rotation; its CAS must lose.
		svc.persistTokens(context.Background(), link, &OAuthToken{AccessToken: "relogin-access", ExpiresIn: 600})

		stored := reloadTokenLink(t, database, link.ID)
		requireStoredGrant(t, stored, "winner-access", "winner-refresh")
		if stored.AccessTokenCiphertext != won.AccessTokenCiphertext {
			t.Fatal("login overwrote the winner's grant")
		}
	})

	// The row this callback read had no refresh token, so there is no fingerprint
	// to CAS on. A concurrent login may still add the credential the provider
	// issues only once; the access-only write must leave it in place.
	t.Run("refresh-less login keeps a refresh token added after its read", func(t *testing.T) {
		provider := &stubRefreshProvider{stubProvider: &stubProvider{id: "google"}}
		database, svc, link, _ := tokenAccessEnv(t, provider, &OAuthToken{AccessToken: tokenTestAccess}, nil)
		rec, err := svc.sealedTokens(link.ProviderID, link.ID.String(), tokenTestGrant())
		if err != nil {
			t.Fatalf("seal concurrent grant: %v", err)
		}
		if err := svc.store.OAuthAccounts().SaveOAuthTokens(context.Background(), link.ID, rec); err != nil {
			t.Fatalf("store concurrent grant: %v", err)
		}
		storedGrant := reloadTokenLink(t, database, link.ID)

		svc.persistTokens(context.Background(), link, &OAuthToken{AccessToken: "relogin-access", ExpiresIn: 600})

		stored := reloadTokenLink(t, database, link.ID)
		requireStoredGrant(t, stored, "relogin-access", tokenTestRefresh)
		if stored.RefreshTokenCiphertext != storedGrant.RefreshTokenCiphertext ||
			stored.RefreshTokenFingerprint != storedGrant.RefreshTokenFingerprint {
			t.Fatal("login zeroed the refresh token a concurrent writer stored")
		}
	})

	// A concurrent signup that lands without a refresh credential leaves a row
	// this login is the only one able to complete: the presented grant has to be
	// stored, guarded so it cannot overwrite a newer one.
	t.Run("unverified signup convergence stores the presented grant", func(t *testing.T) {
		database, _, _, rawSvc := setupServiceTest(t, nil)
		svc := rawSvc.(*service)
		const addr = "raced-pending@example.com"
		pending := db.User{ID: uuid.New(), Email: addr}
		if err := database.Create(&pending).Error; err != nil {
			t.Fatalf("seed pending user: %v", err)
		}
		winner := db.OAuthAccount{ID: uuid.New(), UserID: pending.ID, ProviderID: "google",
			ProviderUserID: "sub-raced-grant", Email: addr}
		rec, err := svc.sealedTokens("google", winner.ID.String(), &OAuthToken{AccessToken: "winner-access", ExpiresIn: 3600})
		if err != nil {
			t.Fatalf("seal winner grant: %v", err)
		}
		applyTokenRecord(&winner, rec)
		if err := database.Create(&winner).Error; err != nil {
			t.Fatalf("seed winner link: %v", err)
		}

		info := &UserInfo{ProviderID: "google", ProviderUserID: "sub-raced-grant", Email: addr}
		got, _, created, err := svc.createUserAndLink(context.Background(), "google", info, tokenTestGrant())
		if err != nil {
			t.Fatalf("createUserAndLink = %v; want convergence", err)
		}
		if created || got.ID != pending.ID {
			t.Fatalf("converged on %v (created=%v); want %v", got.ID, created, pending.ID)
		}

		requireStoredGrant(t, loadTokenLink(t, database, "sub-raced-grant"), tokenTestAccess, tokenTestRefresh)
	})

	t.Run("unverified signup convergence keeps an already stored grant", func(t *testing.T) {
		database, _, _, rawSvc := setupServiceTest(t, nil)
		svc := rawSvc.(*service)
		const addr = "raced-stored@example.com"
		pending := db.User{ID: uuid.New(), Email: addr}
		if err := database.Create(&pending).Error; err != nil {
			t.Fatalf("seed pending user: %v", err)
		}
		winner := db.OAuthAccount{ID: uuid.New(), UserID: pending.ID, ProviderID: "google",
			ProviderUserID: "sub-raced-stored", Email: addr}
		rec, err := svc.sealedTokens("google", winner.ID.String(),
			&OAuthToken{AccessToken: "winner-access", RefreshToken: "winner-refresh", ExpiresIn: 3600})
		if err != nil {
			t.Fatalf("seal winner grant: %v", err)
		}
		applyTokenRecord(&winner, rec)
		if err := database.Create(&winner).Error; err != nil {
			t.Fatalf("seed winner link: %v", err)
		}

		info := &UserInfo{ProviderID: "google", ProviderUserID: "sub-raced-stored", Email: addr}
		if _, _, _, err := svc.createUserAndLink(context.Background(), "google", info, tokenTestGrant()); err != nil {
			t.Fatalf("createUserAndLink = %v; want convergence", err)
		}

		requireStoredGrant(t, loadTokenLink(t, database, "sub-raced-stored"), "winner-access", "winner-refresh")
	})

	t.Run("merge path stores the sealed grant", func(t *testing.T) {
		database, cfg, stub, svc := setupServiceTest(t, &UserInfo{
			ProviderID: "google", ProviderUserID: "sub-merge",
			Email: "merged@example.com", EmailVerified: true,
		})
		stub.token = tokenTestGrant()
		owner := db.User{ID: uuid.New(), Email: "merged@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&owner).Error; err != nil {
			t.Fatalf("seed owner: %v", err)
		}

		runCallback(t, svc, cfg)

		link := loadTokenLink(t, database, "sub-merge")
		if link.UserID != owner.ID {
			t.Fatalf("link owner = %v; want merged owner %v", link.UserID, owner.ID)
		}
		requireStoredGrant(t, link, tokenTestAccess, tokenTestRefresh)
	})

	t.Run("grant without a refresh token stores no refresh material", func(t *testing.T) {
		database, cfg, stub, svc := setupServiceTest(t, verifiedInfo())
		stub.token = &OAuthToken{AccessToken: tokenTestAccess, ExpiresIn: 60}

		runCallback(t, svc, cfg)

		link := loadTokenLink(t, database, "sub-123")
		if link.RefreshTokenCiphertext != "" || link.RefreshTokenFingerprint != "" {
			t.Fatalf("refresh ciphertext = %q, fingerprint = %q; want both empty",
				link.RefreshTokenCiphertext, link.RefreshTokenFingerprint)
		}
		requireStoredGrant(t, link, tokenTestAccess, "")
	})

	t.Run("oversized token on the insert path fails the login with nothing written", func(t *testing.T) {
		database, cfg, stub, svc := setupServiceTest(t, verifiedInfo())
		stub.token = &OAuthToken{AccessToken: strings.Repeat("a", 4097), ExpiresIn: 3600}

		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)

		requireCode(t, err, errors.CodeInternalError, http.StatusInternalServerError)
		requireIdentityRows(t, database, 0, 0, 0)
	})

	t.Run("oversized token on the returning login is swallowed and the old grant survives", func(t *testing.T) {
		database, cfg, stub, svc := setupServiceTest(t, verifiedInfo())
		stub.token = tokenTestGrant()
		runCallback(t, svc, cfg)

		stub.token = &OAuthToken{AccessToken: strings.Repeat("b", 4097), ExpiresIn: 3600}
		runCallback(t, svc, cfg)

		requireStoredGrant(t, loadTokenLink(t, database, "sub-123"), tokenTestAccess, tokenTestRefresh)
	})

	t.Run("nil keyring fails the insert path", func(t *testing.T) {
		database, _, _, rawSvc := setupServiceTest(t, nil)
		noKEK := serviceTestConfig()
		noKEK.OAuth.TokenKEK = ""
		svc := NewServiceWithStore(rawSvc.(*service).store, nil, nil, noKEK).(*service)

		_, _, _, err := svc.linkOrCreate(context.Background(), "google", verifiedInfo(), "", tokenTestGrant())

		requireCode(t, err, errors.CodeInternalError, http.StatusInternalServerError)
		requireIdentityRows(t, database, 0, 0, 0)
	})

	t.Run("transaction retry seals against the row that landed", func(t *testing.T) {
		database, _, _, rawSvc := setupServiceTest(t, nil)
		base := rawSvc.(*service).store
		var abortedID uuid.UUID
		proxy := &retryProxyStore{
			Store: base,
			onAttempt: func(attempt int, store db.Store) db.Store {
				if attempt > 1 {
					return store
				}
				return &wrappedTxStore{
					Store: store,
					users: &interceptUserStore{
						UserStore:  store.Users(),
						createFunc: func(context.Context, *db.User) error { return nil },
					},
					oauth: &interceptOAuthStore{
						OAuthAccountStore: store.OAuthAccounts(),
						createFunc: func(_ context.Context, account *db.OAuthAccount) error {
							abortedID = account.ID
							return stderrors.New("transient transaction failure")
						},
					},
				}
			},
		}
		svc := NewServiceWithStore(proxy, nil, nil, serviceTestConfig()).(*service)

		_, _, _, err := svc.createUserAndLink(context.Background(), "google", verifiedInfo(), tokenTestGrant())
		if err != nil {
			t.Fatalf("createUserAndLink = %v", err)
		}

		link := loadTokenLink(t, database, "sub-123")
		if abortedID == uuid.Nil {
			t.Fatal("first attempt never sealed a row")
		}
		if link.ID == abortedID {
			t.Fatalf("link id = %v; want the retry to regenerate it", link.ID)
		}
		requireStoredGrant(t, link, tokenTestAccess, tokenTestRefresh)
	})

	t.Run("stored columns hold an envelope under the active kid, never plaintext", func(t *testing.T) {
		database, cfg, stub, svc := setupServiceTest(t, verifiedInfo())
		stub.token = tokenTestGrant()
		runCallback(t, svc, cfg)
		link := loadTokenLink(t, database, "sub-123")

		var raw struct {
			Access  string `gorm:"column:access_token_ciphertext"`
			Refresh string `gorm:"column:refresh_token_ciphertext"`
		}
		if err := database.Raw(
			"SELECT access_token_ciphertext, refresh_token_ciphertext FROM oauth_accounts WHERE id = ?",
			link.ID.String()).Scan(&raw).Error; err != nil {
			t.Fatalf("read raw columns: %v", err)
		}
		for name, stored := range map[string]string{"access": raw.Access, "refresh": raw.Refresh} {
			if stored == "" {
				t.Fatalf("%s column is empty", name)
			}
			if stored == tokenTestAccess || stored == tokenTestRefresh || strings.Contains(stored, "provider-") {
				t.Fatalf("%s column holds the provider plaintext", name)
			}
			var envelope struct {
				Version int    `json:"v"`
				Alg     string `json:"alg"`
				Kid     string `json:"kid"`
				Nonce   string `json:"n"`
			}
			if err := json.Unmarshal([]byte(stored), &envelope); err != nil {
				t.Fatalf("%s column is not a JSON envelope: %v", name, err)
			}
			if envelope.Version != 1 || envelope.Alg != "A256GCM" || envelope.Kid != "test-kid" || envelope.Nonce == "" {
				t.Fatalf("%s envelope = %+v; want v1 A256GCM under kid test-kid", name, envelope)
			}
		}
	})
}
