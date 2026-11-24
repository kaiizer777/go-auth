package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

// stubOIDCProvider scripts an OIDC flow: canned ID token on exchange,
// programmable VerifyIDToken outcome with the received nonce recorded.
type stubOIDCProvider struct {
	stubProvider
	idToken   string
	gotNonce  string
	verifyErr error
}

func (f *stubOIDCProvider) ExchangeCode(_ context.Context, code, _ string) (*TokenResponse, error) {
	if code == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token exchange failed", nil)
	}
	return &TokenResponse{AccessToken: "stub-access", IDToken: f.idToken}, nil
}

func (f *stubOIDCProvider) VerifyIDToken(_ context.Context, rawIDToken, nonce string) (*IDTokenClaims, error) {
	f.gotNonce = nonce
	if f.verifyErr != nil {
		return nil, f.verifyErr
	}
	if rawIDToken == "" {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "missing raw id_token", nil)
	}
	return &IDTokenClaims{Nonce: nonce}, nil
}

// statePayloadNonce decodes the signed state cookie without consuming it.
func statePayloadNonce(t *testing.T, cookie *http.Cookie) string {
	t.Helper()
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		t.Fatalf("state cookie is not payload.signature: %q", cookie.Value)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode state payload: %v", err)
	}
	var payload OAuthStatePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal state payload: %v", err)
	}
	return payload.Nonce
}

func TestNonceRoundTrip(t *testing.T) {
	t.Run("nonce survives state cookie", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		rec := httptest.NewRecorder()
		state, err := SetStateCookieWithUserAndNonce(rec, cfg, "google", "v-code", "", "", "n-123")
		if err != nil {
			t.Fatalf("SetStateCookieWithUserAndNonce = %v", err)
		}
		var cookie *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				cookie = c
			}
		}
		if cookie == nil {
			t.Fatal("no state cookie issued")
		}
		if got := statePayloadNonce(t, cookie); got != "n-123" {
			t.Fatalf("decoded nonce = %q; want n-123", got)
		}
		req := httptest.NewRequest(http.MethodGet, "https://example.com/cb", nil)
		req.AddCookie(cookie)
		payload, err := ValidateState(httptest.NewRecorder(), req, cfg, "google", state)
		if err != nil {
			t.Fatalf("ValidateState = %v", err)
		}
		if payload.Nonce != "n-123" {
			t.Fatalf("payload nonce = %q; want n-123", payload.Nonce)
		}
	})

	t.Run("legacy states carry empty nonce", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		state, cookie := issueStateCookie(t, cfg)
		if got := statePayloadNonce(t, cookie); got != "" {
			t.Fatalf("legacy nonce = %q; want empty", got)
		}
		_ = state
	})
}

func TestInitiateFlowNonce(t *testing.T) {
	t.Run("microsoft authorize carries state-bound nonce", func(t *testing.T) {
		t.Parallel()
		database := serviceTestDB(t)
		cfg := serviceTestConfig()
		p := NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURI:  "https://app.example.com/cb",
			Tenant:       "common",
		})
		svc := NewService(database, session.NewService(database, cfg),
			map[string]Provider{"microsoft": p}, cfg)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft", nil)
		authURL, err := svc.InitiateFlow(rec, req, "microsoft")
		if err != nil {
			t.Fatalf("InitiateFlow = %v", err)
		}
		u, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("parse authURL: %v", err)
		}
		if u.Host != "login.microsoftonline.com" || u.Path != "/common/oauth2/v2.0/authorize" {
			t.Fatalf("authorize endpoint = %q%s; want tenant /common endpoint", u.Host, u.Path)
		}
		urlNonce := u.Query().Get("nonce")
		if urlNonce == "" {
			t.Fatalf("authorize URL missing nonce: %q", authURL)
		}
		var cookie *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				cookie = c
			}
		}
		if cookie == nil {
			t.Fatal("no state cookie issued")
		}
		if stateNonce := statePayloadNonce(t, cookie); stateNonce != urlNonce {
			t.Fatalf("state nonce = %q; url nonce = %q; want equal", stateNonce, urlNonce)
		}
	})

	t.Run("non-OIDC authorize omits nonce", func(t *testing.T) {
		t.Parallel()
		_, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		authURL, cookie := func() (string, *http.Cookie) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google", nil)
			authURL, err := svc.InitiateFlow(rec, req, "google")
			if err != nil {
				t.Fatalf("InitiateFlow = %v", err)
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == cfg.OAuth.StateCookieName {
					return authURL, c
				}
			}
			t.Fatal("no state cookie issued")
			return "", nil
		}()
		u, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("parse authURL: %v", err)
		}
		if got := u.Query().Get("nonce"); got != "" {
			t.Fatalf("non-OIDC authorize nonce = %q; want empty", got)
		}
		if got := statePayloadNonce(t, cookie); got == "" {
			t.Fatal("state must still store a nonce for future OIDC use")
		}
	})
}

func TestCallbackNonceVerify(t *testing.T) {
	setupOIDC := func(t *testing.T, fake *stubOIDCProvider) (*config.Config, Service) {
		t.Helper()
		database := serviceTestDB(t)
		cfg := serviceTestConfig()
		svc := NewService(database, session.NewService(database, cfg),
			map[string]Provider{"google": fake}, cfg)
		return cfg, svc
	}

	t.Run("matching nonce links", func(t *testing.T) {
		t.Parallel()
		fake := &stubOIDCProvider{idToken: "test-id-token"}
		fake.info = verifiedInfo()
		cfg, svc := setupOIDC(t, fake)
		state, cookie := signedInitiate(t, svc, cfg, "google", "/auth/oauth/google", "")
		wantNonce := statePayloadNonce(t, cookie)
		if wantNonce == "" {
			t.Fatal("initiate must store a nonce")
		}
		rec, req := callbackRequest(state, cookie)
		if _, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie); err != nil {
			t.Fatalf("HandleCallback = %v", err)
		}
		if fake.gotNonce != wantNonce {
			t.Fatalf("verified nonce = %q; want state nonce %q", fake.gotNonce, wantNonce)
		}
	})

	t.Run("mismatched nonce rejects with 401", func(t *testing.T) {
		t.Parallel()
		fake := &stubOIDCProvider{idToken: "test-id-token",
			verifyErr: errors.New(errors.CodeOAuthIDTokenInvalid, "id_token nonce mismatch", nil)}
		fake.info = verifiedInfo()
		cfg, svc := setupOIDC(t, fake)
		state, cookie := signedInitiate(t, svc, cfg, "google", "/auth/oauth/google", "")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthIDTokenInvalid, http.StatusUnauthorized)
	})

	t.Run("token-only flow skips verify", func(t *testing.T) {
		t.Parallel()
		fake := &stubOIDCProvider{idToken: ""}
		fake.info = verifiedInfo()
		cfg, svc := setupOIDC(t, fake)
		state, cookie := signedInitiate(t, svc, cfg, "google", "/auth/oauth/google", "")
		rec, req := callbackRequest(state, cookie)
		if _, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie); err != nil {
			t.Fatalf("HandleCallback = %v", err)
		}
		if fake.gotNonce != "" {
			t.Fatalf("verify ran with nonce %q; want skipped", fake.gotNonce)
		}
	})
}
