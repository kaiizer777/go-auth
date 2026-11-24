package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

// nonceProvider is an OIDC provider with no per-login option channel: the only
// way a nonce can reach it is the fallback authorize-URL builder.
type nonceProvider struct {
	id        string
	seenNonce string
	verified  string
}

func (p *nonceProvider) ID() string { return p.id }

func (p *nonceProvider) AuthURL(state, codeChallenge string) string {
	q := url.Values{}
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	return "https://idp.example/authorize?" + q.Encode()
}

func (p *nonceProvider) ExchangeCode(context.Context, string, string) (*OAuthToken, error) {
	return &OAuthToken{AccessToken: "nonce-access", IDToken: "id-token"}, nil
}

func (p *nonceProvider) FetchUserInfo(context.Context, *OAuthToken) (*OAuthUser, error) {
	return &OAuthUser{ProviderID: p.id, ProviderUserID: "nonce-sub", Email: "nonce@example.test", EmailVerified: true}, nil
}

func (p *nonceProvider) VerifyIDToken(_ context.Context, rawIDToken, nonce string) (*IDTokenClaims, error) {
	if rawIDToken != "id-token" || nonce == "" || nonce != p.seenNonce {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "id_token nonce mismatch", nil)
	}
	p.verified = nonce
	return &IDTokenClaims{Subject: "nonce-sub", Email: "nonce@example.test", EmailVerified: true}, nil
}

// nonceOptionProvider adds the optional AuthCodeURLProvider capability, so the
// nonce travels as a per-login option instead of the appended query parameter.
type nonceOptionProvider struct{ *nonceProvider }

func (p *nonceOptionProvider) AuthCodeURL(state, codeChallenge string, opts ...AuthCodeOption) string {
	u, err := url.Parse(p.nonceProvider.AuthURL(state, codeChallenge))
	if err != nil {
		return ""
	}
	q := u.Query()
	for _, opt := range opts {
		q.Set(opt.Key, opt.Value)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// TestOIDCNonceContract pins the initiate/callback nonce agreement for both
// provider shapes: whichever builder issues the authorize URL, the nonce the
// provider receives is the one the callback verifies.
func TestOIDCNonceContract(t *testing.T) {
	run := func(t *testing.T, p Provider) {
		t.Helper()
		database := serviceTestDB(t)
		cfg := serviceTestConfig()
		svc := NewService(database, session.NewService(database, cfg),
			map[string]Provider{p.ID(): p}, cfg)

		rec := httptest.NewRecorder()
		initReq := httptest.NewRequest(http.MethodGet, "/auth/oauth/"+p.ID(), nil)
		authURL, err := svc.InitiateFlow(rec, initReq, p.ID())
		if err != nil {
			t.Fatalf("InitiateFlow = %v", err)
		}
		sent, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("parse authorize URL: %v", err)
		}
		state := sent.Query().Get("state")
		nonce := sent.Query().Get("nonce")
		if state == "" || nonce == "" {
			t.Fatalf("authorize URL state=%q nonce=%q; want both set (%q)", state, nonce, authURL)
		}
		var cookie *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				cookie = c
			}
		}
		if cookie == nil {
			t.Fatalf("no %q cookie issued", cfg.OAuth.StateCookieName)
		}
		switch typed := p.(type) {
		case *nonceProvider:
			typed.seenNonce = nonce
		case *nonceOptionProvider:
			typed.seenNonce = nonce
		}

		cbRec, cbReq := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(cbReq.Context(), cbRec, cbReq, p.ID(), "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v; the provider saw nonce %q", err, nonce)
		}
		if sess == nil {
			t.Fatal("no session minted")
		}
	}

	t.Run("provider without an option channel gets the nonce appended", func(t *testing.T) {
		p := &nonceProvider{id: "idp-plain"}
		run(t, p)
		if p.verified == "" {
			t.Fatal("ID token was not verified against the nonce sent at initiate")
		}
	})

	t.Run("provider with an option channel gets the nonce as an option", func(t *testing.T) {
		p := &nonceOptionProvider{nonceProvider: &nonceProvider{id: "idp-option"}}
		run(t, p)
		if p.verified == "" {
			t.Fatal("ID token was not verified against the nonce sent at initiate")
		}
	})
}
