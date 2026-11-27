package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/session"
)

// legacyProvider implements only the pre-option Provider contract. It must keep
// satisfying Provider and flow through InitiateFlow via the AuthURL fallback.
type legacyProvider struct {
	authURL string
}

var _ Provider = (*legacyProvider)(nil)

func (p *legacyProvider) ID() string { return "legacy" }

func (p *legacyProvider) AuthURL(state, codeChallenge string) string {
	return p.authURL + "?state=" + state + "&code_challenge=" + codeChallenge
}

func (p *legacyProvider) ExchangeCode(context.Context, string, string) (*OAuthToken, error) {
	return nil, nil
}

func (p *legacyProvider) FetchUserInfo(context.Context, *OAuthToken) (*OAuthUser, error) {
	return nil, nil
}

// legacyOIDCProvider adds the OIDC capability without AuthCodeURL; the service
// must fall back to AuthURL (appending the nonce) rather than require the
// optional interface: the callback verifies that nonce for every OIDC provider.
type legacyOIDCProvider struct {
	legacyProvider
}

var _ OIDCProvider = (*legacyOIDCProvider)(nil)

func (p *legacyOIDCProvider) VerifyIDToken(context.Context, string, string) (*IDTokenClaims, error) {
	return nil, nil
}

func TestInitiateFlowLegacyProvider(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		provider  Provider
		wantNonce bool
	}{
		{name: "pre-PR provider", provider: &legacyProvider{authURL: "https://legacy.example/authorize"}},
		{name: "pre-PR OIDC provider", provider: &legacyOIDCProvider{legacyProvider{authURL: "https://legacy.example/authorize"}}, wantNonce: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			database := serviceTestDB(t)
			cfg := serviceTestConfig()
			svc := NewService(database, session.NewService(database, cfg),
				map[string]Provider{"legacy": tt.provider}, cfg)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/auth/oauth/legacy", nil)
			raw, err := svc.InitiateFlow(rec, req, "legacy")
			if err != nil {
				t.Fatalf("InitiateFlow = %v", err)
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("parse authURL: %v", err)
			}
			if u.Host != "legacy.example" {
				t.Fatalf("host = %q; want legacy.example", u.Host)
			}
			if u.Query().Get("state") == "" {
				t.Fatal("authorize URL missing state")
			}
			if got := u.Query().Get("nonce"); (got != "") != tt.wantNonce {
				t.Fatalf("nonce = %q; want set=%v", got, tt.wantNonce)
			}
		})
	}
}

func TestAdapterAuthURLByteStable(t *testing.T) {
	t.Parallel()
	cfg := config.ProviderConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://app.example.com/cb",
	}
	tests := []struct {
		id      string
		wantURL string
	}{
		{
			id:      "google",
			wantURL: "https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&client_id=test-client&code_challenge=ch&code_challenge_method=S256&prompt=select_account&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=openid+email+profile&state=st",
		},
		{
			id:      "github",
			wantURL: "https://github.com/login/oauth/authorize?client_id=test-client&code_challenge=ch&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=read%3Auser+user%3Aemail&state=st",
		},
		{
			id:      "apple",
			wantURL: "https://appleid.apple.com/auth/authorize?client_id=test-client&code_challenge=ch&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_mode=form_post&response_type=code&scope=name+email&state=st",
		},
		{
			id:      "facebook",
			wantURL: "https://www.facebook.com/v19.0/dialog/oauth?client_id=test-client&code_challenge=ch&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=email+public_profile&state=st",
		},
		{
			id:      "discord",
			wantURL: "https://discord.com/oauth2/authorize?client_id=test-client&code_challenge=ch&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=identify+email&state=st",
		},
		{
			id:      "x",
			wantURL: "https://twitter.com/i/oauth2/authorize?client_id=test-client&code_challenge=ch&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=users.read+offline.access&state=st",
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			t.Parallel()
			p, err := NewProvider(tt.id, cfg)
			if err != nil {
				t.Fatalf("NewProvider(%q) = %v", tt.id, err)
			}
			if got := p.AuthURL("st", "ch"); got != tt.wantURL {
				t.Fatalf("AuthURL =\n%s\nwant\n%s", got, tt.wantURL)
			}
		})
	}
}
