package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/kaiizer777/go-auth/config"
)

func githubTestConfig() config.ProviderConfig {
	return config.ProviderConfig{
		ClientID:     "github-id",
		ClientSecret: "github-secret",
		RedirectURL:  "https://app.example.com/auth/github/callback",
	}
}

func TestGitHubAuthURL(t *testing.T) {
	t.Parallel()
	p := NewGitHubProvider(githubTestConfig())
	u, err := url.Parse(p.AuthURL("state123", "challenge123"))
	if err != nil {
		t.Fatalf("parse AuthURL: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != "https://github.com/login/oauth/authorize" {
		t.Errorf("host/path = %s; want github authorize endpoint", u.Scheme+"://"+u.Host+u.Path)
	}
	q := u.Query()
	want := map[string]string{
		"client_id":             "github-id",
		"redirect_uri":          "https://app.example.com/auth/github/callback",
		"scope":                 "read:user user:email",
		"state":                 "state123",
		"code_challenge":        "challenge123",
		"code_challenge_method": "S256",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("param %q = %q; want %q", k, q.Get(k), v)
		}
	}
}

func githubMockServers(t *testing.T, userBody string, emailsBody string, emailsStatus int, captureAccept *capturedValue) (*httptest.Server, *httptest.Server) {
	t.Helper()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captureAccept.set(r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "gh-at", "token_type": "Bearer"})
	}))
	mux := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			_, _ = w.Write([]byte(userBody))
		case "/user/emails":
			if emailsStatus != 0 {
				w.WriteHeader(emailsStatus)
				return
			}
			_, _ = w.Write([]byte(emailsBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(tokenSrv.Close)
	t.Cleanup(mux.Close)
	return tokenSrv, mux
}

func TestGitHubPublicEmail(t *testing.T) {
	t.Parallel()
	accept := &capturedValue{}
	tokenSrv, apiSrv := githubMockServers(t,
		`{"id":12345,"login":"octocat","name":"Mona Lisa","email":"mona@github.com","avatar_url":"https://avatars.example.com/u/1"}`,
		`[{"email":"mona@github.com","primary":true,"verified":true,"visibility":"public"}]`,
		0, accept,
	)
	defer tokenSrv.Close()
	defer apiSrv.Close()

	p := NewGitHubProvider(githubTestConfig())
	p.tokenURL = tokenSrv.URL
	p.userURL = apiSrv.URL + "/user"
	p.emailsURL = apiSrv.URL + "/user/emails"

	tok, err := p.ExchangeCode(context.Background(), "code123", "verifier123")
	if err != nil {
		t.Fatalf("ExchangeCode = %v", err)
	}
	if tok.AccessToken != "gh-at" {
		t.Errorf("access token = %q", tok.AccessToken)
	}
	if got := accept.get(); got != "application/json" {
		t.Errorf("Accept = %q; want application/json", got)
	}

	info, err := p.FetchUserInfo(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUserInfo = %v", err)
	}
	if info.ProviderID != "github" || info.ProviderUserID != "12345" ||
		info.Email != "mona@github.com" || !info.EmailVerified ||
		info.Name != "Mona Lisa" || info.AvatarURL != "https://avatars.example.com/u/1" {
		t.Errorf("userinfo = %+v", info)
	}
}

func TestGitHubPrivateEmailFallback(t *testing.T) {
	t.Parallel()
	tokenSrv, apiSrv := githubMockServers(t,
		`{"id":6789,"login":"ghost","name":null,"email":null,"avatar_url":"https://avatars.example.com/u/2"}`,
		`[{"email":"old@example.com","primary":false,"verified":true,"visibility":"private"},`+
			`{"email":"primary@example.com","primary":true,"verified":true,"visibility":"private"}]`,
		0, nil,
	)
	defer tokenSrv.Close()
	defer apiSrv.Close()

	p := NewGitHubProvider(githubTestConfig())
	p.tokenURL = tokenSrv.URL
	p.userURL = apiSrv.URL + "/user"
	p.emailsURL = apiSrv.URL + "/user/emails"

	tok, err := p.ExchangeCode(context.Background(), "code123", "verifier123")
	if err != nil {
		t.Fatalf("ExchangeCode = %v", err)
	}
	info, err := p.FetchUserInfo(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUserInfo = %v", err)
	}
	if info.Email != "primary@example.com" || !info.EmailVerified {
		t.Errorf("userinfo = %+v; want primary verified email", info)
	}
	if info.ProviderUserID != "6789" || info.Name != "ghost" {
		t.Errorf("userinfo = %+v; want numeric id string, login name fallback", info)
	}
}

func TestGitHubNoVerifiedEmail(t *testing.T) {
	t.Parallel()
	tokenSrv, apiSrv := githubMockServers(t,
		`{"id":42,"login":"unverified","name":"Un V","email":null,"avatar_url":""}`,
		`[{"email":"x@example.com","primary":true,"verified":false,"visibility":"private"}]`,
		0, nil,
	)
	defer tokenSrv.Close()
	defer apiSrv.Close()

	p := NewGitHubProvider(githubTestConfig())
	p.tokenURL = tokenSrv.URL
	p.userURL = apiSrv.URL + "/user"
	p.emailsURL = apiSrv.URL + "/user/emails"

	tok, err := p.ExchangeCode(context.Background(), "code123", "verifier123")
	if err != nil {
		t.Fatalf("ExchangeCode = %v", err)
	}
	info, err := p.FetchUserInfo(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUserInfo = %v", err)
	}
	if info.EmailVerified {
		t.Errorf("EmailVerified = true; want false when no primary+verified address exists")
	}
	if info.Email != "" {
		t.Errorf("Email = %q; want empty, never synthesized", info.Email)
	}
}

func TestGitHubErrors(t *testing.T) {
	t.Parallel()

	t.Run("token error body maps to provider error", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"incorrect_client_credentials"}`))
		}))
		defer srv.Close()
		p := NewGitHubProvider(githubTestConfig())
		p.tokenURL = srv.URL
		_, err := p.ExchangeCode(context.Background(), "bad", "v")
		requireProviderError(t, err)
	})

	t.Run("user 5xx maps to provider error", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		p := NewGitHubProvider(githubTestConfig())
		p.userURL = srv.URL
		p.emailsURL = srv.URL
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{AccessToken: "at"})
		requireProviderError(t, err)
	})

	t.Run("emails invalid JSON maps to provider error", func(t *testing.T) {
		t.Parallel()
		_, apiSrv := githubMockServers(t, `{"id":7,"login":"x"}`, `broken[`, 0, nil)
		defer apiSrv.Close()
		p := NewGitHubProvider(githubTestConfig())
		p.userURL = apiSrv.URL + "/user"
		p.emailsURL = apiSrv.URL + "/user/emails"
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{AccessToken: "at"})
		requireProviderError(t, err)
	})

	t.Run("missing user id rejected", func(t *testing.T) {
		t.Parallel()
		_, apiSrv := githubMockServers(t, `{"login":"noid"}`, `[]`, 0, nil)
		defer apiSrv.Close()
		p := NewGitHubProvider(githubTestConfig())
		p.userURL = apiSrv.URL + "/user"
		p.emailsURL = apiSrv.URL + "/user/emails"
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{AccessToken: "at"})
		requireProviderError(t, err)
	})
}
