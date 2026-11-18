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

func googleTestConfig() config.ProviderConfig {
	return config.ProviderConfig{
		ClientID:     "google-id",
		ClientSecret: "google-secret",
		RedirectURL:  "https://app.example.com/auth/google/callback",
	}
}

func TestGoogleAuthURL(t *testing.T) {
	t.Parallel()
	p := NewGoogleProvider(googleTestConfig())
	u, err := url.Parse(p.AuthURL("state123", "challenge123"))
	if err != nil {
		t.Fatalf("parse AuthURL: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != "https://accounts.google.com/o/oauth2/v2/auth" {
		t.Errorf("host/path = %s; want google authorize endpoint", u.Scheme+"://"+u.Host+u.Path)
	}
	q := u.Query()
	want := map[string]string{
		"response_type":         "code",
		"client_id":             "google-id",
		"redirect_uri":          "https://app.example.com/auth/google/callback",
		"scope":                 "openid email profile",
		"state":                 "state123",
		"code_challenge":        "challenge123",
		"code_challenge_method": "S256",
		"access_type":           "offline",
		"prompt":                "select_account",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("param %q = %q; want %q", k, q.Get(k), v)
		}
	}

	t.Run("custom scopes override defaults", func(t *testing.T) {
		t.Parallel()
		cfg := googleTestConfig()
		cfg.Scopes = []string{"openid", "email"}
		u, _ := url.Parse(NewGoogleProvider(cfg).AuthURL("s", "c"))
		if u.Query().Get("scope") != "openid email" {
			t.Errorf("scope = %q; want custom scopes", u.Query().Get("scope"))
		}
	})
}

func TestGoogleExchangeAndUserInfo(t *testing.T) {
	t.Parallel()
	var tokenForm url.Values
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		tokenForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "goog-at", "token_type": "Bearer",
			"refresh_token": "goog-rt", "expires_in": 3600,
		})
	}))
	defer tokenSrv.Close()

	var gotAuth string
	userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": "10492837491823749", "email": "user@example.com",
			"email_verified": true, "name": "Jane Doe",
			"picture": "https://lh3.googleusercontent.com/pic",
		})
	}))
	defer userSrv.Close()

	p := NewGoogleProvider(googleTestConfig())
	p.tokenURL = tokenSrv.URL
	p.userInfoURL = userSrv.URL

	tok, err := p.ExchangeCode(context.Background(), "code123", "verifier123")
	if err != nil {
		t.Fatalf("ExchangeCode = %v", err)
	}
	if tok.AccessToken != "goog-at" || tok.RefreshToken != "goog-rt" || tok.ExpiresIn != 3600 {
		t.Errorf("tokens = %+v; want mapped fields", tok)
	}
	for k, v := range map[string]string{
		"code": "code123", "code_verifier": "verifier123", "grant_type": "authorization_code",
		"client_id": "google-id", "client_secret": "google-secret",
	} {
		if tokenForm.Get(k) != v {
			t.Errorf("token form %q = %q; want %q", k, tokenForm.Get(k), v)
		}
	}

	info, err := p.FetchUserInfo(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUserInfo = %v", err)
	}
	if gotAuth != "Bearer goog-at" {
		t.Errorf("Authorization = %q; want Bearer token", gotAuth)
	}
	if info.ProviderID != "google" || info.ProviderUserID != "10492837491823749" ||
		info.Email != "user@example.com" || !info.EmailVerified ||
		info.Name != "Jane Doe" || info.AvatarURL != "https://lh3.googleusercontent.com/pic" {
		t.Errorf("userinfo = %+v", info)
	}
}

func TestGoogleErrors(t *testing.T) {
	t.Parallel()

	t.Run("token 4xx maps to provider error", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		}))
		defer srv.Close()
		p := NewGoogleProvider(googleTestConfig())
		p.tokenURL = srv.URL
		_, err := p.ExchangeCode(context.Background(), "bad", "v")
		requireProviderError(t, err)
	})

	t.Run("token invalid JSON maps to provider error", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`not json{`))
		}))
		defer srv.Close()
		p := NewGoogleProvider(googleTestConfig())
		p.tokenURL = srv.URL
		_, err := p.ExchangeCode(context.Background(), "code", "v")
		requireProviderError(t, err)
	})

	t.Run("userinfo 5xx maps to provider error", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		p := NewGoogleProvider(googleTestConfig())
		p.userInfoURL = srv.URL
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{AccessToken: "at"})
		requireProviderError(t, err)
	})

	t.Run("missing sub rejected", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"email":"user@example.com","email_verified":true}`))
		}))
		defer srv.Close()
		p := NewGoogleProvider(googleTestConfig())
		p.userInfoURL = srv.URL
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{AccessToken: "at"})
		requireProviderError(t, err)
	})

	t.Run("empty access token rejected", func(t *testing.T) {
		t.Parallel()
		p := NewGoogleProvider(googleTestConfig())
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{})
		requireProviderError(t, err)
	})

	t.Run("unverified email surfaces false", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"123","email":"u@example.com","email_verified":false}`))
		}))
		defer srv.Close()
		p := NewGoogleProvider(googleTestConfig())
		p.userInfoURL = srv.URL
		info, err := p.FetchUserInfo(context.Background(), &TokenResponse{AccessToken: "at"})
		if err != nil {
			t.Fatalf("FetchUserInfo = %v", err)
		}
		if info.EmailVerified || info.Email != "u@example.com" || info.ProviderUserID != "123" {
			t.Errorf("userinfo = %+v; want sub preserved, verified false", info)
		}
	})
}
