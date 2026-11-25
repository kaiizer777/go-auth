package oauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

func requireProviderError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var appErr *errors.Error
	if !errors.As(err, &appErr) {
		t.Fatalf("error type = %T; want *errors.Error", err)
	}
	if appErr.Code() != errors.CodeOAuthProviderError {
		t.Fatalf("code = %q; want %q", appErr.Code(), errors.CodeOAuthProviderError)
	}
	if appErr.HTTPStatus() != http.StatusBadGateway {
		t.Fatalf("status = %d; want 502", appErr.HTTPStatus())
	}
}

func TestSupportedProviders(t *testing.T) {
	t.Parallel()
	expected := []string{"google", "github", "apple", "microsoft", "facebook", "discord", "x"}
	if len(SupportedProviders) != len(expected) {
		t.Fatalf("len = %d; want %d", len(SupportedProviders), len(expected))
	}
	for _, id := range expected {
		if _, ok := SupportedProviders[id]; !ok {
			t.Errorf("missing provider %q", id)
		}
		if !IsSupportedProvider(id) {
			t.Errorf("IsSupportedProvider(%q) = false; want true", id)
		}
	}
	for _, id := range []string{"", "slack", "GOOGLE", "google "} {
		if IsSupportedProvider(id) {
			t.Errorf("IsSupportedProvider(%q) = true; want false", id)
		}
	}
}

func TestNewProvider(t *testing.T) {
	t.Parallel()
	cfg := config.ProviderConfig{ClientID: "id", ClientSecret: "secret", RedirectURL: "https://app.example.com/cb"}

	t.Run("all 7 providers resolve with matching IDs", func(t *testing.T) {
		t.Parallel()
		for _, id := range []string{"google", "github", "apple", "microsoft", "facebook", "discord", "x"} {
			p, err := NewProvider(id, cfg)
			if err != nil {
				t.Errorf("NewProvider(%q) = %v", id, err)
				continue
			}
			if p.ID() != id {
				t.Errorf("ID() = %q; want %q", p.ID(), id)
			}
		}
	})

	t.Run("microsoft typed overrides thread through", func(t *testing.T) {
		t.Parallel()
		typed := &config.OAuthConfig{
			Microsoft: &config.MicrosoftConfig{
				Tenant:         "organizations",
				TrustedTenants: []string{"partner-guid"},
				JWKSCacheTTL:   2 * time.Hour,
			},
		}
		p, err := NewProvider("microsoft", cfg, typed)
		if err != nil {
			t.Fatalf("NewProvider(microsoft) = %v", err)
		}
		mp, ok := p.(*MicrosoftProvider)
		if !ok {
			t.Fatalf("type = %T; want *MicrosoftProvider", p)
		}
		if mp.cfg.Tenant != "organizations" {
			t.Errorf("Tenant = %q; want organizations", mp.cfg.Tenant)
		}
		if len(mp.trustedTenants) != 1 {
			t.Fatalf("trustedTenants entries = %d; want 1", len(mp.trustedTenants))
		}
		if mp.cfg.JWKSCacheTTL != 2*time.Hour {
			t.Errorf("JWKSCacheTTL = %v; want 2h", mp.cfg.JWKSCacheTTL)
		}
		if !strings.Contains(mp.authURL, "/organizations/") {
			t.Errorf("authURL = %q; want organizations authority", mp.authURL)
		}
	})

	t.Run("facebook typed graph version threads through", func(t *testing.T) {
		t.Parallel()
		typed := &config.OAuthConfig{
			Facebook: &config.FacebookConfig{GraphVersion: "v20.0"},
		}
		p, err := NewProvider("facebook", cfg, typed)
		if err != nil {
			t.Fatalf("NewProvider(facebook) = %v", err)
		}
		fp, ok := p.(*FacebookProvider)
		if !ok {
			t.Fatalf("type = %T; want *FacebookProvider", p)
		}
		if fp.cfg.GraphVersion != "v20.0" {
			t.Errorf("GraphVersion = %q; want v20.0", fp.cfg.GraphVersion)
		}
	})

	t.Run("deferred and unknown reject with 404", func(t *testing.T) {
		t.Parallel()
		for _, id := range []string{"slack", "gitlab", "twitch", "unknown", ""} {
			p, err := NewProvider(id, cfg)
			if p != nil {
				t.Errorf("NewProvider(%q) provider = %v; want nil", id, p)
			}
			if err == nil {
				t.Errorf("NewProvider(%q) error = nil; want OAUTH_PROVIDER_NOT_FOUND", id)
				continue
			}
			var appErr *errors.Error
			if !errors.As(err, &appErr) {
				t.Errorf("NewProvider(%q) type = %T; want *errors.Error", id, err)
				continue
			}
			if appErr.Code() != errors.CodeOAuthProviderNotFound {
				t.Errorf("NewProvider(%q) code = %q; want OAUTH_PROVIDER_NOT_FOUND", id, appErr.Code())
			}
			if appErr.HTTPStatus() != http.StatusNotFound {
				t.Errorf("NewProvider(%q) status = %d; want 404", id, appErr.HTTPStatus())
			}
		}
	})
}

func TestNewProviderFacebookEmailAttestation(t *testing.T) {
	t.Parallel()

	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"fb-user-1","name":"Fb User","email":"fb@example.com"}`)
	}))
	t.Cleanup(graph.Close)

	// Builds the adapter through the validated config surface, the same path
	// startup takes, then points only the userinfo call at the fake Graph API.
	// A nil assert leaves the field absent, which must behave like false.
	newAdapter := func(t *testing.T, assert *bool) *FacebookProvider {
		t.Helper()
		cfg := config.DefaultConfig()
		cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
		cfg.BaseURL = "https://example.com"
		cfg.OAuth.StateSecret = "test-state-secret-at-least-32-bytes!"
		fb := &config.FacebookConfig{
			AppID:       "fb-id",
			AppSecret:   "fb-secret",
			RedirectURI: "https://example.com/cb",
		}
		if assert != nil {
			fb.AssertEmailVerified = *assert
		}
		cfg.OAuth.Facebook = fb
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate = %v", err)
		}
		p, err := NewProvider("facebook", cfg.OAuth.Providers["facebook"])
		if err != nil {
			t.Fatalf("NewProvider(facebook) = %v", err)
		}
		fp, ok := p.(*FacebookProvider)
		if !ok {
			t.Fatalf("provider type = %T; want *FacebookProvider", p)
		}
		fp.userInfoURL = graph.URL
		return fp
	}

	fetch := func(t *testing.T, assert *bool) *OAuthUser {
		t.Helper()
		user, err := newAdapter(t, assert).FetchUserInfo(context.Background(), &OAuthToken{AccessToken: "at-1"})
		if err != nil {
			t.Fatalf("FetchUserInfo = %v", err)
		}
		if user.Email != "fb@example.com" {
			t.Fatalf("Email = %q; want fb@example.com", user.Email)
		}
		return user
	}

	boolPtr := func(v bool) *bool { return &v }

	t.Run("asserted config reports the Graph email verified", func(t *testing.T) {
		t.Parallel()
		user := fetch(t, boolPtr(true))
		if !user.EmailVerified {
			t.Fatal("EmailVerified = false; want true under assert_email_verified")
		}
		if err := validateProviderIdentity(user); err != nil {
			t.Fatalf("validateProviderIdentity = %v; want the merge gate open", err)
		}
	})

	t.Run("absent flag keeps the Graph email unverified and blocks merging", func(t *testing.T) {
		t.Parallel()
		user := fetch(t, nil)
		if user.EmailVerified {
			t.Fatal("EmailVerified = true; a non-empty Graph email is not an attested claim")
		}
		if err := validateProviderIdentity(user); !errors.Is(err, errors.ErrOAuthEmailUnverified) {
			t.Fatalf("validateProviderIdentity = %v; want ErrOAuthEmailUnverified", err)
		}
	})

	t.Run("explicit false keeps the Graph email unverified", func(t *testing.T) {
		t.Parallel()
		user := fetch(t, boolPtr(false))
		if user.EmailVerified {
			t.Fatal("EmailVerified = true; want false when the operator does not assert it")
		}
		if err := validateProviderIdentity(user); !errors.Is(err, errors.ErrOAuthEmailUnverified) {
			t.Fatalf("validateProviderIdentity = %v; want ErrOAuthEmailUnverified", err)
		}
	})
}

func TestNewProviderPropagatesAuthoritySettings(t *testing.T) {
	t.Parallel()

	t.Run("microsoft tenant, allowlist and jwks ttl reach the adapter", func(t *testing.T) {
		t.Parallel()
		p, err := NewProvider("microsoft", config.ProviderConfig{
			ClientID:       "ms-id",
			ClientSecret:   "ms-secret",
			RedirectURL:    "https://app.example.com/cb",
			Tenant:         "tenant-guid",
			TrustedTenants: []string{"partner-guid"},
			JWKSCacheTTL:   2 * time.Hour,
		})
		if err != nil {
			t.Fatalf("NewProvider(microsoft) = %v", err)
		}
		ms, ok := p.(*MicrosoftProvider)
		if !ok {
			t.Fatalf("provider type = %T; want *MicrosoftProvider", p)
		}
		if ms.cfg.Tenant != "tenant-guid" {
			t.Errorf("cfg.Tenant = %q; want tenant-guid", ms.cfg.Tenant)
		}
		if _, ok := ms.trustedTenants["partner-guid"]; !ok {
			t.Errorf("trustedTenants = %v; want partner-guid", ms.trustedTenants)
		}
		if ms.jwksMgr.ttl != 2*time.Hour {
			t.Errorf("jwks ttl = %v; want 2h", ms.jwksMgr.ttl)
		}
		if !strings.Contains(ms.authURL, "/tenant-guid/") {
			t.Errorf("authURL = %q; want tenant-guid authority", ms.authURL)
		}
	})

	t.Run("microsoft empty tenant keeps common and no allowlist", func(t *testing.T) {
		t.Parallel()
		p, err := NewProvider("microsoft", config.ProviderConfig{
			ClientID:     "ms-id",
			ClientSecret: "ms-secret",
			RedirectURL:  "https://app.example.com/cb",
		})
		if err != nil {
			t.Fatalf("NewProvider(microsoft) = %v", err)
		}
		ms := p.(*MicrosoftProvider)
		if !strings.Contains(ms.authURL, "/common/") {
			t.Errorf("authURL = %q; want common authority", ms.authURL)
		}
		if len(ms.trustedTenants) != 0 {
			t.Errorf("trustedTenants = %v; want empty (no allowlist)", ms.trustedTenants)
		}
		if ms.jwksMgr.ttl != 24*time.Hour {
			t.Errorf("jwks ttl = %v; want 24h default", ms.jwksMgr.ttl)
		}
	})

	t.Run("facebook graph version reaches the adapter", func(t *testing.T) {
		t.Parallel()
		p, err := NewProvider("facebook", config.ProviderConfig{
			ClientID:     "fb-id",
			ClientSecret: "fb-secret",
			RedirectURL:  "https://app.example.com/cb",
			GraphVersion: "v20.0",
		})
		if err != nil {
			t.Fatalf("NewProvider(facebook) = %v", err)
		}
		fb, ok := p.(*FacebookProvider)
		if !ok {
			t.Fatalf("provider type = %T; want *FacebookProvider", p)
		}
		if fb.cfg.GraphVersion != "v20.0" {
			t.Errorf("cfg.GraphVersion = %q; want v20.0", fb.cfg.GraphVersion)
		}
		if !strings.Contains(fb.authURL, "/v20.0/") {
			t.Errorf("authURL = %q; want v20.0 graph version", fb.authURL)
		}
	})
}

func TestProviderHTTPHelpers(t *testing.T) {
	t.Parallel()

	serve := func(t *testing.T, h http.HandlerFunc) string {
		t.Helper()
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		return srv.URL
	}
	mustProviderMessage := func(t *testing.T, err error, want string) {
		t.Helper()
		requireProviderError(t, err)
		var appErr *errors.Error
		if !errors.As(err, &appErr) {
			t.Fatalf("error type = %T; want *errors.Error", err)
		}
		if got := appErr.Message(); got != want {
			t.Fatalf("message = %q; want %q", got, want)
		}
	}

	t.Run("object body decodes with bearer auth", func(t *testing.T) {
		t.Parallel()
		url := serve(t, func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer at-1" {
				t.Errorf("Authorization = %q; want bearer token", got)
			}
			if got := r.Header.Get("Accept"); got != "application/json" {
				t.Errorf("Accept = %q; want application/json", got)
			}
			_, _ = io.WriteString(w, `{"sub":"1","email":"a@b.c"}`)
		})
		raw, err := getJSON(context.Background(), http.DefaultClient, url, "at-1")
		if err != nil {
			t.Fatalf("getJSON = %v", err)
		}
		if raw["sub"] != "1" {
			t.Fatalf("sub = %v; want 1", raw["sub"])
		}
	})

	t.Run("array body decodes", func(t *testing.T) {
		t.Parallel()
		url := serve(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `[{"email":"a@b.c","primary":true}]`)
		})
		raw, err := getJSONArray(context.Background(), http.DefaultClient, url, "at-1")
		if err != nil {
			t.Fatalf("getJSONArray = %v", err)
		}
		if len(raw) != 1 {
			t.Fatalf("len = %d; want 1", len(raw))
		}
	})

	t.Run("status error carries the status", func(t *testing.T) {
		t.Parallel()
		url := serve(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		_, err := getJSON(context.Background(), http.DefaultClient, url, "at-1")
		mustProviderMessage(t, err, "oauth provider responded with status 500")
	})

	t.Run("invalid json rejected", func(t *testing.T) {
		t.Parallel()
		url := serve(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{oops`)
		})
		_, err := getJSON(context.Background(), http.DefaultClient, url, "at-1")
		mustProviderMessage(t, err, "oauth provider returned invalid response")
	})

	t.Run("empty body rejected", func(t *testing.T) {
		t.Parallel()
		url := serve(t, func(w http.ResponseWriter, r *http.Request) {})
		_, err := getJSON(context.Background(), http.DefaultClient, url, "at-1")
		mustProviderMessage(t, err, "oauth provider returned invalid response")
	})

	t.Run("null body rejected", func(t *testing.T) {
		t.Parallel()
		url := serve(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `null`)
		})
		_, err := getJSONArray(context.Background(), http.DefaultClient, url, "at-1")
		mustProviderMessage(t, err, "oauth provider returned invalid response")
	})

	t.Run("body over the cap is truncated", func(t *testing.T) {
		t.Parallel()
		url := serve(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"sub":"`)
			_, _ = io.WriteString(w, strings.Repeat("x", oauthBodyLimit+1))
			_, _ = io.WriteString(w, `"}`)
		})
		_, err := getJSON(context.Background(), http.DefaultClient, url, "at-1")
		mustProviderMessage(t, err, "oauth provider returned invalid response")
	})
}

// TestPostTokenFormKeepsProviderErrorOutOfMessage pins the same boundary the X
// adapter keeps: a token response carrying an OAuth error is reported to the
// client generically, with error and error_description preserved in the cause
// for server-side logs.
func TestPostTokenFormKeepsProviderErrorOutOfMessage(t *testing.T) {
	t.Parallel()

	const genericMessage = "oauth token exchange failed"

	exchange := func(t *testing.T, body string) (*TokenResponse, error) {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(srv.Close)
		return postTokenForm(context.Background(), srv.Client(), srv.URL, "grant_type=authorization_code")
	}

	tests := []struct {
		name    string
		body    string
		details []string
	}{
		{
			name:    "error and description",
			body:    `{"error":"invalid_grant","error_description":"AADSTS70008: the refresh token has expired"}`,
			details: []string{"invalid_grant", "AADSTS70008: the refresh token has expired"},
		},
		{
			name:    "error code alone",
			body:    `{"error":"invalid_client"}`,
			details: []string{"invalid_client"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tok, err := exchange(t, tt.body)
			if tok != nil {
				t.Fatalf("token = %v; want nil for a provider error body", tok)
			}
			requireProviderError(t, err)

			var appErr *errors.Error
			if !errors.As(err, &appErr) {
				t.Fatalf("error type = %T; want *errors.Error", err)
			}
			if got := appErr.Message(); got != genericMessage {
				t.Fatalf("message = %q; want %q", got, genericMessage)
			}
			for _, detail := range tt.details {
				if strings.Contains(appErr.Message(), detail) {
					t.Errorf("message = %q; the provider detail %q must not be client-visible", appErr.Message(), detail)
				}
				if !strings.Contains(err.Error(), detail) {
					t.Errorf("error = %v; want %q kept in the cause chain", err, detail)
				}
			}
		})
	}
}
