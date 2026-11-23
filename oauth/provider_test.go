package oauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	}
}

func TestNewProvider(t *testing.T) {
	t.Parallel()
	cfg := config.ProviderConfig{ClientID: "id", ClientSecret: "secret", RedirectURL: "https://app.example.com/cb"}

	t.Run("big 3 resolve with matching IDs", func(t *testing.T) {
		t.Parallel()
		for _, id := range []string{"google", "github", "apple"} {
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

	t.Run("deferred and unknown reject with 404", func(t *testing.T) {
		t.Parallel()
		for _, id := range []string{"discord", "microsoft", "facebook", ""} {
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
