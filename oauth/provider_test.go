package oauth

import (
	"net/http"
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
	if len(SupportedProviders) != 3 {
		t.Fatalf("len = %d; want 3", len(SupportedProviders))
	}
	for _, id := range []string{"google", "github", "apple"} {
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
