package goauth

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/oauth"
)

func providerQuery(t *testing.T, p oauth.Provider) (url.Values, string) {
	t.Helper()
	u, err := url.Parse(p.AuthURL("state", "challenge"))
	if err != nil {
		t.Fatalf("invalid auth url for %q: %v", p.ID(), err)
	}
	return u.Query(), u.Path
}

func TestNewOAuthProviders_RegistersTypedConfigsWithoutMapEntries(t *testing.T) {
	t.Parallel()

	providers, err := newOAuthProviders(config.OAuthConfig{
		Microsoft: &config.MicrosoftConfig{
			ClientID:       "ms-id",
			ClientSecret:   "ms-secret",
			Tenant:         "tenant-guid",
			TrustedTenants: []string{"partner-guid"},
			RedirectURI:    "https://app.example.com/ms",
			JWKSCacheTTL:   3 * time.Hour,
		},
		Facebook: &config.FacebookConfig{
			AppID:        "fb-id",
			AppSecret:    "fb-secret",
			RedirectURI:  "https://app.example.com/fb",
			GraphVersion: "v20.0",
		},
		Discord: &config.DiscordConfig{
			ClientID:     "dc-id",
			ClientSecret: "dc-secret",
			RedirectURI:  "https://app.example.com/dc",
		},
		X: &config.XConfig{
			ClientID:     "x-id",
			ClientSecret: "x-secret",
			RedirectURI:  "https://app.example.com/x",
		},
	})
	if err != nil {
		t.Fatalf("newOAuthProviders = %v", err)
	}
	if len(providers) != 4 {
		t.Fatalf("providers = %d; want 4", len(providers))
	}
	for _, id := range []string{"microsoft", "facebook", "discord", "x"} {
		p, ok := providers[id]
		if !ok {
			t.Fatalf("missing provider %q", id)
		}
		if p.ID() != id {
			t.Errorf("ID() = %q; want %q", p.ID(), id)
		}
	}

	msQuery, msPath := providerQuery(t, providers["microsoft"])
	if msQuery.Get("client_id") != "ms-id" {
		t.Errorf("microsoft client_id = %q; want ms-id", msQuery.Get("client_id"))
	}
	if !strings.Contains(msPath, "/tenant-guid/") {
		t.Errorf("microsoft auth path = %q; want tenant-guid authority", msPath)
	}

	fbQuery, fbPath := providerQuery(t, providers["facebook"])
	if fbQuery.Get("client_id") != "fb-id" {
		t.Errorf("facebook client_id = %q; want fb-id", fbQuery.Get("client_id"))
	}
	if !strings.Contains(fbPath, "/v20.0/") {
		t.Errorf("facebook auth path = %q; want v20.0", fbPath)
	}
}

func TestOAuthProviderConfigs_Precedence(t *testing.T) {
	t.Parallel()

	t.Run("non-zero typed fields overlay the map entry and register once", func(t *testing.T) {
		t.Parallel()
		providers, err := newOAuthProviders(config.OAuthConfig{
			Providers: map[string]config.ProviderConfig{
				"microsoft": {
					ClientID:     "map-id",
					ClientSecret: "map-secret",
					RedirectURL:  "https://map.example/cb",
					Enabled:      true,
					Tenant:       "map-tenant",
				},
			},
			Microsoft: &config.MicrosoftConfig{
				ClientID:     "typed-id",
				ClientSecret: "typed-secret",
				RedirectURI:  "https://typed.example/cb",
				Tenant:       "typed-tenant",
			},
		})
		if err != nil {
			t.Fatalf("newOAuthProviders = %v", err)
		}
		if len(providers) != 1 {
			t.Fatalf("providers = %d; want 1 (no double registration)", len(providers))
		}
		query, path := providerQuery(t, providers["microsoft"])
		if query.Get("client_id") != "typed-id" {
			t.Errorf("client_id = %q; want typed-id", query.Get("client_id"))
		}
		if query.Get("redirect_uri") != "https://typed.example/cb" {
			t.Errorf("redirect_uri = %q; want typed https://typed.example/cb", query.Get("redirect_uri"))
		}
		if !strings.Contains(path, "/typed-tenant/") {
			t.Errorf("auth path = %q; want typed-tenant authority", path)
		}
	})

	t.Run("typed fields left zero inherit the map entry", func(t *testing.T) {
		t.Parallel()
		providers, err := newOAuthProviders(config.OAuthConfig{
			Providers: map[string]config.ProviderConfig{
				"microsoft": {
					ClientID:     "map-id",
					ClientSecret: "map-secret",
					RedirectURL:  "https://map.example/cb",
					Enabled:      true,
				},
			},
			Microsoft: &config.MicrosoftConfig{
				ClientID: "typed-id",
				Tenant:   "typed-tenant",
			},
		})
		if err != nil {
			t.Fatalf("newOAuthProviders = %v", err)
		}
		query, _ := providerQuery(t, providers["microsoft"])
		if query.Get("client_id") != "typed-id" {
			t.Errorf("client_id = %q; want typed-id", query.Get("client_id"))
		}
		if query.Get("redirect_uri") != "https://map.example/cb" {
			t.Errorf("redirect_uri = %q; want inherited https://map.example/cb", query.Get("redirect_uri"))
		}
	})

	t.Run("disabled map entry alone stays unregistered", func(t *testing.T) {
		t.Parallel()
		providers, err := newOAuthProviders(config.OAuthConfig{
			Providers: map[string]config.ProviderConfig{
				"microsoft": {
					ClientID:     "map-id",
					ClientSecret: "map-secret",
					RedirectURL:  "https://map.example/cb",
					Enabled:      false,
				},
			},
		})
		if err != nil {
			t.Fatalf("newOAuthProviders = %v", err)
		}
		if len(providers) != 0 {
			t.Fatalf("providers = %v; want none", providers)
		}
	})

	t.Run("typed config registers over a disabled map entry", func(t *testing.T) {
		t.Parallel()
		providers, err := newOAuthProviders(config.OAuthConfig{
			Providers: map[string]config.ProviderConfig{
				"microsoft": {
					ClientID:     "map-id",
					ClientSecret: "map-secret",
					RedirectURL:  "https://map.example/cb",
					Enabled:      false,
				},
			},
			Microsoft: &config.MicrosoftConfig{
				ClientID:     "typed-id",
				ClientSecret: "typed-secret",
				RedirectURI:  "https://typed.example/cb",
			},
		})
		if err != nil {
			t.Fatalf("newOAuthProviders = %v", err)
		}
		if len(providers) != 1 {
			t.Fatalf("providers = %d; want 1", len(providers))
		}
	})

	t.Run("typed config without client id is ignored entirely", func(t *testing.T) {
		t.Parallel()
		providers, err := newOAuthProviders(config.OAuthConfig{
			Providers: map[string]config.ProviderConfig{
				"microsoft": {
					ClientID:     "map-id",
					ClientSecret: "map-secret",
					RedirectURL:  "https://map.example/cb",
					Enabled:      true,
				},
			},
			Microsoft: &config.MicrosoftConfig{Tenant: "typed-tenant"},
		})
		if err != nil {
			t.Fatalf("newOAuthProviders = %v", err)
		}
		query, path := providerQuery(t, providers["microsoft"])
		if query.Get("client_id") != "map-id" {
			t.Errorf("client_id = %q; want map-id", query.Get("client_id"))
		}
		if !strings.Contains(path, "/common/") {
			t.Errorf("auth path = %q; want common (typed config not applied)", path)
		}
	})
}
