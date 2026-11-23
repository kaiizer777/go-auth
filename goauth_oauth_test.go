package goauth

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

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

func TestNewWithDB_RegistersTypedOAuthProviders(t *testing.T) {
	sqliteDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, dbErr := sqliteDB.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	})

	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		credential_version INTEGER NOT NULL DEFAULT 0,
		email_verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		id_hash CHAR(64) UNIQUE NOT NULL,
		session_type VARCHAR(10) NOT NULL DEFAULT 'cookie',
		ip_address VARCHAR(45) NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '',
		credential_version INTEGER NOT NULL DEFAULT 0,
		last_active_at DATETIME NOT NULL,
		absolute_expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	`
	if err := sqliteDB.Exec(ddl).Error; err != nil {
		t.Fatalf("failed to execute sqlite ddl: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://auth.example.com"
	cfg.OAuth.StateSecret = "test-state-secret-at-least-32-bytes!"
	cfg.OAuth.Microsoft = &config.MicrosoftConfig{
		ClientID:       "ms-id",
		ClientSecret:   "ms-secret",
		Tenant:         "tenant-guid",
		TrustedTenants: []string{"partner-guid"},
		RedirectURI:    "https://auth.example.com/auth/oauth/microsoft/callback",
	}

	a, err := NewWithDB(sqliteDB, cfg)
	if err != nil {
		t.Fatalf("NewWithDB = %v", err)
	}
	defer func() { _ = a.Close() }()

	if a.OAuth == nil {
		t.Fatal("typed-only microsoft config did not register a provider")
	}
}
