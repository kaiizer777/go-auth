package goauth

import (
	"encoding/json"
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

// validatedOAuthConfig builds a valid config and runs the startup validation so
// provider tests exercise the same config production wires.
func validatedOAuthConfig(t *testing.T, mutate func(*config.Config)) config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://auth.example.com"
	cfg.OAuth.StateSecret = "test-state-secret-at-least-32-bytes!"
	mutate(&cfg)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate = %v", err)
	}
	return cfg
}

func openTestSQLite(t *testing.T) *gorm.DB {
	t.Helper()
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
	return sqliteDB
}

func microsoftAuthority(t *testing.T, p oauth.Provider) string {
	t.Helper()
	u, err := url.Parse(p.AuthURL("state", "challenge"))
	if err != nil {
		t.Fatalf("invalid microsoft auth url: %v", err)
	}
	if u.Host != "login.microsoftonline.com" {
		t.Fatalf("microsoft auth host = %q; want login.microsoftonline.com", u.Host)
	}
	// Path is /{tenant}/oauth2/v2.0/authorize.
	segments := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(segments) < 2 || segments[1] != "oauth2" {
		t.Fatalf("microsoft auth path = %q; want /{tenant}/oauth2/...", u.Path)
	}
	return segments[0]
}

func TestNewOAuthProviders_RegistersTypedConfigsWithoutMapEntries(t *testing.T) {
	t.Parallel()

	cfg := validatedOAuthConfig(t, func(c *config.Config) {
		c.OAuth.Microsoft = &config.MicrosoftConfig{
			ClientID:       "ms-id",
			ClientSecret:   "ms-secret",
			Tenant:         "11111111-1111-1111-1111-111111111111",
			TrustedTenants: []string{"partner-guid"},
			RedirectURI:    "https://app.example.com/ms",
			JWKSCacheTTL:   3 * time.Hour,
		}
		c.OAuth.Facebook = &config.FacebookConfig{
			AppID:        "fb-id",
			AppSecret:    "fb-secret",
			RedirectURI:  "https://app.example.com/fb",
			GraphVersion: "v20.0",
		}
		c.OAuth.Discord = &config.DiscordConfig{
			ClientID:     "dc-id",
			ClientSecret: "dc-secret",
			RedirectURI:  "https://app.example.com/dc",
		}
		c.OAuth.X = &config.XConfig{
			ClientID:     "x-id",
			ClientSecret: "x-secret",
			RedirectURI:  "https://app.example.com/x",
		}
	})

	providers, err := newOAuthProviders(cfg.OAuth)
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

	msQuery, _ := providerQuery(t, providers["microsoft"])
	if msQuery.Get("client_id") != "ms-id" {
		t.Errorf("microsoft client_id = %q; want ms-id", msQuery.Get("client_id"))
	}
	if got := microsoftAuthority(t, providers["microsoft"]); got != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("microsoft authority = %q; want typed guid", got)
	}

	fbQuery, fbPath := providerQuery(t, providers["facebook"])
	if fbQuery.Get("client_id") != "fb-id" {
		t.Errorf("facebook client_id = %q; want fb-id", fbQuery.Get("client_id"))
	}
	if !strings.Contains(fbPath, "/v20.0/") {
		t.Errorf("facebook auth path = %q; want v20.0", fbPath)
	}
}

func TestNewOAuthProviders_MapGraphVersionReachesProvider(t *testing.T) {
	t.Parallel()

	cfg := validatedOAuthConfig(t, func(c *config.Config) {
		c.OAuth.Providers = map[string]config.ProviderConfig{
			"facebook": {
				Enabled:      true,
				ClientID:     "fb-id",
				ClientSecret: "fb-secret",
				RedirectURL:  "https://app.example.com/fb",
				GraphVersion: "v21.0",
			},
		}
	})

	providers, err := newOAuthProviders(cfg.OAuth)
	if err != nil {
		t.Fatalf("newOAuthProviders = %v", err)
	}
	fb, ok := providers["facebook"]
	if !ok {
		t.Fatal("missing facebook provider")
	}
	if _, fbPath := providerQuery(t, fb); !strings.Contains(fbPath, "/v21.0/") {
		t.Errorf("facebook auth path = %q; want v21.0", fbPath)
	}
}

func TestNewOAuthProviders_TenantPrecedence(t *testing.T) {
	t.Parallel()

	t.Run("map tenant survives a typed section that omits it", func(t *testing.T) {
		t.Parallel()
		cfg := validatedOAuthConfig(t, func(c *config.Config) {
			c.OAuth.Providers = map[string]config.ProviderConfig{
				"microsoft": {
					ClientID:     "map-id",
					ClientSecret: "map-secret",
					RedirectURL:  "https://map.example/cb",
					Enabled:      true,
					Tenant:       "corp-guid",
				},
			}
			c.OAuth.Microsoft = &config.MicrosoftConfig{
				ClientID:     "typed-id",
				ClientSecret: "typed-secret",
				RedirectURI:  "https://typed.example/cb",
			}
		})

		providers, err := newOAuthProviders(cfg.OAuth)
		if err != nil {
			t.Fatalf("newOAuthProviders = %v", err)
		}
		if len(providers) != 1 {
			t.Fatalf("providers = %d; want 1 (no double registration)", len(providers))
		}
		if got := microsoftAuthority(t, providers["microsoft"]); got != "corp-guid" {
			t.Errorf("microsoft authority = %q; want corp-guid", got)
		}
	})

	t.Run("typed tenant wins over the map entry", func(t *testing.T) {
		t.Parallel()
		cfg := validatedOAuthConfig(t, func(c *config.Config) {
			c.OAuth.Providers = map[string]config.ProviderConfig{
				"microsoft": {
					ClientID:     "map-id",
					ClientSecret: "map-secret",
					RedirectURL:  "https://map.example/cb",
					Enabled:      true,
					Tenant:       "map-guid",
				},
			}
			c.OAuth.Microsoft = &config.MicrosoftConfig{
				ClientID:     "typed-id",
				ClientSecret: "typed-secret",
				RedirectURI:  "https://typed.example/cb",
				Tenant:       "22222222-2222-2222-2222-222222222222",
			}
		})

		providers, err := newOAuthProviders(cfg.OAuth)
		if err != nil {
			t.Fatalf("newOAuthProviders = %v", err)
		}
		if got := microsoftAuthority(t, providers["microsoft"]); got != "22222222-2222-2222-2222-222222222222" {
			t.Errorf("microsoft authority = %q; want typed guid", got)
		}
	})

	t.Run("json map tenant survives defaults", func(t *testing.T) {
		t.Parallel()
		raw := `{
			"DatabaseURL": "postgres://user:pass@localhost:5432/testdb",
			"BaseURL": "https://auth.example.com",
			"OAuth": {
				"StateSecret": "test-state-secret-at-least-32-bytes!",
				"Providers": {
					"microsoft": {
						"ClientID": "map-id",
						"ClientSecret": "map-secret",
						"RedirectURL": "https://auth.example.com/auth/oauth/microsoft/callback",
						"Enabled": true,
						"tenant": "corp-guid"
					}
				}
			}
		}`
		cfg := config.DefaultConfig()
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			t.Fatalf("unmarshal config: %v", err)
		}

		a, err := NewWithDB(openTestSQLite(t), cfg)
		if err != nil {
			t.Fatalf("NewWithDB = %v", err)
		}
		defer func() { _ = a.Close() }()

		providers, err := newOAuthProviders(a.cfg.OAuth)
		if err != nil {
			t.Fatalf("newOAuthProviders = %v", err)
		}
		p, ok := providers["microsoft"]
		if !ok {
			t.Fatal("json map entry did not register a microsoft provider")
		}
		if got := microsoftAuthority(t, p); got != "corp-guid" {
			t.Errorf("microsoft authority = %q; want corp-guid", got)
		}
	})
}

func TestNewOAuthProviders_EnabledPrecedence(t *testing.T) {
	t.Parallel()

	microsoftTyped := func(enable *bool) *config.MicrosoftConfig {
		return &config.MicrosoftConfig{
			ClientID:     "typed-id",
			ClientSecret: "typed-secret",
			RedirectURI:  "https://typed.example/cb",
			Enabled:      enable,
		}
	}
	disabledMapEntry := func() map[string]config.ProviderConfig {
		return map[string]config.ProviderConfig{
			"microsoft": {
				ClientID:     "map-id",
				ClientSecret: "map-secret",
				RedirectURL:  "https://map.example/cb",
				Enabled:      false,
			},
		}
	}

	t.Run("map entry enabled false vetoes a typed provider", func(t *testing.T) {
		t.Parallel()
		cfg := validatedOAuthConfig(t, func(c *config.Config) {
			c.OAuth.Providers = disabledMapEntry()
			c.OAuth.Microsoft = microsoftTyped(nil)
		})
		providers, err := newOAuthProviders(cfg.OAuth)
		if err != nil {
			t.Fatalf("newOAuthProviders = %v", err)
		}
		if len(providers) != 0 {
			t.Fatalf("providers = %v; want none", providers)
		}
	})

	t.Run("typed enabled false vetoes an enabled map entry", func(t *testing.T) {
		t.Parallel()
		off := false
		cfg := validatedOAuthConfig(t, func(c *config.Config) {
			c.OAuth.Providers = map[string]config.ProviderConfig{
				"microsoft": {
					ClientID:     "map-id",
					ClientSecret: "map-secret",
					RedirectURL:  "https://map.example/cb",
					Enabled:      true,
				},
			}
			c.OAuth.Microsoft = microsoftTyped(&off)
		})
		providers, err := newOAuthProviders(cfg.OAuth)
		if err != nil {
			t.Fatalf("newOAuthProviders = %v", err)
		}
		if len(providers) != 0 {
			t.Fatalf("providers = %v; want none", providers)
		}
	})

	t.Run("disabled map entry alone stays unregistered", func(t *testing.T) {
		t.Parallel()
		cfg := validatedOAuthConfig(t, func(c *config.Config) {
			c.OAuth.Providers = disabledMapEntry()
		})
		providers, err := newOAuthProviders(cfg.OAuth)
		if err != nil {
			t.Fatalf("newOAuthProviders = %v", err)
		}
		if len(providers) != 0 {
			t.Fatalf("providers = %v; want none", providers)
		}
	})
}

func TestNewWithDB_RegistersTypedOAuthProviders(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://auth.example.com"
	cfg.OAuth.StateSecret = "test-state-secret-at-least-32-bytes!"
	cfg.OAuth.Microsoft = &config.MicrosoftConfig{
		ClientID:       "ms-id",
		ClientSecret:   "ms-secret",
		Tenant:         "11111111-1111-1111-1111-111111111111",
		TrustedTenants: []string{"partner-guid"},
		RedirectURI:    "https://auth.example.com/auth/oauth/microsoft/callback",
	}

	a, err := NewWithDB(openTestSQLite(t), cfg)
	if err != nil {
		t.Fatalf("NewWithDB = %v", err)
	}
	defer func() { _ = a.Close() }()

	if a.OAuth == nil {
		t.Fatal("typed-only microsoft config did not register a provider")
	}
}
