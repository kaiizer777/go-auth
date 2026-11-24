package config

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/errors"
)

func validOAuthBase() Config {
	cfg := DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	cfg.OAuth.StateSecret = "test-state-secret-at-least-32-bytes!"
	return cfg
}

func TestOAuthDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.OAuth.StateCookieName != "oauth_state" {
		t.Errorf("StateCookieName = %q; want oauth_state", cfg.OAuth.StateCookieName)
	}
	if cfg.OAuth.StateCookiePath != "/" {
		t.Errorf("StateCookiePath = %q; want /", cfg.OAuth.StateCookiePath)
	}
	if cfg.OAuth.StateTTL != 10*time.Minute {
		t.Errorf("StateTTL = %v; want 10m", cfg.OAuth.StateTTL)
	}
	if cfg.OAuth.StateCookieSameSite != http.SameSiteLaxMode {
		t.Errorf("StateCookieSameSite = %v; want Lax", cfg.OAuth.StateCookieSameSite)
	}
}

func TestConfigValidate_OAuth(t *testing.T) {
	enabled := func(id string, p ProviderConfig) map[string]ProviderConfig {
		p.Enabled = true
		return map[string]ProviderConfig{id: p}
	}
	appleKeys := ProviderConfig{
		ClientID:    "apple-client",
		RedirectURL: "https://example.com/auth/oauth/apple/callback",
		TeamID:      "ABCDE12345",
		KeyID:       "FGHIJ67890",
		PrivateKey:  "-----BEGIN PRIVATE KEY-----\nxyz\n-----END PRIVATE KEY-----",
	}

	tests := []struct {
		name                 string
		mutate               func(*Config)
		wantErr              *errors.Error
		wantTTL              time.Duration
		wantSameSite         http.SameSite
		wantMicrosoftTenant  string
		wantMicrosoftJWKSTTL time.Duration
	}{
		{
			name:    "no providers passes",
			mutate:  func(*Config) {},
			wantErr: nil,
		},
		{
			name: "disabled provider with empty fields passes",
			mutate: func(c *Config) {
				c.OAuth.Providers = map[string]ProviderConfig{"google": {}}
			},
			wantErr: nil,
		},
		{
			name: "enabled google passes",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("google", ProviderConfig{
					ClientID:     "gid",
					ClientSecret: "gsecret",
					RedirectURL:  "https://example.com/auth/oauth/google/callback",
				})
			},
			wantErr: nil,
		},
		{
			name: "enabled github passes",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("github", ProviderConfig{
					ClientID:     "hid",
					ClientSecret: "hsecret",
					RedirectURL:  "https://example.com/auth/oauth/github/callback",
				})
			},
			wantErr: nil,
		},
		{
			name: "apple with team keys and no secret passes",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("apple", appleKeys)
			},
			wantErr: nil,
		},
		{
			name: "apple with static secret passes",
			mutate: func(c *Config) {
				p := appleKeys
				p.TeamID, p.KeyID, p.PrivateKey = "", "", ""
				p.ClientSecret = "apple-secret"
				c.OAuth.Providers = enabled("apple", p)
			},
			wantErr: nil,
		},
		{
			name: "unknown provider rejected",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("unsupported-idp", ProviderConfig{
					ClientID:     "did",
					ClientSecret: "dsecret",
					RedirectURL:  "https://example.com/callback",
				})
			},
			wantErr: errors.ErrOAuthProviderUnknown,
		},
		{
			name: "enabled provider missing client id rejected",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("google", ProviderConfig{
					ClientSecret: "gsecret",
					RedirectURL:  "https://example.com/callback",
				})
			},
			wantErr: errors.ErrOAuthClientIDRequired,
		},
		{
			name: "enabled provider missing redirect rejected",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("google", ProviderConfig{
					ClientID:     "gid",
					ClientSecret: "gsecret",
				})
			},
			wantErr: errors.ErrOAuthRedirectURLRequired,
		},
		{
			name: "google missing secret rejected",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("google", ProviderConfig{
					ClientID:    "gid",
					RedirectURL: "https://example.com/callback",
				})
			},
			wantErr: errors.ErrOAuthClientSecretRequired,
		},
		{
			name: "github missing secret rejected",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("github", ProviderConfig{
					ClientID:    "hid",
					RedirectURL: "https://example.com/callback",
				})
			},
			wantErr: errors.ErrOAuthClientSecretRequired,
		},
		{
			name: "apple missing secret and keys rejected",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("apple", ProviderConfig{
					ClientID:    "aid",
					RedirectURL: "https://example.com/callback",
				})
			},
			wantErr: errors.ErrOAuthClientSecretRequired,
		},
		{
			name: "apple partial keys rejected",
			mutate: func(c *Config) {
				p := appleKeys
				p.PrivateKey = ""
				c.OAuth.Providers = enabled("apple", p)
			},
			wantErr: errors.ErrOAuthClientSecretRequired,
		},
		{
			name: "negative state TTL rejected",
			mutate: func(c *Config) {
				c.OAuth.StateTTL = -time.Minute
			},
			wantErr: errors.ErrOAuthStateTTLInvalid,
		},
		{
			name: "sub-second state TTL rejected",
			mutate: func(c *Config) {
				c.OAuth.StateTTL = 500 * time.Millisecond
			},
			wantErr: errors.ErrOAuthStateTTLInvalid,
		},
		{
			name: "zero state TTL defaults",
			mutate: func(c *Config) {
				c.OAuth.StateTTL = 0
			},
			wantErr: nil,
			wantTTL: 10 * time.Minute,
		},
		{
			name: "zero state SameSite defaults to Lax",
			mutate: func(c *Config) {
				c.OAuth.StateCookieSameSite = 0
			},
			wantErr:      nil,
			wantSameSite: http.SameSiteLaxMode,
		},
		{
			name: "short state secret rejected",
			mutate: func(c *Config) {
				c.OAuth.StateSecret = "x"
			},
			wantErr: errors.ErrOAuthStateSecretTooShort,
		},
		{
			name: "enabled provider without state secret rejected",
			mutate: func(c *Config) {
				c.OAuth.StateSecret = ""
				c.OAuth.Providers = enabled("google", ProviderConfig{
					ClientID:     "gid",
					ClientSecret: "gsecret",
					RedirectURL:  "https://example.com/auth/oauth/google/callback",
				})
			},
			wantErr: errors.ErrOAuthStateSecretRequired,
		},
		{
			name: "no providers without secret passes",
			mutate: func(c *Config) {
				c.OAuth.StateSecret = ""
			},
			wantErr: nil,
		},
		{
			name: "disabled provider without secret passes",
			mutate: func(c *Config) {
				c.OAuth.StateSecret = ""
				c.OAuth.Providers = map[string]ProviderConfig{"google": {}}
			},
			wantErr: nil,
		},
		{
			name: "bad state cookie name rejected",
			mutate: func(c *Config) {
				c.OAuth.StateCookieName = "bad name"
			},
			wantErr: errors.ErrOAuthStateCookieNameInvalid,
		},
		{
			name: "state cookie name collides with session cookie rejected",
			mutate: func(c *Config) {
				c.OAuth.StateCookieName = c.SessionCookieName
			},
			wantErr: errors.ErrOAuthStateCookieNameCollision,
		},
		{
			name: "state cookie name collides with CSRF cookie rejected",
			mutate: func(c *Config) {
				c.OAuth.StateCookieName = c.CSRFCookieName
			},
			wantErr: errors.ErrOAuthStateCookieNameCollision,
		},
		{
			name: "bad state cookie path rejected",
			mutate: func(c *Config) {
				c.OAuth.StateCookiePath = "relative/path"
			},
			wantErr: errors.ErrOAuthStateCookiePathInvalid,
		},
		{
			name: "microsoft config valid defaults",
			mutate: func(c *Config) {
				c.OAuth.Microsoft = &MicrosoftConfig{
					ClientID:     "ms-client-id",
					ClientSecret: "ms-client-secret",
					RedirectURI:  "https://example.com/callback",
				}
			},
			wantErr:              nil,
			wantMicrosoftTenant:  "common",
			wantMicrosoftJWKSTTL: 24 * time.Hour,
		},
		{
			name: "microsoft config missing client id rejected",
			mutate: func(c *Config) {
				c.OAuth.Microsoft = &MicrosoftConfig{
					ClientSecret: "ms-client-secret",
				}
			},
			wantErr: errors.ErrOAuthClientIDRequired,
		},
		{
			name: "microsoft config missing client secret rejected",
			mutate: func(c *Config) {
				c.OAuth.Microsoft = &MicrosoftConfig{
					ClientID: "ms-client-id",
				}
			},
			wantErr: errors.ErrOAuthClientSecretRequired,
		},
		{
			name: "microsoft config missing redirect uri rejected",
			mutate: func(c *Config) {
				c.OAuth.Microsoft = &MicrosoftConfig{
					ClientID:     "ms-client-id",
					ClientSecret: "ms-client-secret",
					RedirectURI:  "",
				}
			},
			wantErr: errors.ErrOAuthRedirectURLRequired,
		},
		{
			name: "microsoft config missing state secret rejected",
			mutate: func(c *Config) {
				c.OAuth.StateSecret = ""
				c.OAuth.Microsoft = &MicrosoftConfig{
					ClientID:     "ms-client-id",
					ClientSecret: "ms-client-secret",
				}
			},
			wantErr: errors.ErrOAuthStateSecretRequired,
		},
		{
			name: "microsoft uppercase tenant and trusted tenants normalised",
			mutate: func(c *Config) {
				c.OAuth.Microsoft = &MicrosoftConfig{
					ClientID:       "ms-client-id",
					ClientSecret:   "ms-client-secret",
					RedirectURI:    "https://example.com/callback",
					Tenant:         "  9188040D-6C67-4C5B-B112-36A304B66DAD  ",
					TrustedTenants: []string{"  PARTNER-GUID ", "", "contoso.onmicrosoft.com"},
				}
			},
			wantErr: nil,
		},
		{
			name: "microsoft garbage tenant rejected",
			mutate: func(c *Config) {
				c.OAuth.Microsoft = &MicrosoftConfig{
					ClientID:     "ms-client-id",
					ClientSecret: "ms-client-secret",
					RedirectURI:  "https://example.com/callback",
					Tenant:       "not a tenant!!",
				}
			},
			wantErr: errors.ErrOAuthTenantInvalid,
		},
		{
			name: "microsoft bare single-label tenant rejected",
			mutate: func(c *Config) {
				c.OAuth.Microsoft = &MicrosoftConfig{
					ClientID:     "ms-client-id",
					ClientSecret: "ms-client-secret",
					RedirectURI:  "https://example.com/callback",
					Tenant:       "mytenant",
				}
			},
			wantErr: errors.ErrOAuthTenantInvalid,
		},
		{
			name: "microsoft provider map allowed",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("microsoft", ProviderConfig{
					ClientID:     "ms-client-id",
					ClientSecret: "ms-client-secret",
					RedirectURL:  "https://example.com/callback",
				})
			},
			wantErr: nil,
		},
		{
			name: "disabled unknown provider rejected",
			mutate: func(c *Config) {
				c.OAuth.Providers = map[string]ProviderConfig{"unsupported-idp": {}}
			},
			wantErr: errors.ErrOAuthProviderUnknown,
		},
		{
			name: "discord enabled valid defaults scopes",
			mutate: func(c *Config) {
				c.OAuth.Discord = &DiscordConfig{
					ClientID:     "discord-id",
					ClientSecret: "discord-secret",
					RedirectURI:  "https://example.com/callback",
				}
			},
			wantErr: nil,
		},
		{
			name: "discord missing client id rejected",
			mutate: func(c *Config) {
				c.OAuth.Discord = &DiscordConfig{
					ClientID:     "",
					ClientSecret: "discord-secret",
					RedirectURI:  "https://example.com/callback",
				}
			},
			wantErr: errors.ErrOAuthClientIDRequired,
		},
		{
			name: "discord missing client secret rejected",
			mutate: func(c *Config) {
				c.OAuth.Discord = &DiscordConfig{
					ClientID:     "discord-id",
					ClientSecret: "",
					RedirectURI:  "https://example.com/callback",
				}
			},
			wantErr: errors.ErrOAuthClientSecretRequired,
		},
		{
			name: "discord missing redirect uri rejected",
			mutate: func(c *Config) {
				c.OAuth.Discord = &DiscordConfig{
					ClientID:     "discord-id",
					ClientSecret: "discord-secret",
					RedirectURI:  "",
				}
			},
			wantErr: errors.ErrOAuthRedirectURLRequired,
		},
		{
			name: "discord missing state secret rejected",
			mutate: func(c *Config) {
				c.OAuth.StateSecret = ""
				c.OAuth.Discord = &DiscordConfig{
					ClientID:     "discord-id",
					ClientSecret: "discord-secret",
					RedirectURI:  "https://example.com/callback",
				}
			},
			wantErr: errors.ErrOAuthStateSecretRequired,
		},
		{
			name: "facebook enabled valid defaults version and scopes",
			mutate: func(c *Config) {
				c.OAuth.Facebook = &FacebookConfig{
					AppID:       "fb-app-id",
					AppSecret:   "fb-app-secret",
					RedirectURI: "https://example.com/callback",
				}
			},
			wantErr: nil,
		},
		{
			name: "facebook missing app id rejected",
			mutate: func(c *Config) {
				c.OAuth.Facebook = &FacebookConfig{
					AppID:       "",
					AppSecret:   "fb-app-secret",
					RedirectURI: "https://example.com/callback",
				}
			},
			wantErr: errors.ErrOAuthClientIDRequired,
		},
		{
			name: "facebook missing app secret rejected",
			mutate: func(c *Config) {
				c.OAuth.Facebook = &FacebookConfig{
					AppID:       "fb-app-id",
					AppSecret:   "",
					RedirectURI: "https://example.com/callback",
				}
			},
			wantErr: errors.ErrOAuthClientSecretRequired,
		},
		{
			name: "facebook missing redirect uri rejected",
			mutate: func(c *Config) {
				c.OAuth.Facebook = &FacebookConfig{
					AppID:       "fb-app-id",
					AppSecret:   "fb-app-secret",
					RedirectURI: "",
				}
			},
			wantErr: errors.ErrOAuthRedirectURLRequired,
		},
		{
			name: "facebook invalid graph version missing v prefix rejected",
			mutate: func(c *Config) {
				c.OAuth.Facebook = &FacebookConfig{
					AppID:        "fb-app-id",
					AppSecret:    "fb-app-secret",
					RedirectURI:  "https://example.com/callback",
					GraphVersion: "19.0",
				}
			},
			wantErr: errors.ErrOAuthGraphVersionInvalid,
		},
		{
			name: "facebook invalid graph version below 19 rejected",
			mutate: func(c *Config) {
				c.OAuth.Facebook = &FacebookConfig{
					AppID:        "fb-app-id",
					AppSecret:    "fb-app-secret",
					RedirectURI:  "https://example.com/callback",
					GraphVersion: "v18.0",
				}
			},
			wantErr: errors.ErrOAuthGraphVersionInvalid,
		},
		{
			name: "facebook valid graph version 20 allowed",
			mutate: func(c *Config) {
				c.OAuth.Facebook = &FacebookConfig{
					AppID:        "fb-app-id",
					AppSecret:    "fb-app-secret",
					RedirectURI:  "https://example.com/callback",
					GraphVersion: "v20.0",
				}
			},
			wantErr: nil,
		},
		{
			name: "facebook map graph version missing v prefix rejected",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("facebook", ProviderConfig{
					ClientID:     "fb-app-id",
					ClientSecret: "fb-app-secret",
					RedirectURL:  "https://example.com/callback",
					GraphVersion: "18.0",
				})
			},
			wantErr: errors.ErrOAuthGraphVersionInvalid,
		},
		{
			name: "facebook map graph version below 19 rejected",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("facebook", ProviderConfig{
					ClientID:     "fb-app-id",
					ClientSecret: "fb-app-secret",
					RedirectURL:  "https://example.com/callback",
					GraphVersion: "v18.0",
				})
			},
			wantErr: errors.ErrOAuthGraphVersionInvalid,
		},
		{
			name: "facebook missing state secret rejected",
			mutate: func(c *Config) {
				c.OAuth.StateSecret = ""
				c.OAuth.Facebook = &FacebookConfig{
					AppID:       "fb-app-id",
					AppSecret:   "fb-app-secret",
					RedirectURI: "https://example.com/callback",
				}
			},
			wantErr: errors.ErrOAuthStateSecretRequired,
		},
		{
			name: "x enabled valid defaults scopes",
			mutate: func(c *Config) {
				c.OAuth.X = &XConfig{
					ClientID:     "x-id",
					ClientSecret: "x-secret",
					RedirectURI:  "https://example.com/callback",
				}
			},
			wantErr: nil,
		},
		{
			name: "x missing client id rejected",
			mutate: func(c *Config) {
				c.OAuth.X = &XConfig{
					ClientID:     "",
					ClientSecret: "x-secret",
					RedirectURI:  "https://example.com/callback",
				}
			},
			wantErr: errors.ErrOAuthClientIDRequired,
		},
		{
			name: "x missing client secret rejected",
			mutate: func(c *Config) {
				c.OAuth.X = &XConfig{
					ClientID:     "x-id",
					ClientSecret: "",
					RedirectURI:  "https://example.com/callback",
				}
			},
			wantErr: errors.ErrOAuthClientSecretRequired,
		},
		{
			name: "x missing redirect uri rejected",
			mutate: func(c *Config) {
				c.OAuth.X = &XConfig{
					ClientID:     "x-id",
					ClientSecret: "x-secret",
					RedirectURI:  "",
				}
			},
			wantErr: errors.ErrOAuthRedirectURLRequired,
		},
		{
			name: "x missing state secret rejected",
			mutate: func(c *Config) {
				c.OAuth.StateSecret = ""
				c.OAuth.X = &XConfig{
					ClientID:     "x-id",
					ClientSecret: "x-secret",
					RedirectURI:  "https://example.com/callback",
				}
			},
			wantErr: errors.ErrOAuthStateSecretRequired,
		},
		{
			name: "x provider map allowed",
			mutate: func(c *Config) {
				c.OAuth.Providers = enabled("x", ProviderConfig{
					ClientID:     "x-id",
					ClientSecret: "x-secret",
					RedirectURL:  "https://example.com/callback",
				})
			},
			wantErr: nil,
		},
		{
			name: "disabled microsoft section without credentials passes",
			mutate: func(c *Config) {
				off := false
				c.OAuth.Microsoft = &MicrosoftConfig{Enabled: &off}
			},
			wantErr: nil,
		},
		{
			name: "disabled discord section without credentials passes",
			mutate: func(c *Config) {
				off := false
				c.OAuth.Discord = &DiscordConfig{Enabled: &off}
			},
			wantErr: nil,
		},
		{
			name: "disabled facebook section without credentials passes",
			mutate: func(c *Config) {
				off := false
				c.OAuth.Facebook = &FacebookConfig{Enabled: &off}
			},
			wantErr: nil,
		},
		{
			name: "disabled x section without credentials passes",
			mutate: func(c *Config) {
				off := false
				c.OAuth.X = &XConfig{Enabled: &off}
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validOAuthBase()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate = %v; want nil", err)
				}
				if tt.wantTTL != 0 && cfg.OAuth.StateTTL != tt.wantTTL {
					t.Fatalf("StateTTL = %v; want %v", cfg.OAuth.StateTTL, tt.wantTTL)
				}
				if tt.wantSameSite != 0 && cfg.OAuth.StateCookieSameSite != tt.wantSameSite {
					t.Fatalf("StateCookieSameSite = %v; want %v", cfg.OAuth.StateCookieSameSite, tt.wantSameSite)
				}
				if tt.wantMicrosoftTenant != "" {
					if cfg.OAuth.Microsoft == nil || cfg.OAuth.Microsoft.Tenant != tt.wantMicrosoftTenant {
						t.Fatalf("Microsoft.Tenant = %v; want %v", cfg.OAuth.Microsoft, tt.wantMicrosoftTenant)
					}
				}
				if tt.wantMicrosoftJWKSTTL != 0 {
					if cfg.OAuth.Microsoft == nil || cfg.OAuth.Microsoft.JWKSCacheTTL != tt.wantMicrosoftJWKSTTL {
						t.Fatalf("Microsoft.JWKSCacheTTL = %v; want %v", cfg.OAuth.Microsoft, tt.wantMicrosoftJWKSTTL)
					}
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate = %v; want %v", err, tt.wantErr)
			}
			var appErr *errors.Error
			if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidConfig {
				t.Fatalf("Validate code = %v; want CONFIG_INVALID", err)
			}
		})
	}
}

func TestConfigValidate_MicrosoftTenantNormalisation(t *testing.T) {
	cfg := validOAuthBase()
	cfg.OAuth.Microsoft = &MicrosoftConfig{
		ClientID:       "ms-client-id",
		ClientSecret:   "ms-client-secret",
		RedirectURI:    "https://example.com/callback",
		Tenant:         "  ORGANIZATIONS  ",
		TrustedTenants: []string{"  PARTNER-GUID ", "", "Contoso.OnMicrosoft.com"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate = %v; want nil", err)
	}
	if cfg.OAuth.Microsoft.Tenant != "organizations" {
		t.Errorf("Tenant = %q; want lowercased organizations", cfg.OAuth.Microsoft.Tenant)
	}
	want := []string{"partner-guid", "contoso.onmicrosoft.com"}
	if len(cfg.OAuth.Microsoft.TrustedTenants) != len(want) {
		t.Fatalf("TrustedTenants = %q; want %q", cfg.OAuth.Microsoft.TrustedTenants, want)
	}
	for i := range want {
		if cfg.OAuth.Microsoft.TrustedTenants[i] != want[i] {
			t.Errorf("TrustedTenants[%d] = %q; want %q", i, cfg.OAuth.Microsoft.TrustedTenants[i], want[i])
		}
	}
}

func TestConfigValidate_MapMicrosoftTenantNormalisation(t *testing.T) {
	msMap := func(tenant string) map[string]ProviderConfig {
		return map[string]ProviderConfig{"microsoft": {
			ClientID:     "ms-client-id",
			ClientSecret: "ms-client-secret",
			RedirectURL:  "https://example.com/callback",
			Enabled:      true,
			Tenant:       tenant,
		}}
	}

	tests := []struct {
		name    string
		tenant  string
		want    string
		wantErr *errors.Error
	}{
		{name: "named authority lowercased", tenant: "Common", want: "common"},
		{name: "surrounding space trimmed", tenant: " common ", want: "common"},
		{name: "uppercase guid lowercased", tenant: "  9188040D-6C67-4C5B-B112-36A304B66DAD  ", want: "9188040d-6c67-4c5b-b112-36a304b66dad"},
		{name: "domain lowercased", tenant: "Contoso.OnMicrosoft.com", want: "contoso.onmicrosoft.com"},
		{name: "empty defaults to common", tenant: "", want: "common"},
		{name: "garbage rejected", tenant: "not a tenant!!", wantErr: errors.ErrOAuthTenantInvalid},
		{name: "single label rejected", tenant: "mytenant", wantErr: errors.ErrOAuthTenantInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validOAuthBase()
			cfg.OAuth.Providers = msMap(tt.tenant)
			err := cfg.Validate()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Validate = %v; want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate = %v; want nil", err)
			}
			if got := cfg.OAuth.Providers["microsoft"].Tenant; got != tt.want {
				t.Errorf("Tenant = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestConfigValidate_NormalizesProviderMapWithoutMutatingInput(t *testing.T) {
	input := map[string]ProviderConfig{
		"google": {
			ClientID:     "google-client-id",
			ClientSecret: "google-client-secret",
			RedirectURL:  "https://example.com/auth/oauth/google/callback",
			Enabled:      true,
		},
		"microsoft": {
			ClientID:     "ms-client-id",
			ClientSecret: "ms-client-secret",
			RedirectURL:  "https://example.com/auth/oauth/microsoft/callback",
			Enabled:      true,
			Tenant:       "  Contoso.OnMicrosoft.com  ",
		},
	}

	cfg := validOAuthBase()
	cfg.OAuth.Providers = input
	for run := 0; run < 2; run++ {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate run %d = %v", run, err)
		}
		if got := cfg.OAuth.Providers["microsoft"].Tenant; got != "contoso.onmicrosoft.com" {
			t.Fatalf("Validate run %d Tenant = %q; want contoso.onmicrosoft.com", run, got)
		}
		if len(cfg.OAuth.Providers) != len(input) {
			t.Fatalf("Validate run %d providers = %d; want %d", run, len(cfg.OAuth.Providers), len(input))
		}
	}

	if got := input["microsoft"].Tenant; got != "  Contoso.OnMicrosoft.com  " {
		t.Errorf("source map Tenant = %q; want the input left untouched", got)
	}
	if got := input["google"].Tenant; got != "" {
		t.Errorf("source map google Tenant = %q; want empty", got)
	}
}

func TestProviderConfigJSONTags(t *testing.T) {
	var p ProviderConfig
	raw := `{"client_id":"id","tenant":"tenant-guid","trusted_tenants":["partner-guid"],"jwks_cache_ttl":3600000000000,"graph_version":"v20.0"}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("unmarshal ProviderConfig: %v", err)
	}
	if p.Tenant != "tenant-guid" {
		t.Errorf("Tenant = %q; want tenant-guid", p.Tenant)
	}
	if len(p.TrustedTenants) != 1 || p.TrustedTenants[0] != "partner-guid" {
		t.Errorf("TrustedTenants = %v; want [partner-guid]", p.TrustedTenants)
	}
	if p.JWKSCacheTTL != time.Hour {
		t.Errorf("JWKSCacheTTL = %v; want 1h", p.JWKSCacheTTL)
	}
	if p.GraphVersion != "v20.0" {
		t.Errorf("GraphVersion = %q; want v20.0", p.GraphVersion)
	}
}

func TestProviderConfigLogValue(t *testing.T) {
	t.Run("masks client secret and private key", func(t *testing.T) {
		p := ProviderConfig{
			ClientID:     "my-client-id",
			ClientSecret: "top-secret-token",
			RedirectURL:  "https://example.com/callback",
			TeamID:       "ABCDE12345",
			KeyID:        "FGHIJ67890",
			PrivateKey:   "-----BEGIN PRIVATE KEY-----\nxyz",
		}
		val := p.LogValue()
		attrs := make(map[string]string)
		for _, attr := range val.Group() {
			attrs[attr.Key] = attr.Value.String()
		}
		for _, leaked := range []string{"top-secret-token", "PRIVATE KEY"} {
			for k, v := range attrs {
				if strings.Contains(v, leaked) {
					t.Fatalf("LogValue leaked secret in %q: %q", k, v)
				}
			}
		}
		if attrs["client_secret"] != "[REDACTED]" {
			t.Errorf("client_secret = %q; want [REDACTED]", attrs["client_secret"])
		}
		if attrs["private_key"] != "[REDACTED]" {
			t.Errorf("private_key = %q; want [REDACTED]", attrs["private_key"])
		}
	})

	t.Run("empty secrets stay empty", func(t *testing.T) {
		val := ProviderConfig{ClientID: "id"}.LogValue()
		attrs := make(map[string]string)
		for _, attr := range val.Group() {
			attrs[attr.Key] = attr.Value.String()
		}
		if attrs["client_secret"] != "" {
			t.Errorf("client_secret = %q; want empty", attrs["client_secret"])
		}
		if attrs["private_key"] != "" {
			t.Errorf("private_key = %q; want empty", attrs["private_key"])
		}
	})

	t.Run("String masks client secret", func(t *testing.T) {
		p := ProviderConfig{ClientID: "id", ClientSecret: "top-secret-token"}
		if str := p.String(); strings.Contains(str, "top-secret-token") {
			t.Fatalf("String() leaked client secret: %q", str)
		}
	})

	t.Run("MicrosoftConfig masks client secret in LogValue", func(t *testing.T) {
		m := MicrosoftConfig{
			ClientID:     "ms-id",
			ClientSecret: "ms-top-secret",
			Tenant:       "common",
			RedirectURI:  "https://example.com/callback",
		}
		val := m.LogValue()
		attrs := make(map[string]string)
		for _, attr := range val.Group() {
			attrs[attr.Key] = attr.Value.String()
		}
		if attrs["client_secret"] != "[REDACTED]" {
			t.Errorf("client_secret = %q; want [REDACTED]", attrs["client_secret"])
		}
		if strings.Contains(attrs["client_secret"], "ms-top-secret") {
			t.Fatalf("LogValue leaked microsoft secret")
		}
	})

	t.Run("OAuthConfig masks state secret and nested microsoft secret", func(t *testing.T) {
		o := OAuthConfig{
			StateSecret: "state-secret-super-confidential",
			Microsoft: &MicrosoftConfig{
				ClientID:     "ms-id",
				ClientSecret: "ms-secret",
			},
		}
		val := o.LogValue()
		attrs := make(map[string]string)
		for _, attr := range val.Group() {
			attrs[attr.Key] = attr.Value.String()
		}
		if attrs["state_secret"] != "[REDACTED]" {
			t.Errorf("state_secret = %q; want [REDACTED]", attrs["state_secret"])
		}
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("oauth config", slog.Any("oauth", o))
		out := buf.String()
		if strings.Contains(out, "ms-secret") {
			t.Fatalf("LogValue leaked nested microsoft secret: %s", out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] in log output, got: %s", out)
		}
	})

	t.Run("MicrosoftConfig String masks client secret", func(t *testing.T) {
		m := MicrosoftConfig{
			ClientID:     "ms-id",
			ClientSecret: "ms-top-secret",
			Tenant:       "common",
			RedirectURI:  "https://example.com/callback",
		}
		str := m.String()
		if strings.Contains(str, "ms-top-secret") {
			t.Fatalf("String() leaked client secret: %q", str)
		}
		if !strings.Contains(str, "[REDACTED]") {
			t.Fatalf("String() expected [REDACTED], got: %q", str)
		}
	})

	t.Run("OAuthConfig providers map redacted under JSON handler", func(t *testing.T) {
		o := OAuthConfig{
			StateSecret: "state-secret-super-confidential",
			Providers: map[string]ProviderConfig{
				"google": {
					ClientID:     "google-id",
					ClientSecret: "google-top-secret",
					RedirectURL:  "https://example.com/callback",
				},
				"apple": {
					ClientID:    "apple-id",
					TeamID:      "TEAMID1234",
					KeyID:       "KEYID56789",
					PrivateKey:  "apple-pem-secret",
					RedirectURL: "https://example.com/callback",
				},
			},
		}
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("oauth config", slog.Any("oauth", o))
		out := buf.String()
		for _, leaked := range []string{"google-top-secret", "apple-pem-secret", "state-secret-super-confidential"} {
			if strings.Contains(out, leaked) {
				t.Fatalf("JSON log leaked secret %q: %s", leaked, out)
			}
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] in JSON log, got: %s", out)
		}
	})

	t.Run("OAuthConfig String masks state secret", func(t *testing.T) {
		o := OAuthConfig{
			StateSecret: "state-secret-super-confidential",
			Microsoft: &MicrosoftConfig{
				ClientID:     "ms-id",
				ClientSecret: "ms-secret",
			},
		}
		str := o.String()
		if strings.Contains(str, "state-secret-super-confidential") {
			t.Fatalf("String() leaked state secret: %q", str)
		}
		if strings.Contains(str, "ms-secret") {
			t.Fatalf("String() leaked nested microsoft secret: %q", str)
		}
	})

	t.Run("DiscordConfig masks client secret in LogValue and String", func(t *testing.T) {
		d := DiscordConfig{
			ClientID:     "discord-client-id",
			ClientSecret: "discord-secret-token",
			RedirectURI:  "https://example.com/callback",
			Scopes:       []string{"identify", "email"},
		}
		val := d.LogValue()
		attrs := make(map[string]string)
		for _, attr := range val.Group() {
			attrs[attr.Key] = attr.Value.String()
		}
		if attrs["client_secret"] != "[REDACTED]" {
			t.Errorf("client_secret = %q; want [REDACTED]", attrs["client_secret"])
		}
		if strings.Contains(attrs["client_secret"], "discord-secret-token") {
			t.Fatalf("LogValue leaked discord client secret")
		}
		str := d.String()
		if strings.Contains(str, "discord-secret-token") {
			t.Fatalf("String() leaked discord client secret: %q", str)
		}
		if !strings.Contains(str, "[REDACTED]") {
			t.Fatalf("String() expected [REDACTED], got: %q", str)
		}
	})

	t.Run("FacebookConfig masks app secret in LogValue and String", func(t *testing.T) {
		f := FacebookConfig{
			AppID:        "fb-app-id",
			AppSecret:    "fb-app-secret-token",
			RedirectURI:  "https://example.com/callback",
			Scopes:       []string{"email", "public_profile"},
			GraphVersion: "v19.0",
		}
		val := f.LogValue()
		attrs := make(map[string]string)
		for _, attr := range val.Group() {
			attrs[attr.Key] = attr.Value.String()
		}
		if attrs["app_secret"] != "[REDACTED]" {
			t.Errorf("app_secret = %q; want [REDACTED]", attrs["app_secret"])
		}
		if strings.Contains(attrs["app_secret"], "fb-app-secret-token") {
			t.Fatalf("LogValue leaked facebook app secret")
		}
		str := f.String()
		if strings.Contains(str, "fb-app-secret-token") {
			t.Fatalf("String() leaked facebook app secret: %q", str)
		}
		if !strings.Contains(str, "[REDACTED]") {
			t.Fatalf("String() expected [REDACTED], got: %q", str)
		}
	})

	t.Run("OAuthConfig masks nested discord and facebook secrets in LogValue and String", func(t *testing.T) {
		o := OAuthConfig{
			StateSecret: "state-secret-super-confidential",
			Discord: &DiscordConfig{
				ClientID:     "discord-id",
				ClientSecret: "discord-secret-leak-test",
			},
			Facebook: &FacebookConfig{
				AppID:     "fb-id",
				AppSecret: "fb-secret-leak-test",
			},
		}
		val := o.LogValue()
		for _, attr := range val.Group() {
			if strings.Contains(attr.Value.String(), "discord-secret-leak-test") ||
				strings.Contains(attr.Value.String(), "fb-secret-leak-test") {
				t.Fatalf("OAuthConfig.LogValue leaked secrets in %s", attr.Key)
			}
		}
		str := o.String()
		if strings.Contains(str, "discord-secret-leak-test") {
			t.Fatalf("String() leaked discord secret")
		}
		if strings.Contains(str, "fb-secret-leak-test") {
			t.Fatalf("String() leaked fb secret")
		}
	})

	t.Run("XConfig defaults scopes", func(t *testing.T) {
		cfg := validOAuthBase()
		cfg.OAuth.X = &XConfig{
			ClientID:     "x-id",
			ClientSecret: "x-secret",
			RedirectURI:  "https://example.com/callback",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate = %v", err)
		}
		if len(cfg.OAuth.X.Scopes) != 1 || cfg.OAuth.X.Scopes[0] != "users.read" {
			t.Fatalf("Scopes = %v; want [users.read]", cfg.OAuth.X.Scopes)
		}
		// Merge premise (oauth sync): the typed X default is least-privilege
		// [users.read] and wins the resolveProviders merge, so the merged map
		// entry carries it rather than the broader remote default.
		scopes := cfg.OAuth.Providers["x"].Scopes
		if len(scopes) != 1 || scopes[0] != "users.read" {
			t.Fatalf("Scopes = %v; want [users.read]", scopes)
		}
	})

	t.Run("XConfig masks client secret in LogValue and String", func(t *testing.T) {
		x := XConfig{
			ClientID:     "x-client-id",
			ClientSecret: "x-secret-token",
			RedirectURI:  "https://example.com/callback",
			Scopes:       []string{"tweet.read", "users.read"},
		}
		val := x.LogValue()
		attrs := make(map[string]string)
		for _, attr := range val.Group() {
			attrs[attr.Key] = attr.Value.String()
		}
		if attrs["client_secret"] != "[REDACTED]" {
			t.Errorf("client_secret = %q; want [REDACTED]", attrs["client_secret"])
		}
		if strings.Contains(attrs["client_secret"], "x-secret-token") {
			t.Fatalf("LogValue leaked x client secret")
		}
		str := x.String()
		if strings.Contains(str, "x-secret-token") {
			t.Fatalf("String() leaked x client secret: %q", str)
		}
		if !strings.Contains(str, "[REDACTED]") {
			t.Fatalf("String() expected [REDACTED], got: %q", str)
		}
	})

	t.Run("OAuthConfig masks nested x secrets in LogValue and String", func(t *testing.T) {
		o := OAuthConfig{
			StateSecret: "state-secret-super-confidential",
			X: &XConfig{
				ClientID:     "x-id",
				ClientSecret: "x-secret-leak-test",
			},
		}
		val := o.LogValue()
		for _, attr := range val.Group() {
			if strings.Contains(attr.Value.String(), "x-secret-leak-test") {
				t.Fatalf("OAuthConfig.LogValue leaked secrets in %s", attr.Key)
			}
		}
		str := o.String()
		if strings.Contains(str, "x-secret-leak-test") {
			t.Fatalf("String() leaked x secret")
		}
	})
}

// A JSON handler resolves LogValuer only on slog.Attr values, so assertions on
// slog.Value.String() cannot catch an unredacted map element.
func TestOAuthConfigLogValueJSONRedaction(t *testing.T) {
	o := OAuthConfig{
		StateSecret: "state-secret-serialized-leak",
		Providers: map[string]ProviderConfig{
			"google": {
				ClientID:     "google-client-id",
				ClientSecret: "google-client-secret-leak",
				RedirectURL:  "https://example.com/callback",
				Scopes:       []string{"openid", "email"},
				Enabled:      true,
			},
			"apple": {
				ClientID:   "apple-client-id",
				TeamID:     "TEAM123456",
				KeyID:      "KEY1234567",
				PrivateKey: "-----BEGIN PRIVATE KEY-----\napple-p8-leak\n-----END PRIVATE KEY-----",
				Enabled:    true,
			},
			"secretless": {ClientID: "public-client"},
		},
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("oauth config", "oauth", o)

	line := buf.String()
	for _, leaked := range []string{"state-secret-serialized-leak", "google-client-secret-leak", "apple-p8-leak"} {
		if strings.Contains(line, leaked) {
			t.Fatalf("serialized log line leaked %q: %s", leaked, line)
		}
	}

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("log line is not valid json: %v", err)
	}
	oauth, ok := entry["oauth"].(map[string]any)
	if !ok {
		t.Fatalf("oauth group missing from log line: %s", line)
	}
	providers, ok := oauth["providers"].(map[string]any)
	if !ok {
		t.Fatalf("providers group missing from log line: %s", line)
	}
	google, ok := providers["google"].(map[string]any)
	if !ok {
		t.Fatalf("google provider missing from log line: %s", line)
	}
	if google["client_secret"] != "[REDACTED]" {
		t.Fatalf("google client_secret = %v; want [REDACTED]", google["client_secret"])
	}
	apple, ok := providers["apple"].(map[string]any)
	if !ok {
		t.Fatalf("apple provider missing from log line: %s", line)
	}
	if apple["private_key"] != "[REDACTED]" {
		t.Fatalf("apple private_key = %v; want [REDACTED]", apple["private_key"])
	}
	secretless, ok := providers["secretless"].(map[string]any)
	if !ok {
		t.Fatalf("secretless provider missing from log line: %s", line)
	}
	if secretless["client_secret"] != "" {
		t.Fatalf("secretless client_secret = %v; want empty", secretless["client_secret"])
	}
}

func TestOAuthConfigLogValueEmptyProviders(t *testing.T) {
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("oauth config", "oauth", OAuthConfig{})

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("log line is not valid json: %v", err)
	}
	oauth, ok := entry["oauth"].(map[string]any)
	if !ok {
		t.Fatalf("oauth group missing from log line: %s", buf.String())
	}
	if raw, present := oauth["providers"]; present {
		if _, isObject := raw.(map[string]any); !isObject {
			t.Fatalf("providers = %v; want a group object", raw)
		}
	}
}

func TestOAuthConfig_ResolvesProvidersAfterDefaults(t *testing.T) {
	msMap := func(tenant string) map[string]ProviderConfig {
		return map[string]ProviderConfig{"microsoft": {
			ClientID:     "map-id",
			ClientSecret: "map-secret",
			RedirectURL:  "https://example.com/cb",
			Enabled:      true,
			Tenant:       tenant,
		}}
	}
	msTyped := func(tenant string) *MicrosoftConfig {
		return &MicrosoftConfig{
			ClientID:     "typed-id",
			ClientSecret: "typed-secret",
			RedirectURI:  "https://example.com/cb",
			Tenant:       tenant,
		}
	}

	t.Run("map tenant survives defaults", func(t *testing.T) {
		cfg := validOAuthBase()
		cfg.OAuth.Providers = msMap("44444444-4444-4444-4444-444444444444")
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate = %v", err)
		}
		p := cfg.OAuth.Providers["microsoft"]
		if p.Tenant != "44444444-4444-4444-4444-444444444444" {
			t.Errorf("Tenant = %q; want guid", p.Tenant)
		}
		if len(p.Scopes) != 4 {
			t.Errorf("Scopes = %v; want defaults", p.Scopes)
		}
		if p.JWKSCacheTTL != 24*time.Hour {
			t.Errorf("JWKSCacheTTL = %v; want 24h", p.JWKSCacheTTL)
		}
	})

	// Merge premise (oauth sync): fixtures use realistic tenant GUIDs because
	// Validate enforces the tenant gate (fail closed on non-GUID/domain refs).
	t.Run("typed tenant wins over map tenant", func(t *testing.T) {
		cfg := validOAuthBase()
		cfg.OAuth.Providers = msMap("55555555-5555-5555-5555-555555555555")
		cfg.OAuth.Microsoft = msTyped("22222222-2222-2222-2222-222222222222")
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate = %v", err)
		}
		if got := cfg.OAuth.Providers["microsoft"].Tenant; got != "22222222-2222-2222-2222-222222222222" {
			t.Errorf("Tenant = %q; want typed guid", got)
		}
	})

	t.Run("typed tenant wins when map omits it", func(t *testing.T) {
		cfg := validOAuthBase()
		cfg.OAuth.Providers = map[string]ProviderConfig{"microsoft": {
			ClientID:     "map-id",
			ClientSecret: "map-secret",
			RedirectURL:  "https://example.com/cb",
			Enabled:      true,
		}}
		cfg.OAuth.Microsoft = msTyped("22222222-2222-2222-2222-222222222222")
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate = %v", err)
		}
		if got := cfg.OAuth.Providers["microsoft"].Tenant; got != "22222222-2222-2222-2222-222222222222" {
			t.Errorf("Tenant = %q; want typed guid", got)
		}
	})

	t.Run("common remains reachable when nothing configures a tenant", func(t *testing.T) {
		cfg := validOAuthBase()
		cfg.OAuth.Microsoft = msTyped("")
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate = %v", err)
		}
		if got := cfg.OAuth.Providers["microsoft"].Tenant; got != "common" {
			t.Errorf("Tenant = %q; want common", got)
		}
	})

	t.Run("typed provider registers without a map entry", func(t *testing.T) {
		cfg := validOAuthBase()
		cfg.OAuth.Microsoft = msTyped("")
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate = %v", err)
		}
		if !cfg.OAuth.Providers["microsoft"].Enabled {
			t.Error("merged microsoft entry is disabled; want enabled")
		}
	})

	t.Run("explicit map enabled false disables a typed provider", func(t *testing.T) {
		off := false
		cfg := validOAuthBase()
		cfg.OAuth.Providers = msMap("44444444-4444-4444-4444-444444444444")
		entry := cfg.OAuth.Providers["microsoft"]
		entry.Enabled = off
		cfg.OAuth.Providers["microsoft"] = entry
		cfg.OAuth.Microsoft = msTyped("")
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate = %v", err)
		}
		if cfg.OAuth.Providers["microsoft"].Enabled {
			t.Error("merged microsoft entry is enabled; want disabled")
		}
	})

	t.Run("explicit typed enabled false disables the provider", func(t *testing.T) {
		off := false
		cfg := validOAuthBase()
		cfg.OAuth.StateSecret = ""
		cfg.OAuth.Providers = msMap("44444444-4444-4444-4444-444444444444")
		typed := msTyped("")
		typed.Enabled = &off
		cfg.OAuth.Microsoft = typed
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate = %v; want nil (disabled provider needs no state secret)", err)
		}
		if cfg.OAuth.Providers["microsoft"].Enabled {
			t.Error("merged microsoft entry is enabled; want disabled")
		}
	})
}
