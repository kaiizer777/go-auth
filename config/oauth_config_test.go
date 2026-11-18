package config

import (
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
		name         string
		mutate       func(*Config)
		wantErr      *errors.Error
		wantTTL      time.Duration
		wantSameSite http.SameSite
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
				c.OAuth.Providers = enabled("discord", ProviderConfig{
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
			name: "disabled unknown provider rejected",
			mutate: func(c *Config) {
				c.OAuth.Providers = map[string]ProviderConfig{"discord": {}}
			},
			wantErr: errors.ErrOAuthProviderUnknown,
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
}
