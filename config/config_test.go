package config

import (
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/errors"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MigrationsPath != "db/migrations" {
		t.Errorf("got %q, want %q", cfg.MigrationsPath, "db/migrations")
	}
	if cfg.MaxOpenConns != 25 {
		t.Errorf("got %d, want 25", cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns != 10 {
		t.Errorf("got %d, want 10", cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime != time.Hour {
		t.Errorf("got %v, want 1h", cfg.ConnMaxLifetime)
	}
	if cfg.ConnMaxIdleTime != 30*time.Minute {
		t.Errorf("got %v, want 30m", cfg.ConnMaxIdleTime)
	}
	if len(cfg.AllowedOrigins) != 0 {
		t.Errorf("expected empty AllowedOrigins, got %v", cfg.AllowedOrigins)
	}
	if len(cfg.AllowedMethods) == 0 {
		t.Error("expected non-empty AllowedMethods")
	}
	if len(cfg.AllowedHeaders) == 0 {
		t.Error("expected non-empty AllowedHeaders")
	}
}

func TestConfigValidate_ZeroValueUsesAsyncEmailDispatch(t *testing.T) {
	cfg := Config{
		DatabaseURL: "postgres://user:pass@localhost:5432/testdb",
		BaseURL:     "https://example.com",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected err = %v", err)
	}
	if cfg.DisableAsyncEmailDispatch {
		t.Fatal("zero-value config disabled async email dispatch")
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name               string
		mutate             func(*Config)
		wantErr            error
		wantMigrationsPath string
	}{
		{
			name: "valid configuration",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
			},
			wantErr:            nil,
			wantMigrationsPath: "db/migrations",
		},
		{
			name: "missing database URL",
			mutate: func(c *Config) {
				c.DatabaseURL = ""
			},
			wantErr: errors.ErrDatabaseURLRequired,
		},
		{
			name: "missing base URL",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = ""
			},
			wantErr: errors.ErrBaseURLRequired,
		},
		{
			name: "negative max open connections",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.MaxOpenConns = -1
			},
			wantErr: errors.ErrMaxOpenConnsNegative,
		},
		{
			name: "negative max idle connections",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.MaxIdleConns = -1
			},
			wantErr: errors.ErrMaxIdleConnsNegative,
		},
		{
			name: "max idle exceeds max open",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.MaxOpenConns = 5
				c.MaxIdleConns = 10
			},
			wantErr: errors.ErrMaxIdleExceedsOpen,
		},
		{
			name: "invalid base URL",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "example.com"
			},
			wantErr: errors.ErrBaseURLRequired,
		},
		{
			name: "base URL trailing slash removed",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com/"
			},
			wantErr: nil,
		},
		{
			name: "negative conn max lifetime",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.ConnMaxLifetime = -time.Second
			},
			wantErr: errors.ErrConnMaxLifetimeNegative,
		},
		{
			name: "negative conn max idle time",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.ConnMaxIdleTime = -time.Second
			},
			wantErr: errors.ErrConnMaxIdleTimeNegative,
		},
		{
			name: "negative email dispatch timeout",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.EmailDispatchTimeout = -time.Second
			},
			wantErr: errors.ErrEmailDispatchTimeoutNegative,
		},
		{
			name: "zero durations permitted as no-limit",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.ConnMaxLifetime = 0
				c.ConnMaxIdleTime = 0
			},
			wantErr:            nil,
			wantMigrationsPath: "db/migrations",
		},
		{
			name: "zero email dispatch timeout uses default",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.EmailDispatchTimeout = 0
			},
			wantErr: nil,
		},
		{
			name: "empty migrations path falls back to default",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.MigrationsPath = ""
			},
			wantErr:            nil,
			wantMigrationsPath: "db/migrations",
		},
		{
			name: "custom migrations path preserved",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.MigrationsPath = "custom/migrations"
			},
			wantErr:            nil,
			wantMigrationsPath: "custom/migrations",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Validate() err = %v, wantErr = %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("Validate() unexpected err = %v", err)
			}
			if tt.wantErr == nil && tt.wantMigrationsPath != "" && cfg.MigrationsPath != tt.wantMigrationsPath {
				t.Errorf("got migrations path %q, want %q", cfg.MigrationsPath, tt.wantMigrationsPath)
			}
			if tt.name == "zero email dispatch timeout uses default" && cfg.EmailDispatchTimeout != 10*time.Second {
				t.Errorf("got email dispatch timeout %v, want 10s", cfg.EmailDispatchTimeout)
			}
			if tt.name == "base URL trailing slash removed" && cfg.BaseURL != "https://example.com" {
				t.Errorf("got base URL %q, want %q", cfg.BaseURL, "https://example.com")
			}
		})
	}
}
