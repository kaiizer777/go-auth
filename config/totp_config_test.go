package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/errors"
)

func validTOTPBase() Config {
	cfg := DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	cfg.TOTP.EncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	return cfg
}

func TestTOTPDefaults(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	if cfg.TOTP.Issuer != "go-auth" {
		t.Errorf("Issuer = %q; want go-auth", cfg.TOTP.Issuer)
	}
	if cfg.TOTP.ChallengeTokenTTL != 10*time.Minute {
		t.Errorf("ChallengeTokenTTL = %v; want 10m", cfg.TOTP.ChallengeTokenTTL)
	}
	if cfg.TOTP.MaxAttemptsPerWindow != 5 {
		t.Errorf("MaxAttemptsPerWindow = %d; want 5", cfg.TOTP.MaxAttemptsPerWindow)
	}
	if cfg.TOTP.AttemptWindow != 5*time.Minute {
		t.Errorf("AttemptWindow = %v; want 5m", cfg.TOTP.AttemptWindow)
	}
}

func TestConfigValidate_TOTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr error
	}{
		{
			name:    "valid 64-char hex key passes",
			mutate:  func(c *Config) {},
			wantErr: nil,
		},
		{
			name: "short hex key fails ErrTOTPEncryptionKeyInvalid",
			mutate: func(c *Config) {
				c.TOTP.EncryptionKey = "0123456789abcdef"
			},
			wantErr: errors.ErrTOTPEncryptionKeyInvalid,
		},
		{
			name: "63-char hex key fails ErrTOTPEncryptionKeyInvalid",
			mutate: func(c *Config) {
				c.TOTP.EncryptionKey = strings.Repeat("a", 63)
			},
			wantErr: errors.ErrTOTPEncryptionKeyInvalid,
		},
		{
			name: "65-char hex key fails ErrTOTPEncryptionKeyInvalid",
			mutate: func(c *Config) {
				c.TOTP.EncryptionKey = strings.Repeat("a", 65)
			},
			wantErr: errors.ErrTOTPEncryptionKeyInvalid,
		},
		{
			name: "non-hex 64-char key fails ErrTOTPEncryptionKeyInvalid",
			mutate: func(c *Config) {
				c.TOTP.EncryptionKey = strings.Repeat("z", 64)
			},
			wantErr: errors.ErrTOTPEncryptionKeyInvalid,
		},
		{
			name: "challenge token TTL under 1m fails",
			mutate: func(c *Config) {
				c.TOTP.ChallengeTokenTTL = 30 * time.Second
			},
			wantErr: errors.ErrTOTPChallengeTokenTTLInvalid,
		},
		{
			name: "challenge token TTL over 30m fails",
			mutate: func(c *Config) {
				c.TOTP.ChallengeTokenTTL = 31 * time.Minute
			},
			wantErr: errors.ErrTOTPChallengeTokenTTLInvalid,
		},
		{
			name: "max attempts under 1 fails",
			mutate: func(c *Config) {
				c.TOTP.MaxAttemptsPerWindow = 0
			},
			wantErr: errors.ErrTOTPMaxAttemptsInvalid,
		},
		{
			name: "negative max attempts fails",
			mutate: func(c *Config) {
				c.TOTP.MaxAttemptsPerWindow = -1
			},
			wantErr: errors.ErrTOTPMaxAttemptsInvalid,
		},
		{
			name: "attempt window under 1m fails",
			mutate: func(c *Config) {
				c.TOTP.AttemptWindow = 30 * time.Second
			},
			wantErr: errors.ErrTOTPAttemptWindowInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validTOTPBase()
			tt.mutate(&cfg)

			err := cfg.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got error %v, want %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestTOTPConfig_LogValueRedaction(t *testing.T) {
	t.Parallel()

	cfg := validTOTPBase()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	logger.Info("testing totp config log masking", "totp", cfg.TOTP)

	output := buf.String()
	if strings.Contains(output, cfg.TOTP.EncryptionKey) {
		t.Errorf("raw TOTP encryption key leaked in logs: %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in log output: %s", output)
	}
}
