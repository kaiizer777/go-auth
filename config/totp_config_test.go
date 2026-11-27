package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
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

// testTOTPKeyring renders a single-entry kid:base64 keyring that parses.
func testTOTPKeyring(kid string) string {
	key := bytes.Repeat([]byte{0x2a}, 32)
	return kid + ":" + base64.StdEncoding.EncodeToString(key)
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
		{
			name: "keyring alongside the hex key passes",
			mutate: func(c *Config) {
				c.TOTP.Keyring = testTOTPKeyring("k2")
			},
			wantErr: nil,
		},
		{
			name: "keyring only passes",
			mutate: func(c *Config) {
				c.TOTP.EncryptionKey = ""
				c.TOTP.Keyring = testTOTPKeyring("k2")
			},
			wantErr: nil,
		},
		{
			name:    "neither key surface still passes",
			mutate:  func(c *Config) { c.TOTP.EncryptionKey = "" },
			wantErr: nil,
		},
		{
			name: "malformed keyring fails ErrTOTPKeyringInvalid",
			mutate: func(c *Config) {
				c.TOTP.Keyring = "k2:not-base64"
			},
			wantErr: errors.ErrTOTPKeyringInvalid,
		},
		{
			name: "keyring with a short key fails ErrTOTPKeyringInvalid",
			mutate: func(c *Config) {
				c.TOTP.Keyring = "k2:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, 16))
			},
			wantErr: errors.ErrTOTPKeyringInvalid,
		},
		{
			name: "whitespace-only keyring fails ErrTOTPKeyringInvalid",
			mutate: func(c *Config) {
				c.TOTP.Keyring = "   "
			},
			wantErr: errors.ErrTOTPKeyringInvalid,
		},
		{
			name: "duplicate kid in the keyring fails ErrTOTPKeyringInvalid",
			mutate: func(c *Config) {
				c.TOTP.Keyring = testTOTPKeyring("k2") + "," + testTOTPKeyring("k2")
			},
			wantErr: errors.ErrTOTPKeyringInvalid,
		},
		{
			name: "keyring reusing the legacy kid alongside the hex key fails ErrTOTPKeyringInvalid",
			mutate: func(c *Config) {
				c.TOTP.Keyring = testTOTPKeyring("legacy")
			},
			wantErr: errors.ErrTOTPKeyringInvalid,
		},
		{
			name: "keyring reusing the legacy kid without the hex key passes",
			mutate: func(c *Config) {
				c.TOTP.EncryptionKey = ""
				c.TOTP.Keyring = testTOTPKeyring("legacy")
			},
			wantErr: nil,
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

func TestConfigValidate_TOTP_ZeroDefaultsWithKey(t *testing.T) {
	t.Parallel()

	cfg := Config{
		DatabaseURL: "postgres://user:pass@localhost:5432/testdb",
		BaseURL:     "https://example.com",
		TOTP: TOTPConfig{
			EncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config with defaulted TOTP auxiliary fields, got: %v", err)
	}
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

func TestTOTPConfig_KeyringRedaction(t *testing.T) {
	t.Parallel()

	keyring := testTOTPKeyring("k2")
	cfg := TOTPConfig{EncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Keyring: keyring, Issuer: "test-app"}

	var foundKeyring bool
	for _, attr := range cfg.LogValue().Group() {
		if attr.Key != "keyring" {
			continue
		}
		foundKeyring = true
		if got := attr.Value.String(); got != "[REDACTED]" {
			t.Fatalf("LogValue keyring = %q, want [REDACTED]", got)
		}
	}
	if !foundKeyring {
		t.Fatal("LogValue carries no keyring attribute")
	}

	if strings.Contains(cfg.String(), keyring) {
		t.Fatalf("String() leaked the keyring: %q", cfg.String())
	}
	if !strings.Contains(cfg.String(), "Keyring: [REDACTED]") {
		t.Fatalf("String() did not mask the keyring: %q", cfg.String())
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, cfg); strings.Contains(out, keyring) || strings.Contains(out, keyring[:16]) {
			t.Fatalf("%s leaked the keyring: %s", verb, out)
		}
	}

	unset := TOTPConfig{Issuer: "test-app"}
	if strings.Contains(unset.String(), "[REDACTED]") {
		t.Fatalf("unset keyring should not be redacted: %q", unset.String())
	}
	for _, attr := range unset.LogValue().Group() {
		if attr.Key == "keyring" && attr.Value.String() != "" {
			t.Fatalf("unset keyring LogValue = %q, want empty", attr.Value.String())
		}
	}
}
