package config

import (
	"strings"
	"testing"
)

func TestRedactMySQLDSN_PasswordsWithNetworkAddressPatterns(t *testing.T) {
	tests := []struct {
		name     string
		rawDSN   string
		expected string
	}{
		{
			name:     "password contains @tcp pattern",
			rawDSN:   "user:p@ss@tcp(internal)word@tcp(127.0.0.1:3306)/auth_db",
			expected: "user:REDACTED@tcp(127.0.0.1:3306)/auth_db",
		},
		{
			name:     "password contains @unix pattern with tcp target",
			rawDSN:   "user:p@ss@unix(socket)word@tcp(127.0.0.1:3306)/auth_db",
			expected: "user:REDACTED@tcp(127.0.0.1:3306)/auth_db",
		},
		{
			name:     "password contains @tcp pattern with unix target",
			rawDSN:   "user:p@ss@tcp(host)word@unix(/var/run/mysqld/mysqld.sock)/auth_db",
			expected: "user:REDACTED@unix(/var/run/mysqld/mysqld.sock)/auth_db",
		},
		{
			name:     "password contains @tcp pattern with default socket target",
			rawDSN:   "user:p@ss@tcp(host)word@/auth_db",
			expected: "user:REDACTED@/auth_db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := RedactMySQLDSN(tt.rawDSN)
			if !ok {
				t.Fatalf("RedactMySQLDSN failed for %s", tt.rawDSN)
			}
			if got != tt.expected {
				t.Errorf("RedactMySQLDSN() = %q, want %q", got, tt.expected)
			}
			if strings.Contains(got, "p@ss") || strings.Contains(got, "word") || strings.Contains(got, "internal") || strings.Contains(got, "socket") || strings.Contains(got, "host") {
				t.Errorf("leaked password fragment in %q", got)
			}
			redactedURL := RedactURL(tt.rawDSN)
			if redactedURL != tt.expected {
				t.Errorf("RedactURL() = %q, want %q", redactedURL, tt.expected)
			}
		})
	}
}

func TestRedactMySQLDSN_FallbackSanitizesQueryParams(t *testing.T) {
	rawDSN := "user:p@ss@word@tcp(127.0.0.1:3306)/auth_db?secret=supersecret&token=tok123;client_secret=cs456&parseTime=true"
	got, ok := RedactMySQLDSN(rawDSN)
	if !ok {
		t.Fatalf("RedactMySQLDSN failed for %s", rawDSN)
	}

	for _, secret := range []string{"supersecret", "tok123", "cs456", "p@ss@word"} {
		if strings.Contains(got, secret) {
			t.Errorf("expected secret %q to be redacted, got: %s", secret, got)
		}
	}
	if !strings.Contains(got, "parseTime=true") {
		t.Errorf("expected non-sensitive param parseTime=true preserved, got: %s", got)
	}
	if !strings.Contains(got, "user:REDACTED@tcp(127.0.0.1:3306)/auth_db") {
		t.Errorf("unexpected base DSN structure: %s", got)
	}

	redactedURL := RedactURL(rawDSN)
	for _, secret := range []string{"supersecret", "tok123", "cs456", "p@ss@word"} {
		if strings.Contains(redactedURL, secret) {
			t.Errorf("expected RedactURL to redact %q, got: %s", secret, redactedURL)
		}
	}
}

func TestRedactMySQLDSN_QueryParamWithNetworkPattern(t *testing.T) {
	rawDSN := "user:p@ss@word@tcp(127.0.0.1:3306)/auth_db?note=@tcp(1.2.3.4)&secret=sensitive"
	got, ok := RedactMySQLDSN(rawDSN)
	if !ok {
		t.Fatalf("RedactMySQLDSN failed for %s", rawDSN)
	}
	if strings.Contains(got, "sensitive") {
		t.Errorf("expected sensitive query param to be redacted, got: %s", got)
	}
	if !strings.HasPrefix(got, "user:REDACTED@tcp(127.0.0.1:3306)/auth_db") {
		t.Errorf("network address corrupted: %s", got)
	}
}
