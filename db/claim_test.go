package db

import (
	"strings"
	"testing"

	"github.com/kaiizer777/go-auth/errors"
)

func TestClaimKey_NormalisesValidAddresses(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"User@Example.COM", "user@example.com"},
		{"  user+tag@sub.example.com\t", "user+tag@sub.example.com"},
		{"first.last@example.co", "first.last@example.co"},
		{"USER_NAME@EXAMPLE.COM", "user_name@example.com"},
		{`"jane"@example.com`, `"jane"@example.com`},
		// RFC 5322 atext the rest of the system accepts via ValidateEmail: the claim
		// key must accept it too, or those addresses can never be claimed.
		{"o'brien@example.com", "o'brien@example.com"},
		{"admin$@example.com", "admin$@example.com"},
		{"a{b@example.com", "a{b@example.com"},
		// 255 bytes after normalisation is the boundary the column holds.
		{strings.Repeat("a", 243) + "@example.com", strings.Repeat("a", 243) + "@example.com"},
	} {
		key, err := ClaimKey(tc.in)
		if err != nil {
			t.Errorf("ClaimKey(%q) = %v; want %q", tc.in, err, tc.want)
			continue
		}
		if key != tc.want {
			t.Errorf("ClaimKey(%q) = %q; want %q", tc.in, key, tc.want)
		}
	}
	// An empty address claims nothing and is not an error.
	if key, err := ClaimKey(" \t\n"); err != nil || key != "" {
		t.Errorf("ClaimKey(blank) = (%q, %v); want (\"\", nil)", key, err)
	}
}

func TestClaimKey_RejectsNonAddressValues(t *testing.T) {
	for _, bad := range []string{
		"user@@example.com",
		"no-at.example.com",
		"@example.com",
		"user@",
		"user@example",
		"user@.example.com",
		"user@example..com",
		"user@example.com.",
		"user name@example.com",
		"user@exa\tmple.com",
		strings.Repeat("a", 244) + "@example.com", // 256 bytes
	} {
		if _, err := ClaimKey(bad); !errors.Is(err, errors.ErrInvalidEmail) {
			t.Errorf("ClaimKey(%q) err = %v; want ErrInvalidEmail", bad, err)
		}
	}
}
