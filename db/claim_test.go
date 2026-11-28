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
		"admin$@example.com",
		"admin{@example.com",
		"admin}@example.com",
		"a|b@example.com",
		"o'brien@example.com",
		"user@exam ple.com",
		"user@exa\tmple.com",
		"user@@example.com",
		"no-at.example.com",
		"@example.com",
		"user@example",
		"user@.example.com",
		"user@example.com.",
		"user@-example.com",
		"üser@example.com",
		strings.Repeat("a", 250) + "@example.com",
	} {
		if _, err := ClaimKey(bad); !errors.Is(err, errors.ErrInvalidEmail) {
			t.Errorf("ClaimKey(%q) err = %v; want ErrInvalidEmail", bad, err)
		}
	}
}
