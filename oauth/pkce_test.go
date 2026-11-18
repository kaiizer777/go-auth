package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGeneratePKCE(t *testing.T) {
	t.Run("verifier 43-char unpadded base64url", func(t *testing.T) {
		t.Parallel()
		pkce, err := GeneratePKCE()
		if err != nil {
			t.Fatalf("GeneratePKCE = %v", err)
		}
		if len(pkce.Verifier) != 43 {
			t.Errorf("verifier length = %d; want 43", len(pkce.Verifier))
		}
		for _, c := range pkce.Verifier {
			if c == '+' || c == '/' || c == '=' {
				t.Errorf("verifier contains non-URL-safe char %q", c)
			}
		}
		if _, err := base64.RawURLEncoding.DecodeString(pkce.Verifier); err != nil {
			t.Errorf("verifier is not valid raw base64url: %v", err)
		}
	})

	t.Run("unique across calls", func(t *testing.T) {
		t.Parallel()
		seen := make(map[string]struct{}, 200)
		for range 200 {
			pkce, err := GeneratePKCE()
			if err != nil {
				t.Fatalf("GeneratePKCE = %v", err)
			}
			if _, dup := seen[pkce.Verifier]; dup {
				t.Fatalf("duplicate verifier %q", pkce.Verifier)
			}
			seen[pkce.Verifier] = struct{}{}
		}
	})

	t.Run("S256 challenge matches verifier digest", func(t *testing.T) {
		t.Parallel()
		pkce, err := GeneratePKCE()
		if err != nil {
			t.Fatalf("GeneratePKCE = %v", err)
		}
		sum := sha256.Sum256([]byte(pkce.Verifier))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if pkce.Challenge != want {
			t.Errorf("challenge = %q; want %q", pkce.Challenge, want)
		}
		if len(pkce.Challenge) != 43 || strings.ContainsAny(pkce.Challenge, "+/=") {
			t.Errorf("challenge is not 43-char unpadded base64url: %q", pkce.Challenge)
		}
	})

	t.Run("method strictly S256", func(t *testing.T) {
		t.Parallel()
		pkce, err := GeneratePKCE()
		if err != nil {
			t.Fatalf("GeneratePKCE = %v", err)
		}
		if pkce.Method != "S256" {
			t.Errorf("method = %q; want S256", pkce.Method)
		}
	})
}
