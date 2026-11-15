package session

import (
	"encoding/hex"
	"testing"
)

func TestGenerateRawID_Entropy(t *testing.T) {
	const count = 1000
	seen := make(map[string]struct{}, count)

	for i := 0; i < count; i++ {
		id, err := generateRawID()
		if err != nil {
			t.Fatalf("generateRawID failed: %v", err)
		}

		if len(id) != 32 {
			t.Fatalf("expected len 32, got %d for %q", len(id), id)
		}

		decoded, err := hex.DecodeString(id)
		if err != nil {
			t.Fatalf("expected valid hex string, got %v for %q", err, id)
		}
		if len(decoded) != 16 {
			t.Fatalf("expected 16 decoded bytes, got %d", len(decoded))
		}

		if _, exists := seen[id]; exists {
			t.Fatalf("collision detected at iteration %d: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestHashID_Deterministic(t *testing.T) {
	id1 := "0123456789abcdef0123456789abcdef"
	id2 := "fedcba9876543210fedcba9876543210"

	h1 := hashID(id1)
	h1Repeat := hashID(id1)
	h2 := hashID(id2)

	if h1 != h1Repeat {
		t.Fatalf("expected deterministic hash, got %q != %q", h1, h1Repeat)
	}

	if h1 == h2 {
		t.Fatalf("expected distinct hashes for distinct IDs, got identical %q", h1)
	}

	if len(h1) != 64 {
		t.Fatalf("expected 64 chars, got %d", len(h1))
	}

	if _, err := hex.DecodeString(h1); err != nil {
		t.Fatalf("expected valid hex hash, got %v", err)
	}
}
