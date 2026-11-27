package crypto

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/kaiizer777/go-auth/errors"
)

func keyringKey(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func TestParseKeyringValid(t *testing.T) {
	t.Parallel()

	first := keyringKey(0x11)
	second := keyringKey(0x22)

	tests := []struct {
		name       string
		spec       string
		wantKids   []string
		wantActive string
	}{
		{name: "single entry", spec: "k1:" + first, wantKids: []string{"k1"}, wantActive: "k1"},
		{name: "ordered entries", spec: "k1:" + first + ",k2:" + second, wantKids: []string{"k1", "k2"}, wantActive: "k1"},
		{name: "surrounding whitespace", spec: " \t\r\nk1:" + first + "\r\n,\t k2:" + second + " \n", wantKids: []string{"k1", "k2"}, wantActive: "k1"},
		{name: "same key different kids", spec: "k1:" + first + ",k2:" + first, wantKids: []string{"k1", "k2"}, wantActive: "k1"},
		{name: "zero key allowed", spec: "k1:" + keyringKey(0x00), wantKids: []string{"k1"}, wantActive: "k1"},
		{name: "kid max length", spec: strings.Repeat("a", 32) + ":" + first, wantKids: []string{strings.Repeat("a", 32)}, wantActive: strings.Repeat("a", 32)},
		{name: "kid alphabet", spec: "A.b_c-9:" + first, wantKids: []string{"A.b_c-9"}, wantActive: "A.b_c-9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ring, err := ParseKeyring(tt.spec)
			if err != nil {
				t.Fatalf("ParseKeyring() error = %v", err)
			}
			if len(ring.entries) != len(tt.wantKids) {
				t.Fatalf("entries = %d, want %d", len(ring.entries), len(tt.wantKids))
			}
			for i, kid := range tt.wantKids {
				if ring.entries[i].kid != kid {
					t.Errorf("entry %d kid = %q, want %q", i, ring.entries[i].kid, kid)
				}
			}
			if got := ring.ActiveKeyID(); got != tt.wantActive {
				t.Errorf("ActiveKeyID() = %q, want %q", got, tt.wantActive)
			}
		})
	}
}

func TestParseKeyringMissing(t *testing.T) {
	t.Parallel()

	for _, spec := range []string{"", " ", "\t\r\n  \n"} {
		ring, err := ParseKeyring(spec)
		if !errors.Is(err, ErrKeyringMissing) {
			t.Fatalf("ParseKeyring(%q) error = %v, want ErrKeyringMissing", spec, err)
		}
		if ring != nil {
			t.Fatalf("ParseKeyring(%q) returned partial keyring", spec)
		}
	}
}

func TestParseKeyringRejectsMalformed(t *testing.T) {
	t.Parallel()

	valid := keyringKey(0x33)
	noPadding := strings.TrimRight(valid, "=")
	urlSafe := strings.NewReplacer("+", "-", "/", "_").Replace(keyringKey(0xff))

	tests := []struct {
		name string
		spec string
	}{
		{name: "leading comma", spec: "," + "k1:" + valid},
		{name: "trailing comma", spec: "k1:" + valid + ","},
		{name: "empty entry", spec: "k1:" + valid + ",," + "k2:" + valid},
		{name: "only comma", spec: ","},
		{name: "missing separator", spec: "k1" + valid},
		{name: "second colon", spec: "k1:" + valid + ":extra"},
		{name: "empty kid", spec: ":" + valid},
		{name: "kid too long", spec: strings.Repeat("a", 33) + ":" + valid},
		{name: "kid whitespace", spec: "k 1:" + valid},
		{name: "kid invalid char", spec: "k1!:" + valid},
		{name: "kid slash", spec: "k/1:" + valid},
		{name: "duplicate kid same key", spec: "k1:" + valid + ",k1:" + valid},
		{name: "duplicate kid different key", spec: "k1:" + valid + ",k1:" + keyringKey(0x44)},
		{name: "unpadded base64", spec: "k1:" + noPadding},
		{name: "url-safe base64", spec: "k1:" + urlSafe},
		{name: "embedded space", spec: "k1:" + valid[:4] + " " + valid[4:]},
		{name: "embedded newline", spec: "k1:" + valid[:4] + "\n" + valid[4:]},
		{name: "empty key", spec: "k1:"},
		{name: "16 byte key", spec: "k1:" + keyringKey16(0x55)},
		{name: "24 byte key", spec: "k1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 24))},
		{name: "31 byte key", spec: "k1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 31))},
		{name: "33 byte key", spec: "k1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 33))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ring, err := ParseKeyring(tt.spec)
			if !errors.Is(err, ErrKeyringMalformed) {
				t.Fatalf("ParseKeyring(%q) error = %v, want ErrKeyringMalformed", tt.spec, err)
			}
			if ring != nil {
				t.Fatalf("ParseKeyring(%q) returned partial keyring", tt.spec)
			}
		})
	}
}

func keyringKey16(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 16))
}

func TestParseKeyringRejectsNonZeroTrailingBits(t *testing.T) {
	t.Parallel()

	canonical := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lastData := len(canonical) - 2

	for i := 0; i < len(alphabet); i++ {
		variant := canonical[:lastData] + string(alphabet[i]) + canonical[lastData+1:]
		if variant == canonical {
			continue
		}
		if _, err := base64.StdEncoding.DecodeString(variant); err != nil {
			continue
		}
		if _, err := base64.StdEncoding.Strict().DecodeString(variant); err == nil {
			continue
		}
		if _, err := ParseKeyring("k1:" + variant); !errors.Is(err, ErrKeyringMalformed) {
			t.Fatalf("ParseKeyring(non-canonical trailing bits) error = %v, want ErrKeyringMalformed", err)
		}
		return
	}
	t.Fatal("no variant with non-zero trailing bits found")
}

func TestParseKeyringErrorsDoNotLeakKeyMaterial(t *testing.T) {
	t.Parallel()

	key := keyringKey(0x5a)
	specs := []string{
		"k1:" + key + ":tail",
		"k1:" + key + ",k1:" + key,
		"k1:" + strings.TrimRight(key, "="),
		"k1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 31)),
	}

	for _, spec := range specs {
		_, err := ParseKeyring(spec)
		if err == nil {
			t.Fatalf("ParseKeyring(%q) error = nil", spec)
		}
		for _, secret := range []string{key, strings.TrimRight(key, "="), strings.Repeat("Z", 32)} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error %q leaks key material %q", err, secret)
			}
		}
	}
}

func TestKeyringFormattingRedactsKeys(t *testing.T) {
	t.Parallel()

	key := keyringKey(0x5a)
	ring, err := ParseKeyring("k1:" + key)
	if err != nil {
		t.Fatalf("ParseKeyring() error = %v", err)
	}

	targets := []any{ring, *ring, ring.entries, ring.entries[0], ring.entries[0].key}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, target := range targets {
			out := fmt.Sprintf(verb, target)
			if strings.Contains(out, key) || strings.Contains(out, strings.TrimRight(key, "=")) {
				t.Fatalf("format %q of %T leaks key material: %s", verb, target, out)
			}
		}
	}
}

func TestKeyringLookupIsExactAndCaseSensitive(t *testing.T) {
	t.Parallel()

	key := keyringKey(0x11)
	ring, err := ParseKeyring("Key1:" + key + ",key1:" + keyringKey(0x22))
	if err != nil {
		t.Fatalf("ParseKeyring() error = %v", err)
	}

	if _, ok := ring.lookup("Key1"); !ok {
		t.Error("lookup(Key1) = false")
	}
	if _, ok := ring.lookup("key1"); !ok {
		t.Error("lookup(key1) = false")
	}
	for _, kid := range []string{"KEY1", "key", "", "Key1 "} {
		if _, ok := ring.lookup(kid); ok {
			t.Errorf("lookup(%q) = true", kid)
		}
	}
}

func TestKeyringConcurrentReads(t *testing.T) {
	t.Parallel()

	ring, err := ParseKeyring("k1:" + keyringKey(0x11) + ",k2:" + keyringKey(0x22))
	if err != nil {
		t.Fatalf("ParseKeyring() error = %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if _, ok := ring.lookup("k2"); !ok {
					t.Error("lookup(k2) = false")
					return
				}
				if ring.ActiveKeyID() != "k1" {
					t.Error("ActiveKeyID() = " + ring.ActiveKeyID())
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestNilKeyring(t *testing.T) {
	t.Parallel()

	var ring *Keyring
	if ring.ActiveKeyID() != "" {
		t.Errorf("nil ActiveKeyID() = %q", ring.ActiveKeyID())
	}
	if _, ok := ring.lookup("k1"); ok {
		t.Error("nil lookup() = true")
	}
	if _, ok := ring.active(); ok {
		t.Error("nil active() = true")
	}
}
