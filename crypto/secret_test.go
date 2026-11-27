package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kaiizer777/go-auth/errors"
)

const (
	testSecretSubject = "6f1d9a8e-1111-4a2b-9c3d-2b7f5e4d3c21"
	testSecretOther   = "0a2b3c4d-2222-4d5e-8f90-123456789abc"
	testSecretField   = "encrypted_secret"
)

func newTestSecretSealer(t *testing.T, spec string) *SecretSealer {
	t.Helper()

	ring, err := ParseKeyring(spec)
	if err != nil {
		t.Fatalf("ParseKeyring() error = %v", err)
	}
	return NewSecretSealer(ring)
}

// legacySeal reproduces the pre-envelope layout: nonce || ciphertext || tag
// under a bare AES-256-GCM key, with no AAD.
func legacySeal(t *testing.T, key []byte, plaintext []byte) []byte {
	t.Helper()

	gcm := newTestGCM(t, key)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

func newTestGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()

	var material keyMaterial
	copy(material[:], key)
	aead, err := newEnvelopeAEAD(material)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	return aead
}

func decodeSecretEnvelope(t *testing.T, blob []byte) map[string]any {
	t.Helper()

	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("sealed secret is not JSON: %v", err)
	}
	return doc
}

func TestSecretSealerRoundtrip(t *testing.T) {
	t.Parallel()

	sealer := newTestSecretSealer(t, keyringSpec("k1", 0x11))
	plaintexts := [][]byte{
		{},
		[]byte("JBSWY3DPEHPK3PXP"),
		bytes.Repeat([]byte("A"), maxSecretPlaintext),
	}

	for _, plaintext := range plaintexts {
		blob, err := sealer.Seal(testSecretSubject, testSecretField, plaintext)
		if err != nil {
			t.Fatalf("Seal(%d bytes) error = %v", len(plaintext), err)
		}
		got, err := sealer.Open(testSecretSubject, testSecretField, blob)
		if err != nil {
			t.Fatalf("Open(%d bytes) error = %v", len(plaintext), err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("roundtrip(%d bytes) mismatch", len(plaintext))
		}
	}
}

func TestSecretSealRejectsOversizedPlaintext(t *testing.T) {
	t.Parallel()

	sealer := newTestSecretSealer(t, keyringSpec("k1", 0x11))
	if _, err := sealer.Seal(testSecretSubject, testSecretField, bytes.Repeat([]byte("A"), maxSecretPlaintext+1)); !errors.Is(err, ErrPlaintextTooLarge) {
		t.Fatalf("Seal over cap error = %v, want ErrPlaintextTooLarge", err)
	}
}

func TestSecretEnvelopeShape(t *testing.T) {
	t.Parallel()

	sealer := newTestSecretSealer(t, keyringSpec("k1", 0x11))
	blob, err := sealer.Seal(testSecretSubject, testSecretField, []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	doc := decodeSecretEnvelope(t, blob)
	if len(doc) != 5 {
		t.Fatalf("envelope fields = %d, want 5: %v", len(doc), doc)
	}
	if doc["v"] != float64(tokenEnvelopeVersion) {
		t.Errorf("v = %v", doc["v"])
	}
	if doc["alg"] != tokenEnvelopeAlg {
		t.Errorf("alg = %v", doc["alg"])
	}
	if doc["kid"] != "k1" {
		t.Errorf("kid = %v", doc["kid"])
	}
	for _, field := range []string{"n", "ct"} {
		value, ok := doc[field].(string)
		if !ok || value == "" {
			t.Fatalf("%s = %v", field, doc[field])
		}
		if strings.Contains(value, "=") {
			t.Errorf("%s is not unpadded base64url: %q", field, value)
		}
	}
	if strings.Contains(string(blob), testSecretSubject) {
		t.Error("envelope embeds the owning subject; binding must live in the AAD only")
	}
}

func TestSecretSealFreshNonce(t *testing.T) {
	t.Parallel()

	sealer := newTestSecretSealer(t, keyringSpec("k1", 0x11))
	first, err := sealer.Seal(testSecretSubject, testSecretField, []byte("same-secret"))
	if err != nil {
		t.Fatalf("first seal error = %v", err)
	}
	second, err := sealer.Seal(testSecretSubject, testSecretField, []byte("same-secret"))
	if err != nil {
		t.Fatalf("second seal error = %v", err)
	}
	if decodeSecretEnvelope(t, first)["n"] == decodeSecretEnvelope(t, second)["n"] {
		t.Error("nonces repeat across seals")
	}
	if bytes.Equal(first, second) {
		t.Error("identical plaintext sealed to identical blobs")
	}
}

func TestSecretOpenBindsSubjectFieldAndLabel(t *testing.T) {
	t.Parallel()

	sealer := newTestSecretSealer(t, keyringSpec("k1", 0x11))
	blob, err := sealer.Seal(testSecretSubject, testSecretField, []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	tests := []struct {
		name    string
		subject string
		field   string
		blob    []byte
	}{
		{name: "other subject", subject: testSecretOther, field: testSecretField, blob: blob},
		{name: "other field", subject: testSecretSubject, field: "backup_codes", blob: blob},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := sealer.Open(tt.subject, tt.field, tt.blob)
			if !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("Open() = (%q, %v), want ErrAuthenticationFailed", got, err)
			}
		})
	}

	t.Run("token envelope pasted into a secret column", func(t *testing.T) {
		t.Parallel()
		tokens := newTestSealer(t, keyringSpec("k1", 0x11))
		tokenEnvelope, err := tokens.SealAccessToken("github", "acct-1", "JBSWY3DPEHPK3PXP")
		if err != nil {
			t.Fatalf("SealAccessToken() error = %v", err)
		}
		if _, err := sealer.Open(testSecretSubject, testSecretField, []byte(tokenEnvelope)); !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("cross-label open error = %v, want ErrAuthenticationFailed", err)
		}
	})

	t.Run("secret envelope pasted into a token column", func(t *testing.T) {
		t.Parallel()
		tokens := newTestSealer(t, keyringSpec("k1", 0x11))
		if _, err := tokens.OpenAccessToken("github", "acct-1", string(blob)); !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("cross-label open error = %v, want ErrAuthenticationFailed", err)
		}
	})
}

func TestSecretAADLengthPrefixesBlockShiftCollisions(t *testing.T) {
	t.Parallel()

	sealer := newTestSecretSealer(t, keyringSpec("k1", 0x11))
	pairs := []struct{ subject, field, otherSubject, otherField string }{
		{subject: "a:b", field: "c", otherSubject: "a", otherField: "b:c"},
		{subject: "a\x00b", field: "c", otherSubject: "a", otherField: "b\x00c"},
	}

	for _, pair := range pairs {
		blob, err := sealer.Seal(pair.subject, pair.field, []byte("secret"))
		if err != nil {
			t.Fatalf("Seal(%q, %q) error = %v", pair.subject, pair.field, err)
		}
		if _, err := sealer.Open(pair.otherSubject, pair.otherField, blob); !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("open under shifted (%q, %q) error = %v, want ErrAuthenticationFailed", pair.otherSubject, pair.otherField, err)
		}
	}
}

func TestSecretOpenRejectsTampering(t *testing.T) {
	t.Parallel()

	sealer := newTestSecretSealer(t, keyringSpec("k1", 0x11)+","+keyringSpec("k2", 0x22))
	blob, err := sealer.Seal(testSecretSubject, testSecretField, []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	flip := func(t *testing.T, value string) string {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Fatalf("decode %q: %v", value, err)
		}
		raw[0] ^= 0x01
		return base64.RawURLEncoding.EncodeToString(raw)
	}

	sealedDoc := decodeSecretEnvelope(t, blob)
	tests := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr error
	}{
		{name: "ct flipped", mutate: func(doc map[string]any) { doc["ct"] = flip(t, sealedDoc["ct"].(string)) }, wantErr: ErrAuthenticationFailed},
		{name: "nonce flipped", mutate: func(doc map[string]any) { doc["n"] = flip(t, sealedDoc["n"].(string)) }, wantErr: ErrAuthenticationFailed},
		{name: "kid swapped to known key", mutate: func(doc map[string]any) { doc["kid"] = "k2" }, wantErr: ErrAuthenticationFailed},
		{name: "kid unknown", mutate: func(doc map[string]any) { doc["kid"] = "zz" }, wantErr: ErrUnknownKeyID},
		{name: "kid missing", mutate: func(doc map[string]any) { delete(doc, "kid") }, wantErr: ErrAuthenticationFailed},
		{name: "version downgraded", mutate: func(doc map[string]any) { doc["v"] = 2 }, wantErr: ErrAuthenticationFailed},
		{name: "alg downgraded", mutate: func(doc map[string]any) { doc["alg"] = "A128GCM" }, wantErr: ErrAuthenticationFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := decodeSecretEnvelope(t, blob)
			tt.mutate(doc)
			mutated, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("re-encode envelope: %v", err)
			}
			got, err := sealer.Open(testSecretSubject, testSecretField, mutated)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Open() = (%q, %v), want %v", got, err, tt.wantErr)
			}
			if got != nil {
				t.Fatalf("tampered envelope returned plaintext %q", got)
			}
		})
	}
}

func TestSecretOpenRejectsEnvelopeOverCapWithoutLegacyFallback(t *testing.T) {
	t.Parallel()

	sealer := newTestSecretSealer(t, keyringSpec("k1", 0x11))
	oversized := `{"v":1,"alg":"A256GCM","kid":"k1","n":"` + strings.Repeat("A", maxSecretEnvelope) + `","ct":"AAAA"}`
	if _, err := sealer.Open(testSecretSubject, testSecretField, []byte(oversized)); !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Fatalf("Open(oversized) error = %v, want ErrEnvelopeTooLarge", err)
	}
}

func TestSecretOpenRejectsGarbage(t *testing.T) {
	t.Parallel()

	sealer := newTestSecretSealer(t, keyringSpec("k1", 0x11))
	for _, blob := range [][]byte{nil, {}, []byte("short"), []byte("not-json"), make([]byte, 64)} {
		if _, err := sealer.Open(testSecretSubject, testSecretField, blob); !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("Open(%d bytes) error = %v, want ErrAuthenticationFailed", len(blob), err)
		}
	}
}

func TestSecretOpenReadsLegacyBlob(t *testing.T) {
	t.Parallel()

	key := testKeyBytes(t, 0x11)
	sealer := newTestSecretSealer(t, keyringSpec("k1", 0x11))
	plaintext := []byte("JBSWY3DPEHPK3PXP")
	legacy := legacySeal(t, key, plaintext)

	got, err := sealer.Open(testSecretSubject, testSecretField, legacy)
	if err != nil {
		t.Fatalf("Open(legacy) error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Open(legacy) = %q, want %q", got, plaintext)
	}

	// Legacy blobs carry no AAD, so the subject is not bound: this is the gap the
	// rewrap closes.
	if _, err := sealer.Open(testSecretOther, testSecretField, legacy); err != nil {
		t.Fatalf("legacy blob is unbound by design, got %v", err)
	}
}

func TestSecretOpenLegacyUnderAnyRingEntry(t *testing.T) {
	t.Parallel()

	retired := testKeyBytes(t, 0x22)
	// The operator parked the old key at the tail of the ring, not at kid "k1".
	sealer := newTestSecretSealer(t, keyringSpec("k1", 0x11)+","+keyringSpec("retired", 0x22))
	plaintext := []byte("JBSWY3DPEHPK3PXP")

	got, err := sealer.Open(testSecretSubject, testSecretField, legacySeal(t, retired, plaintext))
	if err != nil {
		t.Fatalf("Open(legacy under retired kid) error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Open(legacy under retired kid) = %q, want %q", got, plaintext)
	}
}

func TestSecretOpenLegacyBlobStartingWithBrace(t *testing.T) {
	t.Parallel()

	// A legacy nonce is random, so ~1/256 of legacy rows begin with '{', the first
	// byte of a JSON envelope. Discrimination must be parse-based. This blob was
	// captured from the AES-only implementation that wrote nonce||ct||tag.
	blob, err := hex.DecodeString("7b44ad6620c6cef98029120e4f20d744137cce0925d15d1b4b1827768f9b60509cb56503510e6a5331da7cf8")
	if err != nil {
		t.Fatalf("decode brace fixture: %v", err)
	}
	if blob[0] != '{' {
		t.Fatalf("fixture does not start with '{': %x", blob[0])
	}

	sealer := newTestSecretSealer(t, "legacy:"+legacyFixtureKey(t))
	got, err := sealer.Open(testSecretSubject, testSecretField, blob)
	if err != nil {
		t.Fatalf("Open(brace-prefixed legacy) error = %v", err)
	}
	if string(got) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Open(brace-prefixed legacy) = %q", got)
	}
}

func TestSecretSealerUnconfigured(t *testing.T) {
	t.Parallel()

	var nilSealer *SecretSealer
	if _, err := nilSealer.Seal(testSecretSubject, testSecretField, []byte("x")); !errors.Is(err, ErrSealerUnconfigured) {
		t.Fatalf("nil Seal error = %v, want ErrSealerUnconfigured", err)
	}
	if _, err := nilSealer.Open(testSecretSubject, testSecretField, []byte("x")); !errors.Is(err, ErrSealerUnconfigured) {
		t.Fatalf("nil Open error = %v, want ErrSealerUnconfigured", err)
	}

	empty := NewSecretSealer(nil)
	if _, err := empty.Seal(testSecretSubject, testSecretField, []byte("x")); !errors.Is(err, ErrSealerUnconfigured) {
		t.Fatalf("empty Seal error = %v, want ErrSealerUnconfigured", err)
	}
	if _, err := empty.Open(testSecretSubject, testSecretField, legacySeal(t, testKeyBytes(t, 0x11), []byte("x"))); !errors.Is(err, ErrSealerUnconfigured) {
		t.Fatalf("empty Open error = %v, want ErrSealerUnconfigured", err)
	}
}

func TestSecretEnvelopeKeyID(t *testing.T) {
	t.Parallel()

	sealer := newTestSecretSealer(t, keyringSpec("k1", 0x11))
	blob, err := sealer.Seal(testSecretSubject, testSecretField, []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if kid, ok := sealer.EnvelopeKeyID(blob); !ok || kid != "k1" {
		t.Fatalf("EnvelopeKeyID() = (%q, %v), want (k1, true)", kid, ok)
	}

	// A retired kid is still structurally readable: the sweep needs it to decide.
	retired, err := NewSecretSealer(mustKeyring(t, keyringSpec("old", 0x22))).Seal(testSecretSubject, testSecretField, []byte("x"))
	if err != nil {
		t.Fatalf("retired Seal() error = %v", err)
	}
	if kid, ok := sealer.EnvelopeKeyID(retired); !ok || kid != "old" {
		t.Fatalf("EnvelopeKeyID(retired) = (%q, %v), want (old, true)", kid, ok)
	}

	if kid, ok := sealer.EnvelopeKeyID(legacySeal(t, testKeyBytes(t, 0x11), []byte("x"))); ok {
		t.Fatalf("EnvelopeKeyID(legacy) = (%q, true), want not ok", kid)
	}
	if _, ok := sealer.EnvelopeKeyID([]byte("garbage")); ok {
		t.Fatal("EnvelopeKeyID(garbage) reported an envelope")
	}
}

func mustKeyring(t *testing.T, spec string) *Keyring {
	t.Helper()

	ring, err := ParseKeyring(spec)
	if err != nil {
		t.Fatalf("ParseKeyring() error = %v", err)
	}
	return ring
}

func testKeyBytes(t *testing.T, fill byte) []byte {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(keyringKey(fill))
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	return raw
}

// legacyFixtureKey is the key the legacy TOTP fixtures in totp/testdata were
// sealed with, in the kid:base64 grammar ParseKeyring accepts.
func legacyFixtureKey(t *testing.T) string {
	t.Helper()

	raw, err := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("decode fixture key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
