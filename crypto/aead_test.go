package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/kaiizer777/go-auth/errors"
)

func keyringSpec(kid string, fill byte) string {
	return kid + ":" + keyringKey(fill)
}

func newTestSealer(t *testing.T, spec string) *TokenSealer {
	t.Helper()

	ring, err := ParseKeyring(spec)
	if err != nil {
		t.Fatalf("ParseKeyring() error = %v", err)
	}
	return NewTokenSealer(ring)
}

func decodeTokenEnvelope(t *testing.T, raw string) map[string]any {
	t.Helper()

	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	return doc
}

func encodeTokenEnvelope(t *testing.T, doc map[string]any) string {
	t.Helper()

	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-encode envelope: %v", err)
	}
	return string(encoded)
}

func TestTokenSealerRoundtrip(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	operations := []struct {
		name string
		seal func(providerID, accountID, plaintext string) (string, error)
		open func(providerID, accountID, envelope string) (string, error)
	}{
		{name: "access", seal: sealer.SealAccessToken, open: sealer.OpenAccessToken},
		{name: "refresh", seal: sealer.SealRefreshToken, open: sealer.OpenRefreshToken},
	}

	for _, op := range operations {
		for _, size := range []int{0, 1, 64, maxTokenPlaintext} {
			plaintext := strings.Repeat("t", size)
			envelope, err := op.seal("github", "acct-1", plaintext)
			if err != nil {
				t.Fatalf("%s seal(%d bytes) error = %v", op.name, size, err)
			}
			got, err := op.open("github", "acct-1", envelope)
			if err != nil {
				t.Fatalf("%s open(%d bytes) error = %v", op.name, size, err)
			}
			if got != plaintext {
				t.Fatalf("%s roundtrip(%d bytes) mismatch", op.name, size)
			}
		}
	}
}

func TestTokenEnvelopeShape(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	plaintext := "token-value"
	envelope, err := sealer.SealAccessToken("github", "acct-1", plaintext)
	if err != nil {
		t.Fatalf("SealAccessToken() error = %v", err)
	}
	if strings.HasSuffix(envelope, "\n") {
		t.Fatal("envelope has trailing newline")
	}

	doc := decodeTokenEnvelope(t, envelope)
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

	nonce, err := base64.RawURLEncoding.DecodeString(doc["n"].(string))
	if err != nil || len(nonce) != gcmNonceSize {
		t.Fatalf("nonce decode length = %d, err = %v", len(nonce), err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(doc["ct"].(string))
	if err != nil {
		t.Fatalf("ct decode error = %v", err)
	}
	if want := len(plaintext) + gcmTagSize; len(ciphertext) != want {
		t.Errorf("ciphertext length = %d, want %d", len(ciphertext), want)
	}
}

func TestTokenSealFreshNonce(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	first, err := sealer.SealAccessToken("github", "acct-1", "same-token")
	if err != nil {
		t.Fatalf("first seal error = %v", err)
	}
	second, err := sealer.SealAccessToken("github", "acct-1", "same-token")
	if err != nil {
		t.Fatalf("second seal error = %v", err)
	}

	firstDoc := decodeTokenEnvelope(t, first)
	secondDoc := decodeTokenEnvelope(t, second)
	if firstDoc["n"] == secondDoc["n"] {
		t.Error("nonces repeat across seals")
	}
	if firstDoc["ct"] == secondDoc["ct"] {
		t.Error("ciphertexts repeat across seals")
	}
}

func TestTokenOpenUnknownKid(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	envelope, err := sealer.SealAccessToken("github", "acct-1", "token")
	if err != nil {
		t.Fatalf("SealAccessToken() error = %v", err)
	}

	other := newTestSealer(t, keyringSpec("k2", 0x22))
	got, err := other.OpenAccessToken("github", "acct-1", envelope)
	if !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("open with other keyring error = %v, want ErrUnknownKeyID", err)
	}
	if got != "" {
		t.Fatalf("open with unknown kid returned plaintext %q", got)
	}
}

func TestTokenOpenWrongKeyBytes(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	envelope, err := sealer.SealAccessToken("github", "acct-1", "token")
	if err != nil {
		t.Fatalf("SealAccessToken() error = %v", err)
	}

	impostor := newTestSealer(t, keyringSpec("k1", 0x22))
	got, err := impostor.OpenAccessToken("github", "acct-1", envelope)
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("open with wrong key bytes error = %v, want ErrAuthenticationFailed", err)
	}
	if got != "" {
		t.Fatalf("open with wrong key bytes returned plaintext %q", got)
	}
}

func TestTokenOpenRejectsTampering(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11)+","+keyringSpec("k2", 0x22))
	envelope, err := sealer.SealAccessToken("github", "acct-1", "token")
	if err != nil {
		t.Fatalf("SealAccessToken() error = %v", err)
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

	sealedDoc := decodeTokenEnvelope(t, envelope)
	flippedCiphertext := flip(t, sealedDoc["ct"].(string))
	flippedNonce := flip(t, sealedDoc["n"].(string))

	tests := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr error
	}{
		{
			name: "ct flipped",
			mutate: func(doc map[string]any) {
				doc["ct"] = flippedCiphertext
			},
			wantErr: ErrAuthenticationFailed,
		},
		{
			name: "nonce flipped",
			mutate: func(doc map[string]any) {
				doc["n"] = flippedNonce
			},
			wantErr: ErrAuthenticationFailed,
		},
		{
			name:    "kid swapped to known key",
			mutate:  func(doc map[string]any) { doc["kid"] = "k2" },
			wantErr: ErrAuthenticationFailed,
		},
		{
			name:    "kid unknown",
			mutate:  func(doc map[string]any) { doc["kid"] = "zz" },
			wantErr: ErrUnknownKeyID,
		},
		{
			name:    "kid missing",
			mutate:  func(doc map[string]any) { delete(doc, "kid") },
			wantErr: ErrEnvelopeMalformed,
		},
		{
			name:    "version downgraded",
			mutate:  func(doc map[string]any) { doc["v"] = 2 },
			wantErr: ErrEnvelopeMalformed,
		},
		{
			name:    "version wrong type",
			mutate:  func(doc map[string]any) { doc["v"] = "1" },
			wantErr: ErrEnvelopeMalformed,
		},
		{
			name:    "alg downgraded",
			mutate:  func(doc map[string]any) { doc["alg"] = "A128GCM" },
			wantErr: ErrEnvelopeMalformed,
		},
		{
			name:    "alg missing",
			mutate:  func(doc map[string]any) { delete(doc, "alg") },
			wantErr: ErrEnvelopeMalformed,
		},
		{
			name:    "ct missing",
			mutate:  func(doc map[string]any) { delete(doc, "ct") },
			wantErr: ErrEnvelopeMalformed,
		},
		{
			name:    "ct invalid base64",
			mutate:  func(doc map[string]any) { doc["ct"] = "***" },
			wantErr: ErrEnvelopeMalformed,
		},
		{
			name: "ct truncated below tag",
			mutate: func(doc map[string]any) {
				doc["ct"] = base64.RawURLEncoding.EncodeToString([]byte("short"))
			},
			wantErr: ErrEnvelopeMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := decodeTokenEnvelope(t, envelope)
			tt.mutate(doc)
			got, err := sealer.OpenAccessToken("github", "acct-1", encodeTokenEnvelope(t, doc))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("open error = %v, want %v", err, tt.wantErr)
			}
			if got != "" {
				t.Fatalf("tampered envelope returned plaintext %q", got)
			}
		})
	}
}

func TestTokenOpenRejectsBadNonceLength(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	envelope, err := sealer.SealAccessToken("github", "acct-1", "token")
	if err != nil {
		t.Fatalf("SealAccessToken() error = %v", err)
	}

	for _, size := range []int{0, 11, 13} {
		doc := decodeTokenEnvelope(t, envelope)
		doc["n"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, size))
		if _, err := sealer.OpenAccessToken("github", "acct-1", encodeTokenEnvelope(t, doc)); !errors.Is(err, ErrEnvelopeMalformed) {
			t.Fatalf("nonce length %d error = %v, want ErrEnvelopeMalformed", size, err)
		}
	}
}

func TestTokenOpenRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	for _, envelope := range []string{"", "not-json", "{", "[]", `{"v":1,"alg":"A256GCM","kid":"k1","n":"","ct":""}`} {
		got, err := sealer.OpenAccessToken("github", "acct-1", envelope)
		if !errors.Is(err, ErrEnvelopeMalformed) {
			t.Fatalf("open(%q) error = %v, want ErrEnvelopeMalformed", envelope, err)
		}
		if got != "" {
			t.Fatalf("open(%q) returned plaintext %q", envelope, got)
		}
	}
}

func TestTokenOpenIgnoresUnknownFields(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	envelope, err := sealer.SealAccessToken("github", "acct-1", "token")
	if err != nil {
		t.Fatalf("SealAccessToken() error = %v", err)
	}

	extended := strings.Replace(envelope, "{", `{"future":{"nested":true},"beta":2,`, 1)
	got, err := sealer.OpenAccessToken("github", "acct-1", extended)
	if err != nil {
		t.Fatalf("open with unknown fields error = %v", err)
	}
	if got != "token" {
		t.Fatalf("open with unknown fields = %q", got)
	}
}

func TestTokenOpenDuplicateJSONKeysUseLastValue(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	envelope, err := sealer.SealAccessToken("github", "acct-1", "token")
	if err != nil {
		t.Fatalf("SealAccessToken() error = %v", err)
	}

	duplicated := strings.Replace(envelope, `"kid":"k1"`, `"kid":"zz","kid":"k1"`, 1)
	got, err := sealer.OpenAccessToken("github", "acct-1", duplicated)
	if err != nil {
		t.Fatalf("open with duplicate kid error = %v", err)
	}
	if got != "token" {
		t.Fatalf("open with duplicate kid = %q", got)
	}
}

// nonCanonicalBase64URLVariant returns an encoding of the same bytes whose
// trailing bits differ: the default decoder accepts it, the strict one rejects
// it.
func nonCanonicalBase64URLVariant(t *testing.T, encoded string) string {
	t.Helper()

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	want, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode envelope body: %v", err)
	}

	last := len(encoded) - 1
	for i := 0; i < len(alphabet); i++ {
		variant := encoded[:last] + string(alphabet[i])
		if variant == encoded {
			continue
		}
		got, err := base64.RawURLEncoding.DecodeString(variant)
		if err != nil || !bytes.Equal(got, want) {
			continue
		}
		if _, err := base64.RawURLEncoding.Strict().DecodeString(variant); err == nil {
			continue
		}
		return variant
	}
	t.Fatal("no non-canonical variant of the envelope body found")
	return ""
}

func TestTokenOpenRejectsNonCanonicalEnvelopeEncoding(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	// Three plaintext bytes plus the tag give a body whose encoding ends in
	// unused bits, which is where a non-strict decoder normalises.
	envelope, err := sealer.SealAccessToken("github", "acct-1", "tok")
	if err != nil {
		t.Fatalf("SealAccessToken() error = %v", err)
	}

	doc := decodeTokenEnvelope(t, envelope)
	body, _ := doc["ct"].(string)
	if body == "" {
		t.Fatal("envelope has no ciphertext body")
	}
	doc["ct"] = nonCanonicalBase64URLVariant(t, body)
	mutated := encodeTokenEnvelope(t, doc)

	got, err := sealer.OpenAccessToken("github", "acct-1", mutated)
	if !errors.Is(err, ErrEnvelopeMalformed) {
		t.Fatalf("open of a non-canonical body = (%q, %v), want ErrEnvelopeMalformed", got, err)
	}
}

func TestTokenAADLengthPrefixesBlockShiftCollisions(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	// Each pair joins to the same string once the length prefixes are dropped,
	// which is the collision the prefixes exist to prevent.
	pairs := []struct {
		provider      string
		account       string
		otherProvider string
		otherAccount  string
	}{
		{provider: "a:b", account: "c", otherProvider: "a", otherAccount: "b:c"},
		{provider: "a\x00b", account: "c", otherProvider: "a", otherAccount: "b\x00c"},
	}

	for _, pair := range pairs {
		envelope, err := sealer.SealAccessToken(pair.provider, pair.account, "token")
		if err != nil {
			t.Fatalf("SealAccessToken(%q, %q) error = %v", pair.provider, pair.account, err)
		}
		got, err := sealer.OpenAccessToken(pair.otherProvider, pair.otherAccount, envelope)
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("open under (%q, %q) = (%q, %v), want ErrAuthenticationFailed",
				pair.otherProvider, pair.otherAccount, got, err)
		}
	}
}

func TestTokenRejectsCrossFieldAndCrossRowReplay(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	envelope, err := sealer.SealAccessToken("github", "acct-1", "token")
	if err != nil {
		t.Fatalf("SealAccessToken() error = %v", err)
	}

	tests := []struct {
		name string
		run  func() (string, error)
	}{
		{
			name: "other account",
			run:  func() (string, error) { return sealer.OpenAccessToken("github", "acct-2", envelope) },
		},
		{
			name: "other provider",
			run:  func() (string, error) { return sealer.OpenAccessToken("gitlab", "acct-1", envelope) },
		},
		{
			name: "other field",
			run:  func() (string, error) { return sealer.OpenRefreshToken("github", "acct-1", envelope) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.run()
			if !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("open error = %v, want ErrAuthenticationFailed", err)
			}
			if got != "" {
				t.Fatalf("replayed envelope returned plaintext %q", got)
			}
		})
	}
}

func TestTokenSealerRotation(t *testing.T) {
	t.Parallel()

	oldSealer := newTestSealer(t, keyringSpec("k1", 0x11))
	rotated := newTestSealer(t, keyringSpec("k2", 0x22)+","+keyringSpec("k1", 0x11))

	oldEnvelope, err := oldSealer.SealAccessToken("github", "acct-1", "old-token")
	if err != nil {
		t.Fatalf("old seal error = %v", err)
	}
	newEnvelope, err := rotated.SealAccessToken("github", "acct-1", "new-token")
	if err != nil {
		t.Fatalf("rotated seal error = %v", err)
	}

	if kid := decodeTokenEnvelope(t, newEnvelope)["kid"]; kid != "k2" {
		t.Fatalf("rotated seal kid = %v, want k2", kid)
	}
	if got, err := rotated.OpenAccessToken("github", "acct-1", newEnvelope); err != nil || got != "new-token" {
		t.Fatalf("rotated open new envelope = %q, %v", got, err)
	}
	if got, err := rotated.OpenAccessToken("github", "acct-1", oldEnvelope); err != nil || got != "old-token" {
		t.Fatalf("rotated open old envelope = %q, %v", got, err)
	}
	if _, err := oldSealer.OpenAccessToken("github", "acct-1", newEnvelope); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("old keyring open new envelope error = %v, want ErrUnknownKeyID", err)
	}
}

func TestTokenSealerSizeLimits(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))

	if _, err := sealer.SealAccessToken("github", "acct-1", strings.Repeat("t", maxTokenPlaintext+1)); !errors.Is(err, ErrPlaintextTooLarge) {
		t.Fatalf("seal over plaintext cap error = %v, want ErrPlaintextTooLarge", err)
	}

	if _, err := sealer.OpenAccessToken("github", "acct-1", strings.Repeat("x", maxTokenEnvelope)); errors.Is(err, ErrEnvelopeTooLarge) {
		t.Fatalf("open at envelope cap error = %v, want malformed", err)
	}
	if _, err := sealer.OpenAccessToken("github", "acct-1", strings.Repeat("x", maxTokenEnvelope+1)); !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Fatalf("open over envelope cap error = %v, want ErrEnvelopeTooLarge", err)
	}
}

func TestTokenSealerUnconfigured(t *testing.T) {
	t.Parallel()

	var nilSealer *TokenSealer
	if _, err := nilSealer.SealAccessToken("github", "acct-1", "token"); !errors.Is(err, ErrSealerUnconfigured) {
		t.Fatalf("nil sealer seal error = %v", err)
	}
	if _, err := nilSealer.OpenAccessToken("github", "acct-1", "{}"); !errors.Is(err, ErrSealerUnconfigured) {
		t.Fatalf("nil sealer open error = %v", err)
	}

	empty := NewTokenSealer(&Keyring{})
	if _, err := empty.SealAccessToken("github", "acct-1", "token"); !errors.Is(err, ErrSealerUnconfigured) {
		t.Fatalf("empty keyring seal error = %v", err)
	}
	if _, err := empty.OpenAccessToken("github", "acct-1", "{}"); !errors.Is(err, ErrSealerUnconfigured) {
		t.Fatalf("empty keyring open error = %v", err)
	}
}

func TestTokenSealEntropyFailure(t *testing.T) {
	original := randReader
	defer func() { randReader = original }()
	randReader = iotest.ErrReader(io.ErrUnexpectedEOF)

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	got, err := sealer.SealAccessToken("github", "acct-1", "token")
	if !errors.Is(err, ErrSealFailed) {
		t.Fatalf("seal with failing entropy error = %v, want ErrSealFailed", err)
	}
	if got != "" {
		t.Fatalf("seal with failing entropy returned envelope %q", got)
	}
}

func TestTokenErrorsDoNotLeakEnvelopeContent(t *testing.T) {
	t.Parallel()

	sealer := newTestSealer(t, keyringSpec("k1", 0x11))
	plaintext := "secret-token-value"
	envelope, err := sealer.SealAccessToken("github", "acct-1", plaintext)
	if err != nil {
		t.Fatalf("SealAccessToken() error = %v", err)
	}
	doc := decodeTokenEnvelope(t, envelope)
	nonce := doc["n"].(string)
	ciphertext := doc["ct"].(string)

	failures := []func() error{
		func() error {
			mutated := decodeTokenEnvelope(t, envelope)
			mutated["ct"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x00}, 32))
			_, err := sealer.OpenAccessToken("github", "acct-1", encodeTokenEnvelope(t, mutated))
			return err
		},
		func() error {
			mutated := decodeTokenEnvelope(t, envelope)
			mutated["kid"] = "attacker-controlled-kid"
			_, err := sealer.OpenAccessToken("github", "acct-1", encodeTokenEnvelope(t, mutated))
			return err
		},
		func() error {
			_, err := sealer.OpenAccessToken("github", "acct-2", envelope)
			return err
		},
	}

	for _, fail := range failures {
		err := fail()
		if err == nil {
			t.Fatal("expected failure")
		}
		for _, secret := range []string{nonce, ciphertext, plaintext, "attacker-controlled-kid"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error %q leaks %q", err, secret)
			}
		}
	}
}

func TestRefreshTokenFingerprint(t *testing.T) {
	t.Parallel()

	first := newTestSealer(t, keyringSpec("k1", 0x11))
	second := newTestSealer(t, keyringSpec("k2", 0x22))

	fingerprint, err := first.RefreshTokenFingerprint("refresh-token")
	if err != nil {
		t.Fatalf("RefreshTokenFingerprint() error = %v", err)
	}
	if len(fingerprint) != 64 {
		t.Fatalf("fingerprint length = %d, want 64", len(fingerprint))
	}
	for _, c := range fingerprint {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("fingerprint %q is not lowercase hex", fingerprint)
		}
	}

	rotated, err := second.RefreshTokenFingerprint("refresh-token")
	if err != nil {
		t.Fatalf("RefreshTokenFingerprint() with other keyring error = %v", err)
	}
	if rotated != fingerprint {
		t.Fatalf("fingerprint depends on keyring: %q != %q", rotated, fingerprint)
	}

	distinct, err := first.RefreshTokenFingerprint("other-token")
	if err != nil {
		t.Fatalf("RefreshTokenFingerprint() error = %v", err)
	}
	if distinct == fingerprint {
		t.Fatal("distinct tokens share a fingerprint")
	}

	if _, err := first.RefreshTokenFingerprint(""); !errors.Is(err, ErrEmptyRefreshToken) {
		t.Fatalf("empty token error = %v, want ErrEmptyRefreshToken", err)
	}
}

// TestTokenAADBytesPinned pins the exact additional data a stored OAuth token is
// authenticated with. Reordering or reformatting the components would silently
// make every token written before the change unreadable, so this test builds the
// bytes by hand and GCM-opens a real envelope with them.
func TestTokenAADBytesPinned(t *testing.T) {
	t.Parallel()

	const kid, providerID, accountID, field = "k1", "github", "acct-1", "access_token"

	sealer := newTestSealer(t, keyringSpec(kid, 0x11))
	envelope, err := sealer.SealAccessToken(providerID, accountID, "token")
	if err != nil {
		t.Fatalf("SealAccessToken() error = %v", err)
	}

	doc := decodeTokenEnvelope(t, envelope)
	nonce, err := base64.RawURLEncoding.DecodeString(doc["n"].(string))
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(doc["ct"].(string))
	if err != nil {
		t.Fatalf("decode ct: %v", err)
	}

	// label | u32be len | component, for kid, provider, account, field.
	aad := []byte("goauth.oauth.token/v1")
	for _, component := range []string{kid, providerID, accountID, field} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(component)))
		aad = append(aad, length[:]...)
		aad = append(aad, component...)
	}

	block, err := aes.NewCipher(testKeyBytes(t, 0x11))
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("hand-written token AAD does not authenticate the envelope: %v", err)
	}
	if string(plaintext) != "token" {
		t.Fatalf("hand-written token AAD opened %q", plaintext)
	}
}
