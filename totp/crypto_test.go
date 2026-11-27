package totp

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	ptotp "github.com/pquerna/otp/totp"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/errors"
)

// legacyFixtureSecret is the plaintext inside the pre-envelope fixtures in
// testdata, captured from the AES-only implementation before it was removed.
const legacyFixtureSecret = "JBSWY3DPEHPK3PXP"

func validTestHexKey() string {
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

func testKeyringSpec(kid string, fill byte) string {
	return kid + ":" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func newTestTOTPCrypto(t *testing.T, cfg config.TOTPConfig) *Crypto {
	t.Helper()

	c, err := NewCrypto(cfg)
	if err != nil {
		t.Fatalf("NewCrypto() error = %v", err)
	}
	return c
}

func readLegacyFixture(t *testing.T, name string) []byte {
	t.Helper()

	encoded, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	blob, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	return blob
}

func TestNewCrypto_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     config.TOTPConfig
		wantErr error
	}{
		{name: "hex key only", cfg: config.TOTPConfig{EncryptionKey: validTestHexKey()}},
		{name: "keyring only", cfg: config.TOTPConfig{Keyring: testKeyringSpec("k1", 0x42)}},
		{name: "keyring beside the hex key", cfg: config.TOTPConfig{EncryptionKey: validTestHexKey(), Keyring: testKeyringSpec("k1", 0x42)}},
		{name: "too short key", cfg: config.TOTPConfig{EncryptionKey: "0123456789abcdef"}, wantErr: errors.ErrTOTPEncryptionKeyInvalid},
		{name: "too long key", cfg: config.TOTPConfig{EncryptionKey: strings.Repeat("a", 66)}, wantErr: errors.ErrTOTPEncryptionKeyInvalid},
		{name: "non-hex characters", cfg: config.TOTPConfig{EncryptionKey: strings.Repeat("z", 64)}, wantErr: errors.ErrTOTPEncryptionKeyInvalid},
		{name: "empty key and keyring", cfg: config.TOTPConfig{}, wantErr: errors.ErrTOTPEncryptionKeyInvalid},
		{name: "malformed keyring", cfg: config.TOTPConfig{Keyring: "k1:not-base64"}, wantErr: errors.ErrTOTPKeyringInvalid},
		{
			name:    "keyring reusing the legacy kid",
			cfg:     config.TOTPConfig{EncryptionKey: validTestHexKey(), Keyring: testKeyringSpec(legacyKeyID, 0x42)},
			wantErr: errors.ErrTOTPKeyringInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, err := NewCrypto(tt.cfg)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NewCrypto() error = %v, want %v", err, tt.wantErr)
				}
				if c != nil {
					t.Fatalf("expected nil Crypto, got %+v", c)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewCrypto() error = %v", err)
			}
			if c == nil {
				t.Fatal("expected non-nil Crypto")
			}
		})
	}
}

func TestCryptoActiveKeyID(t *testing.T) {
	t.Parallel()

	hexOnly := newTestTOTPCrypto(t, config.TOTPConfig{EncryptionKey: validTestHexKey()})
	if got := hexOnly.ActiveKeyID(); got != legacyKeyID {
		t.Errorf("hex-only active kid = %q, want %q", got, legacyKeyID)
	}

	both := newTestTOTPCrypto(t, config.TOTPConfig{EncryptionKey: validTestHexKey(), Keyring: testKeyringSpec("k2", 0x42)})
	if got := both.ActiveKeyID(); got != "k2" {
		t.Errorf("keyring-plus-hex active kid = %q, want k2", got)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	c := newTestTOTPCrypto(t, config.TOTPConfig{EncryptionKey: validTestHexKey()})
	owner := uuid.New()
	messages := [][]byte{
		[]byte(legacyFixtureSecret),
		[]byte("short"),
		[]byte(""),
		bytes.Repeat([]byte("A"), 1024),
	}

	for _, original := range messages {
		encrypted, err := c.Encrypt(owner, original)
		if err != nil {
			t.Fatalf("encrypt(%d bytes) failed: %v", len(original), err)
		}

		decrypted, err := c.Decrypt(owner, encrypted)
		if err != nil {
			t.Fatalf("decrypt(%d bytes) failed: %v", len(original), err)
		}
		if !bytes.Equal(original, decrypted) {
			t.Errorf("got %q, want %q", decrypted, original)
		}
	}
}

func TestEncryptWritesEnvelopeBoundToOwner(t *testing.T) {
	t.Parallel()

	owner := uuid.New()
	c := newTestTOTPCrypto(t, config.TOTPConfig{EncryptionKey: validTestHexKey()})
	blob, err := c.Encrypt(owner, []byte(legacyFixtureSecret))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if bytes.Contains(blob, []byte(legacyFixtureSecret)) {
		t.Fatal("stored blob contains the plaintext secret")
	}

	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("stored secret is not a JSON envelope: %v", err)
	}
	if doc["v"] != float64(1) || doc["alg"] != "A256GCM" {
		t.Fatalf("envelope header = (%v, %v)", doc["v"], doc["alg"])
	}
	if doc["kid"] != legacyKeyID {
		t.Errorf("envelope kid = %v, want %q", doc["kid"], legacyKeyID)
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
	if strings.Contains(string(blob), owner.String()) {
		t.Error("envelope embeds the owner id; the binding must live in the AAD only")
	}
}

func TestEncryptProducesUniqueNonce(t *testing.T) {
	t.Parallel()

	c := newTestTOTPCrypto(t, config.TOTPConfig{EncryptionKey: validTestHexKey()})
	owner := uuid.New()
	plaintext := []byte(legacyFixtureSecret)

	nonceOf := func(blob []byte) string {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(blob, &doc); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		value, _ := doc["n"].(string)
		return value
	}

	first, err := c.Encrypt(owner, plaintext)
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}
	second, err := c.Encrypt(owner, plaintext)
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}

	if nonceOf(first) == nonceOf(second) {
		t.Fatal("nonces were identical across encryptions")
	}
	if bytes.Equal(first, second) {
		t.Fatal("subsequent encryptions of identical plaintext produced identical blobs")
	}
}

func TestDecryptCrossUserTransplantFails(t *testing.T) {
	t.Parallel()

	c := newTestTOTPCrypto(t, config.TOTPConfig{EncryptionKey: validTestHexKey()})
	owner := uuid.New()
	other := uuid.New()

	blob, err := c.Encrypt(owner, []byte(legacyFixtureSecret))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	plaintext, err := c.Decrypt(other, blob)
	if err == nil {
		t.Fatalf("cross-user transplant opened to %q; AAD binding is missing", plaintext)
	}
}

func TestDecryptUppercaseUUIDOwner(t *testing.T) {
	t.Parallel()

	c := newTestTOTPCrypto(t, config.TOTPConfig{EncryptionKey: validTestHexKey()})
	owner := uuid.New()
	blob, err := c.Encrypt(owner, []byte(legacyFixtureSecret))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	upper, err := uuid.Parse(strings.ToUpper(owner.String()))
	if err != nil {
		t.Fatalf("parse uppercase uuid: %v", err)
	}
	plaintext, err := c.Decrypt(upper, blob)
	if err != nil {
		t.Fatalf("decrypt with uppercase-derived owner failed: %v", err)
	}
	if string(plaintext) != legacyFixtureSecret {
		t.Fatalf("decrypt = %q, want %q", plaintext, legacyFixtureSecret)
	}
}

func TestDecryptTamperedEnvelope(t *testing.T) {
	t.Parallel()

	c := newTestTOTPCrypto(t, config.TOTPConfig{EncryptionKey: validTestHexKey()})
	owner := uuid.New()
	blob, err := c.Encrypt(owner, []byte("top-secret-totp-seed"))
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	var sealed map[string]any
	if err := json.Unmarshal(blob, &sealed); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	flip := func(value string) string {
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Fatalf("decode %q: %v", value, err)
		}
		raw[0] ^= 0x01
		return base64.RawURLEncoding.EncodeToString(raw)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "ciphertext", mutate: func(doc map[string]any) { doc["ct"] = flip(sealed["ct"].(string)) }},
		{name: "nonce", mutate: func(doc map[string]any) { doc["n"] = flip(sealed["n"].(string)) }},
		{name: "version", mutate: func(doc map[string]any) { doc["v"] = 2 }},
		{name: "algorithm", mutate: func(doc map[string]any) { doc["alg"] = "A128GCM" }},
		{name: "kid", mutate: func(doc map[string]any) { doc["kid"] = "rotated" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := make(map[string]any, len(sealed))
			for key, value := range sealed {
				doc[key] = value
			}
			tt.mutate(doc)
			tampered, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("re-encode envelope: %v", err)
			}
			if _, err := c.Decrypt(owner, tampered); err == nil {
				t.Fatalf("tampered %s decrypted successfully; expected failure", tt.name)
			}
		})
	}

	for _, blob := range [][]byte{nil, {}, []byte("too-short")} {
		if _, err := c.Decrypt(owner, blob); err == nil {
			t.Errorf("decrypting short blob of len %d succeeded, expected error", len(blob))
		}
	}
}

func TestDecryptLegacyFixture(t *testing.T) {
	t.Parallel()

	c := newTestTOTPCrypto(t, config.TOTPConfig{EncryptionKey: validTestHexKey()})
	owner := uuid.New()

	for _, name := range []string{"legacy_secret.hex", "legacy_secret_brace.hex"} {
		blob := readLegacyFixture(t, name)
		plaintext, err := c.Decrypt(owner, blob)
		if err != nil {
			t.Fatalf("decrypt %s failed: %v", name, err)
		}
		if string(plaintext) != legacyFixtureSecret {
			t.Fatalf("decrypt %s = %q, want %q", name, plaintext, legacyFixtureSecret)
		}
	}
}

func TestDecryptLegacyFixtureUnderParkedKey(t *testing.T) {
	t.Parallel()

	// The old hex key is not the active key, but it still opens legacy rows.
	c := newTestTOTPCrypto(t, config.TOTPConfig{
		Keyring:       testKeyringSpec("rotated", 0x42),
		EncryptionKey: validTestHexKey(),
	})
	if c.ActiveKeyID() != "rotated" {
		t.Fatalf("active kid = %q, want rotated", c.ActiveKeyID())
	}

	plaintext, err := c.Decrypt(uuid.New(), readLegacyFixture(t, "legacy_secret.hex"))
	if err != nil {
		t.Fatalf("decrypt legacy row under a rotated ring failed: %v", err)
	}
	if string(plaintext) != legacyFixtureSecret {
		t.Fatalf("decrypt = %q, want %q", plaintext, legacyFixtureSecret)
	}
}

func TestEncryptRejectsOversizedPlaintext(t *testing.T) {
	t.Parallel()

	c := newTestTOTPCrypto(t, config.TOTPConfig{EncryptionKey: validTestHexKey()})
	if _, err := c.Encrypt(uuid.New(), bytes.Repeat([]byte("A"), 1025)); !errors.Is(err, crypto.ErrPlaintextTooLarge) {
		t.Fatalf("Encrypt over cap error = %v, want ErrPlaintextTooLarge", err)
	}
}

func TestPackageBuildsNoAEAD(t *testing.T) {
	t.Parallel()

	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("inspect package imports: %v", err)
	}
	for _, path := range pkg.Imports {
		if path == "crypto/aes" || path == "crypto/cipher" {
			t.Errorf("totp must delegate sealing to package crypto; it imports %s", path)
		}
	}
}

func TestGenerateSecret(t *testing.T) {
	t.Parallel()

	secret, uri, err := GenerateSecret("go-auth", "user@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	if len(secret) == 0 {
		t.Error("expected non-empty secret")
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("expected otpauth uri prefix, got %q", uri)
	}
	if !strings.Contains(uri, "issuer=go-auth") {
		t.Errorf("expected issuer in uri, got %q", uri)
	}
	if !strings.Contains(uri, "user%40example.com") && !strings.Contains(uri, "user@example.com") {
		t.Errorf("expected account in uri, got %q", uri)
	}
}

func TestGenerateQRCodeDataURI(t *testing.T) {
	t.Parallel()

	key, err := GenerateKey("go-auth", "user@example.com")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	dataURI, err := GenerateQRCodeDataURI(key, 200, 200)
	if err != nil {
		t.Fatalf("GenerateQRCodeDataURI failed: %v", err)
	}

	if !strings.HasPrefix(dataURI, "data:image/png;base64,") {
		t.Fatalf("expected data:image/png;base64 prefix, got %s", dataURI[:30])
	}
}

func TestValidateCodeCurrentStep(t *testing.T) {
	t.Parallel()

	secret, _, err := GenerateSecret("go-auth", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	now := time.Now().UTC()
	code, err := ptotp.GenerateCodeCustom(secret, now, ptotp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom failed: %v", err)
	}

	valid, err := ValidateCodeAtTime(code, secret, now)
	if err != nil {
		t.Fatalf("ValidateCodeAtTime failed: %v", err)
	}
	if !valid {
		t.Error("valid code at current step failed validation")
	}
}

func TestValidateCodeDrift(t *testing.T) {
	t.Parallel()

	secret, _, err := GenerateSecret("go-auth", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	baseTime := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	// Step T+30s (skew +1) should pass
	codePlusOne, err := ptotp.GenerateCodeCustom(secret, baseTime.Add(30*time.Second), ptotp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("code generation failed: %v", err)
	}
	valid, err := ValidateCodeAtTime(codePlusOne, secret, baseTime)
	if err != nil || !valid {
		t.Errorf("drift +1 step rejected; err: %v, valid: %v", err, valid)
	}

	// Step T-30s (skew -1) should pass
	codeMinusOne, err := ptotp.GenerateCodeCustom(secret, baseTime.Add(-30*time.Second), ptotp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("code generation failed: %v", err)
	}
	valid, err = ValidateCodeAtTime(codeMinusOne, secret, baseTime)
	if err != nil || !valid {
		t.Errorf("drift -1 step rejected; err: %v, valid: %v", err, valid)
	}

	// Step T+60s (skew +2) should fail (outside window)
	codePlusTwo, err := ptotp.GenerateCodeCustom(secret, baseTime.Add(60*time.Second), ptotp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("code generation failed: %v", err)
	}
	valid, err = ValidateCodeAtTime(codePlusTwo, secret, baseTime)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if valid {
		t.Error("drift +2 step was accepted; expected outside window rejection")
	}
}

func TestValidateCodeWrong(t *testing.T) {
	t.Parallel()

	secret, _, err := GenerateSecret("go-auth", "charlie@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	valid, _ := ValidateCode("000000", secret)
	if valid {
		t.Error("arbitrary invalid code 000000 accepted")
	}
}

func TestCodeHashDeterministic(t *testing.T) {
	t.Parallel()

	h1 := CodeHash("123456", "user-uuid-1")
	h2 := CodeHash("123456", "user-uuid-1")

	if !bytes.Equal(h1, h2) {
		t.Errorf("expected deterministic hash; got %x != %x", h1, h2)
	}
	if len(h1) != 32 {
		t.Errorf("expected 32-byte sha256 output, got %d bytes", len(h1))
	}
}

func TestCodeHashDistinct(t *testing.T) {
	t.Parallel()

	h1 := CodeHash("123456", "user-uuid-1")
	h2 := CodeHash("123456", "user-uuid-2")
	h3 := CodeHash("654321", "user-uuid-1")

	if bytes.Equal(h1, h2) {
		t.Error("different users produced identical code hash (cross-user replay hazard)")
	}
	if bytes.Equal(h1, h3) {
		t.Error("different codes produced identical hash")
	}

	// Delimiter prevents concatenation ambiguity: ("12", "34") vs ("1", "234")
	h4 := CodeHash("12", "34")
	h5 := CodeHash("1", "234")
	if bytes.Equal(h4, h5) {
		t.Error("delimiter failure: ambiguous concatenation produced identical code hash")
	}
}

func TestCodeHashString(t *testing.T) {
	t.Parallel()

	s := CodeHashString("123456")
	if len(s) != 64 {
		t.Errorf("expected 64 hex chars, got %d (%s)", len(s), s)
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		t.Errorf("invalid hex string: %v", err)
	}
}
