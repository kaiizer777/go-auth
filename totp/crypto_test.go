package totp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	ptotp "github.com/pquerna/otp/totp"

	"github.com/kaiizer777/go-auth/errors"
)

func validTestHexKey() string {
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

func TestNewCrypto_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		hexKey  string
		wantErr bool
	}{
		{
			name:    "valid 64 hex characters (32 bytes)",
			hexKey:  validTestHexKey(),
			wantErr: false,
		},
		{
			name:    "too short key",
			hexKey:  "0123456789abcdef",
			wantErr: true,
		},
		{
			name:    "too long key",
			hexKey:  strings.Repeat("a", 66),
			wantErr: true,
		},
		{
			name:    "non-hex characters",
			hexKey:  strings.Repeat("z", 64),
			wantErr: true,
		},
		{
			name:    "empty key",
			hexKey:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := NewCrypto(tt.hexKey)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				if !errors.Is(err, errors.ErrTOTPEncryptionKeyInvalid) {
					t.Errorf("expected ErrTOTPEncryptionKeyInvalid, got %v", err)
				}
				if c != nil {
					t.Errorf("expected nil Crypto, got %+v", c)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if c == nil {
					t.Fatalf("expected non-nil Crypto")
				}
			}
		})
	}
}

func TestNewCryptoFromBytes(t *testing.T) {
	t.Parallel()

	raw := make([]byte, 32)
	_, _ = rand.Read(raw)

	c, err := NewCryptoFromBytes(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil crypto")
	}

	short := make([]byte, 16)
	_, err = NewCryptoFromBytes(short)
	if !errors.Is(err, errors.ErrTOTPEncryptionKeyInvalid) {
		t.Errorf("expected ErrTOTPEncryptionKeyInvalid for short byte key, got %v", err)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	c, err := NewCrypto(validTestHexKey())
	if err != nil {
		t.Fatalf("failed to init crypto: %v", err)
	}

	messages := [][]byte{
		[]byte("JBSWY3DPEHPK3PXP"),
		[]byte("short"),
		[]byte(""),
		bytes.Repeat([]byte("A"), 1024),
	}

	for _, original := range messages {
		encrypted, err := c.Encrypt(original)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		decrypted, err := c.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		if !bytes.Equal(original, decrypted) {
			t.Errorf("got %q, want %q", decrypted, original)
		}
	}
}

func TestEncryptProducesUniqueNonce(t *testing.T) {
	t.Parallel()

	c, err := NewCrypto(validTestHexKey())
	if err != nil {
		t.Fatalf("failed to init crypto: %v", err)
	}

	plaintext := []byte("JBSWY3DPEHPK3PXP")
	enc1, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("enc1 failed: %v", err)
	}
	enc2, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("enc2 failed: %v", err)
	}

	if bytes.Equal(enc1, enc2) {
		t.Fatal("subsequent encryptions of identical plaintext produced identical ciphertexts (nonce reuse)")
	}

	// 12-byte nonces must differ
	nonce1 := enc1[:12]
	nonce2 := enc2[:12]
	if bytes.Equal(nonce1, nonce2) {
		t.Fatal("nonces were identical across encryptions")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	t.Parallel()

	c, err := NewCrypto(validTestHexKey())
	if err != nil {
		t.Fatalf("failed to init crypto: %v", err)
	}

	plaintext := []byte("top-secret-totp-seed")
	blob, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Tamper in nonce region
	tamperedNonce := make([]byte, len(blob))
	copy(tamperedNonce, blob)
	tamperedNonce[0] ^= 0x01
	if _, err := c.Decrypt(tamperedNonce); err == nil {
		t.Error("tampered nonce decrypted successfully; expected authentication failure")
	}

	// Tamper in ciphertext region
	tamperedCipher := make([]byte, len(blob))
	copy(tamperedCipher, blob)
	tamperedCipher[len(tamperedCipher)-1] ^= 0xFF
	if _, err := c.Decrypt(tamperedCipher); err == nil {
		t.Error("tampered ciphertext decrypted successfully; expected authentication failure")
	}
}

func TestDecryptCiphertextTooShort(t *testing.T) {
	t.Parallel()

	c, err := NewCrypto(validTestHexKey())
	if err != nil {
		t.Fatalf("failed to init crypto: %v", err)
	}

	shortBlobs := [][]byte{
		nil,
		{},
		[]byte("too-short"),
		make([]byte, 11),
	}

	for _, b := range shortBlobs {
		if _, err := c.Decrypt(b); err == nil {
			t.Errorf("decrypting short blob of len %d succeeded, expected error", len(b))
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
