package crypto

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/kaiizer777/go-auth/errors"
)

const (
	keyIDMaxLength = 32
	keyBytes       = 32
	keyringTrimSet = " \t\r\n"
)

// Predefined sentinel errors for token keyring operations.
var (
	ErrKeyringMissing   = errors.New(errors.CodeInvalidConfig, "token keyring is not configured", nil)
	ErrKeyringMalformed = errors.New(errors.CodeInvalidConfig, "token keyring is malformed", nil)
)

// keyMaterial holds raw AES-256 key bytes; no formatter renders them.
type keyMaterial [keyBytes]byte

func (keyMaterial) String() string   { return "[redacted]" }
func (keyMaterial) GoString() string { return "crypto.keyMaterial{[redacted]}" }

type keyringEntry struct {
	kid string
	key keyMaterial
}

// Keyring is an immutable, concurrency-safe set of kid-keyed AES-256 keys.
// The first parsed entry encrypts; every entry can decrypt.
type Keyring struct {
	entries []keyringEntry
	byID    map[string]int
}

// String and GoString redact the whole ring. Without them a caller formatting
// the exported value would get the unexported entries field rendered by fmt,
// which prints key bytes in decimal because fmt cannot call methods through an
// unexported field.
func (Keyring) String() string   { return "[redacted]" }
func (Keyring) GoString() string { return "crypto.Keyring{[redacted]}" }

// ParseKeyring validates a `kid:base64key[,kid:base64key...]` specification.
// Empty input yields ErrKeyringMissing; any grammar violation yields an error
// wrapping ErrKeyringMalformed and no partial keyring.
func ParseKeyring(spec string) (*Keyring, error) {
	spec = strings.Trim(spec, keyringTrimSet)
	if spec == "" {
		return nil, ErrKeyringMissing
	}

	rawEntries := strings.Split(spec, ",")
	ring := &Keyring{
		entries: make([]keyringEntry, 0, len(rawEntries)),
		byID:    make(map[string]int, len(rawEntries)),
	}
	for i, raw := range rawEntries {
		entry, err := parseKeyringEntry(strings.Trim(raw, keyringTrimSet), i)
		if err != nil {
			return nil, err
		}
		if _, duplicate := ring.byID[entry.kid]; duplicate {
			return nil, keyringError("entry %d: duplicate kid %q", i, entry.kid)
		}
		ring.byID[entry.kid] = len(ring.entries)
		ring.entries = append(ring.entries, entry)
	}
	return ring, nil
}

func parseKeyringEntry(raw string, index int) (keyringEntry, error) {
	if raw == "" {
		return keyringEntry{}, keyringError("entry %d: empty entry", index)
	}

	kid, encodedKey, found := strings.Cut(raw, ":")
	if !found {
		return keyringEntry{}, keyringError("entry %d: missing ':' separator", index)
	}
	if !validKeyID(kid) {
		return keyringEntry{}, keyringError("entry %d: kid must match ^[A-Za-z0-9._-]{1,32}$", index)
	}
	if strings.ContainsAny(encodedKey, "\r\n") {
		return keyringEntry{}, keyringError("entry %d (kid %q): key contains whitespace", index, kid)
	}

	decoded, err := base64.StdEncoding.Strict().DecodeString(encodedKey)
	if err != nil {
		return keyringEntry{}, keyringError("entry %d (kid %q): key is not strict padded standard base64", index, kid)
	}
	defer wipeBytes(decoded)

	if len(decoded) != keyBytes {
		return keyringEntry{}, keyringError("entry %d (kid %q): key must decode to %d bytes, got %d", index, kid, keyBytes, len(decoded))
	}

	var key keyMaterial
	copy(key[:], decoded)
	return keyringEntry{kid: kid, key: key}, nil
}

func validKeyID(kid string) bool {
	if len(kid) == 0 || len(kid) > keyIDMaxLength {
		return false
	}
	for i := 0; i < len(kid); i++ {
		c := kid[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// ActiveKeyID returns the kid of the key used for encryption, or "" when unset.
func (k *Keyring) ActiveKeyID() string {
	entry, ok := k.active()
	if !ok {
		return ""
	}
	return entry.kid
}

func (k *Keyring) active() (keyringEntry, bool) {
	if k == nil || len(k.entries) == 0 {
		return keyringEntry{}, false
	}
	return k.entries[0], true
}

func (k *Keyring) lookup(kid string) (keyMaterial, bool) {
	if k == nil {
		return keyMaterial{}, false
	}
	index, ok := k.byID[kid]
	if !ok {
		return keyMaterial{}, false
	}
	return k.entries[index].key, true
}

func keyringError(format string, args ...any) error {
	return errors.New(errors.CodeInvalidConfig, fmt.Sprintf(format, args...), ErrKeyringMalformed)
}
