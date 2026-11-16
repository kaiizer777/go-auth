package crypto

import (
	_ "embed"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/kaiizer777/go-auth/errors"
)

//go:embed passwords.txt
var embeddedPasswords string

var (
	blocklistMu     sync.RWMutex
	commonPasswords map[string]struct{}
)

// Predefined sentinel errors for password validation.
var (
	ErrPasswordTooShort  = errors.New(errors.CodePasswordTooShort, "password is too short", nil)
	ErrPasswordTooLong   = errors.New(errors.CodePasswordTooLong, "password is too long", nil)
	ErrPasswordTooCommon = errors.New(errors.CodePasswordTooCommon, "password is too common", nil)
)

// parseBlocklist parses newline-separated passwords, handling CRLF (\r\n), LF (\n), and CR (\r).
func parseBlocklist(data string) map[string]struct{} {
	lines := strings.FieldsFunc(data, func(r rune) bool {
		return r == '\r' || r == '\n'
	})
	blocklist := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		normalized := strings.ToLower(strings.TrimSpace(line))
		if normalized != "" {
			blocklist[normalized] = struct{}{}
		}
	}
	return blocklist
}

func init() {
	commonPasswords = parseBlocklist(embeddedPasswords)
}

// AddBlockedPasswords dynamically extends the in-memory common passwords blocklist.
// It is thread-safe and normalizes each word to lowercase and trimmed whitespace.
func AddBlockedPasswords(passwords ...string) {
	blocklistMu.Lock()
	defer blocklistMu.Unlock()
	for _, p := range passwords {
		normalized := strings.ToLower(strings.TrimSpace(p))
		if normalized != "" {
			commonPasswords[normalized] = struct{}{}
		}
	}
}

// IsCommonPassword checks whether a password exists in the common password blocklist.
func IsCommonPassword(password string) bool {
	normalized := strings.ToLower(strings.TrimSpace(password))
	blocklistMu.RLock()
	defer blocklistMu.RUnlock()
	_, exists := commonPasswords[normalized]
	return exists
}

// ValidatePassword validates password length against Unicode code points and verifies
// that the password is not present in the common password blocklist or any provided extraBlocked list.
func ValidatePassword(password string, minLen, maxLen uint, extraBlocked ...string) error {
	runeCount := uint(utf8.RuneCountInString(password)) // #nosec G115 -- rune count is non-negative

	if runeCount < minLen {
		return ErrPasswordTooShort
	}
	if runeCount > maxLen {
		return ErrPasswordTooLong
	}
	if IsCommonPassword(password) {
		return ErrPasswordTooCommon
	}

	normalized := strings.ToLower(strings.TrimSpace(password))
	for _, extra := range extraBlocked {
		if strings.ToLower(strings.TrimSpace(extra)) == normalized {
			return ErrPasswordTooCommon
		}
	}

	return nil
}
