package crypto

import (
	_ "embed"
	"strings"
	"unicode/utf8"

	"github.com/kaiizer777/go-auth/errors"
)

//go:embed passwords.txt
var embeddedPasswords string

var commonPasswords map[string]struct{}

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

// IsCommonPassword checks whether a password exists in the static common password blocklist.
func IsCommonPassword(password string) bool {
	normalized := strings.ToLower(strings.TrimSpace(password))
	_, exists := commonPasswords[normalized]
	return exists
}

// ValidatePassword validates password length against Unicode code points and verifies
// that the password is not present in the common password blocklist.
func ValidatePassword(password string, minLen, maxLen uint) error {
	runeCount := uint(utf8.RuneCountInString(password))

	if runeCount < minLen {
		return errors.New(errors.CodePasswordTooShort, "password is too short", nil)
	}
	if runeCount > maxLen {
		return errors.New(errors.CodePasswordTooLong, "password is too long", nil)
	}
	if IsCommonPassword(password) {
		return errors.New(errors.CodePasswordTooCommon, "password is too common", nil)
	}

	return nil
}
