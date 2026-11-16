package csrf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"runtime"
	"strings"

	"github.com/kaiizer777/go-auth/config"
	apperrors "github.com/kaiizer777/go-auth/errors"
)

// randReader is the CSPRNG entropy source for CSRF token generation, package-scoped for unit test injection.
var randReader io.Reader = rand.Reader

var safeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
}

// ensureConfig returns cfg if non-nil or a pointer to default config if nil.
func ensureConfig(cfg *config.Config) *config.Config {
	if cfg == nil {
		defaultCfg := config.DefaultConfig()
		return &defaultCfg
	}
	return cfg
}

// generateCSRFToken creates a 32-byte (256-bit) CSPRNG token, hex-encoded to 64 chars.
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return "", err
	}
	defer func() {
		clear(b)
		runtime.KeepAlive(b)
	}()
	return hex.EncodeToString(b), nil
}

// isValidHexToken verifies that s is exactly 64 hexadecimal characters.
func isValidHexToken(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// Middleware enforces Double Submit Cookie CSRF protection.
func Middleware(cfg *config.Config) func(http.Handler) http.Handler {
	cfg = ensureConfig(cfg)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Bearer token requests are inherently immune to CSRF — skip only if a non-empty token is present.
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				trimmed := strings.TrimSpace(authHeader)
				if len(trimmed) > 7 && strings.EqualFold(trimmed[:7], "bearer ") {
					token := strings.TrimSpace(trimmed[7:])
					if token != "" {
						next.ServeHTTP(w, r)
						return
					}
				}
			}

			csrfCookie, err := r.Cookie(cfg.CSRFCookieName)

			// Safe methods ensure a valid 64-char hex cookie exists, generating one if absent or invalid.
			if safeMethods[r.Method] {
				if err != nil || !isValidHexToken(csrfCookie.Value) {
					token, genErr := generateCSRFToken()
					if genErr != nil {
						apperrors.WriteHTTP(w, apperrors.New(apperrors.CodeInternalError, "failed to generate CSRF token", genErr))
						return
					}
					setCSRFCookie(w, token, cfg)
				}
				next.ServeHTTP(w, r)
				return
			}

			// State-changing methods (POST, PUT, PATCH, DELETE) enforce cookie and header.
			if err != nil || csrfCookie.Value == "" {
				apperrors.WriteHTTP(w, apperrors.ErrCSRFTokenMissing)
				return
			}

			if !isValidHexToken(csrfCookie.Value) {
				apperrors.WriteHTTP(w, apperrors.ErrCSRFTokenInvalid)
				return
			}

			headerToken := r.Header.Get(cfg.CSRFHeaderName)
			if headerToken == "" {
				apperrors.WriteHTTP(w, apperrors.ErrCSRFTokenMissing)
				return
			}

			if !isValidHexToken(headerToken) {
				apperrors.WriteHTTP(w, apperrors.ErrCSRFTokenInvalid)
				return
			}

			if !secureCompare(csrfCookie.Value, headerToken) {
				apperrors.WriteHTTP(w, apperrors.ErrCSRFTokenInvalid)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GenerateToken creates a 32-byte (256-bit) CSPRNG token, hex-encoded to 64 chars.
func GenerateToken() (string, error) {
	return generateCSRFToken()
}

// SetCookie writes the CSRF token cookie to the response writer.
func SetCookie(w http.ResponseWriter, token string, cfg *config.Config) {
	setCSRFCookie(w, token, ensureConfig(cfg))
}

// IssueCookie generates a new CSRF token and sets the CSRF cookie on w.
func IssueCookie(w http.ResponseWriter, cfg *config.Config) (string, error) {
	token, err := generateCSRFToken()
	if err != nil {
		return "", err
	}
	setCSRFCookie(w, token, ensureConfig(cfg))
	return token, nil
}

// setCSRFCookie writes the CSRF token cookie.
// HttpOnly: false is intentional and mandatory so client JavaScript can read it to set X-CSRF-Token.
// SameSite: Strict ensures maximum isolation.
func setCSRFCookie(w http.ResponseWriter, token string, cfg *config.Config) {
	cfg = ensureConfig(cfg)
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // Mandatory false for Double Submit Cookie pattern
		Secure:   cfg.SessionCookieSecure,
		SameSite: http.SameSiteStrictMode, // Strict for CSRF cookie
	})
}

// secureCompare executes constant-time string comparison to prevent timing leaks.
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
