package csrf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/kaiizer777/go-auth/config"
	apperrors "github.com/kaiizer777/go-auth/errors"
)

var safeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
}

// generateCSRFToken creates a 32-byte (256-bit) CSPRNG token, hex-encoded to 64 chars.
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Middleware enforces Double Submit Cookie CSRF protection.
func Middleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Bearer token requests are inherently immune to CSRF — skip entirely.
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" && strings.HasPrefix(strings.ToLower(strings.TrimSpace(authHeader)), "bearer ") {
				next.ServeHTTP(w, r)
				return
			}

			csrfCookie, err := r.Cookie(cfg.CSRFCookieName)

			// Safe methods ensure cookie exists, then pass through.
			if safeMethods[r.Method] {
				if err != nil || csrfCookie.Value == "" {
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

			headerToken := r.Header.Get(cfg.CSRFHeaderName)
			if headerToken == "" {
				apperrors.WriteHTTP(w, apperrors.ErrCSRFTokenMissing)
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

// setCSRFCookie writes the CSRF token cookie.
// HttpOnly: false is intentional and mandatory so client JavaScript can read it to set X-CSRF-Token.
// SameSite: Strict ensures maximum isolation.
func setCSRFCookie(w http.ResponseWriter, token string, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,                   // Mandatory false for Double Submit Cookie pattern
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
