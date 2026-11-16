package session

import (
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/kaiizer777/go-auth/config"
	apperrors "github.com/kaiizer777/go-auth/errors"
)

// SetSessionCookie writes the session cookie to the response.
// HttpOnly is HARDCODED to true — callers cannot opt out.
// This is intentional: a session cookie must never be readable by JavaScript.
func SetSessionCookie(w http.ResponseWriter, rawID string, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.SessionCookieName,
		Value:    rawID,
		Path:     cfg.SessionCookiePath,
		Domain:   cfg.SessionCookieDomain,
		MaxAge:   int(cfg.SessionAbsoluteMaxAge / time.Second),
		HttpOnly: true,                      // HARDCODED — prevents JS access; not configurable
		Secure:   cfg.SessionCookieSecure,   // true in prod; configurable for local dev
		SameSite: cfg.SessionCookieSameSite, // Lax minimum
	})
}

// SetSessionCookieWithExpiry writes the session cookie with MaxAge dynamically matching expiresAt.
// HttpOnly is HARDCODED to true — callers cannot opt out.
func SetSessionCookieWithExpiry(w http.ResponseWriter, rawID string, expiresAt time.Time, cfg *config.Config) {
	remaining := int(time.Until(expiresAt).Seconds())
	if remaining < 0 {
		remaining = 0
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.SessionCookieName,
		Value:    rawID,
		Path:     cfg.SessionCookiePath,
		Domain:   cfg.SessionCookieDomain,
		MaxAge:   remaining,
		Expires:  expiresAt,
		HttpOnly: true,                      // HARDCODED — prevents JS access; not configurable
		Secure:   cfg.SessionCookieSecure,   // true in prod; configurable for local dev
		SameSite: cfg.SessionCookieSameSite, // Lax minimum
	})
}

// ClearSessionCookie sets the session cookie to empty with MaxAge=-1,
// which instructs the browser to delete it immediately.
// MaxAge=-1 means "delete now". MaxAge=0 means "session cookie" in some browsers — never use 0 for deletion.
func ClearSessionCookie(w http.ResponseWriter, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.SessionCookieName,
		Value:    "",
		Path:     cfg.SessionCookiePath,
		Domain:   cfg.SessionCookieDomain,
		MaxAge:   -1, // -1 = delete immediately; 0 = session cookie (wrong for logout)
		Expires:  time.Unix(1, 0),
		HttpOnly: true,
		Secure:   cfg.SessionCookieSecure,
		SameSite: cfg.SessionCookieSameSite,
	})
}

// ReadSessionCookie extracts the raw session ID from the cookie.
// Returns apperrors.ErrSessionNotFound (wrapping http.ErrNoCookie) if the cookie is absent or empty.
// Returns apperrors.ErrSessionInvalid if the cookie value is malformed (not 32 hex characters).
func ReadSessionCookie(r *http.Request, cfg *config.Config) (string, error) {
	c, err := r.Cookie(cfg.SessionCookieName)
	if err != nil {
		return "", apperrors.New(apperrors.CodeSessionNotFound, "Session is invalid or has expired", http.ErrNoCookie)
	}
	val := strings.TrimSpace(c.Value)
	if val == "" {
		return "", apperrors.New(apperrors.CodeSessionNotFound, "Session is invalid or has expired", http.ErrNoCookie)
	}
	if len(val) != 32 {
		return "", apperrors.ErrSessionInvalid
	}
	if _, err := hex.DecodeString(val); err != nil {
		return "", apperrors.ErrSessionInvalid
	}
	return strings.ToLower(val), nil
}
