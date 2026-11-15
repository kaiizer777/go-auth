package session

import (
	"net/http"
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
		HttpOnly: true,
		Secure:   cfg.SessionCookieSecure,
		SameSite: cfg.SessionCookieSameSite,
	})
}

// ReadSessionCookie extracts the raw session ID from the cookie.
// Returns apperrors.ErrSessionNotFound (wrapping http.ErrNoCookie) if the cookie is absent or empty.
func ReadSessionCookie(r *http.Request, cfg *config.Config) (string, error) {
	c, err := r.Cookie(cfg.SessionCookieName)
	if err != nil {
		return "", apperrors.New(apperrors.CodeSessionNotFound, "Session is invalid or has expired", http.ErrNoCookie)
	}
	if c.Value == "" {
		return "", apperrors.New(apperrors.CodeSessionNotFound, "Session is invalid or has expired", http.ErrNoCookie)
	}
	return c.Value, nil
}
