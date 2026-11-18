package handler

import (
	"net/http"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/csrf"
	"github.com/kaiizer777/go-auth/errors"
)

// GetCSRFToken issues or refreshes the CSRF double-submit cookie for SPA clients.
// An already-valid cookie is reused (expiry refreshed) to avoid multi-tab overwrites.
func (h *Handler) GetCSRFToken(w http.ResponseWriter, r *http.Request) {
	// Token responses carry the cookie value; never let caches store them.
	w.Header().Set("Cache-Control", "no-store")
	cfg := &h.cfg
	// A CSRF cookie name colliding with the session cookie would expose
	// the session credential in the token response; refuse to proceed.
	csrfName, sessName := cfg.CSRFCookieName, cfg.SessionCookieName
	if csrfName == "" || sessName == "" {
		dflt := config.DefaultConfig()
		if csrfName == "" {
			csrfName = dflt.CSRFCookieName
		}
		if sessName == "" {
			sessName = dflt.SessionCookieName
		}
	}
	if csrfName == sessName {
		errors.WriteHTTP(w, errors.New(errors.CodeInvalidConfig, "CSRF cookie name must not match session cookie name", nil))
		return
	}
	if c, err := r.Cookie(cfg.CSRFCookieName); err == nil && csrf.ValidToken(c.Value) {
		csrf.SetCookie(w, c.Value, cfg)
		writeJSON(w, http.StatusOK, map[string]string{"csrf_token": c.Value})
		return
	}
	token, err := csrf.IssueCookie(w, cfg)
	if err != nil {
		errors.WriteHTTP(w, errors.New(errors.CodeInternalError, "failed to generate CSRF token", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": token})
}
