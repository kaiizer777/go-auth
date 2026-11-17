package handler

import (
	"net/http"

	"github.com/kaiizer777/go-auth/csrf"
	"github.com/kaiizer777/go-auth/errors"
)

// GetCSRFToken issues or refreshes the CSRF double-submit cookie for SPA clients.
// An already-valid cookie is reused (expiry refreshed) to avoid multi-tab overwrites.
func (h *Handler) GetCSRFToken(w http.ResponseWriter, r *http.Request) {
	cfg := &h.cfg
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
