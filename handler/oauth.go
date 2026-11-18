package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kaiizer777/go-auth/csrf"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/oauth"
)

// OAuthInitiate starts the provider dance: state cookie set, 302 to provider.
func (h *Handler) OAuthInitiate(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("provider")
	if _, ok := oauth.SupportedProviders[providerID]; !ok {
		errors.WriteHTTP(w, errors.ErrOAuthProviderNotFound)
		return
	}
	if h.oauthSvc == nil {
		// Wiring bug, not a bad provider slug: 500 so operators don't chase providers.
		errors.WriteHTTP(w, errors.New(errors.CodeInternalError, "oauth service unavailable", nil))
		return
	}
	authURL, err := h.oauthSvc.InitiateFlow(w, r, providerID)
	if err != nil {
		errors.WriteHTTP(w, err)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// OAuthCallback finishes the dance: state check, link/create, session.
// GET reads code/state from the query; POST (Apple form_post) from the form body.
// Success is 302 for browser flows, 200 JSON for bearer/JSON-accepting clients.
func (h *Handler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("provider")
	if _, ok := oauth.SupportedProviders[providerID]; !ok {
		errors.WriteHTTP(w, errors.ErrOAuthProviderNotFound)
		return
	}
	if h.oauthSvc == nil {
		// Wiring bug, not a bad provider slug: 500 so operators don't chase providers.
		errors.WriteHTTP(w, errors.New(errors.CodeInternalError, "oauth service unavailable", nil))
		return
	}
	if r.Method == http.MethodPost {
		// Bound the form read so a hostile IdP-shaped POST cannot OOM the callback.
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			oauth.ClearStateCookie(w, &h.cfg)
			errors.WriteHTTP(w, errors.New(errors.CodeValidationError, "invalid callback form", nil))
			return
		}
	}
	if r.URL.Query().Get("error") != "" {
		slog.InfoContext(r.Context(), "oauth_callback_failure",
			"provider", providerID,
			"reason", "provider_error",
			"ip", realIP(r),
			"user_agent", r.UserAgent(),
		)
		// Single-use state must not survive a failed flow.
		oauth.ClearStateCookie(w, &h.cfg)
		errors.WriteHTTP(w, errors.New(errors.CodeOAuthProviderError, "oauth provider returned an error", nil))
		return
	}
	code := r.FormValue("code")
	state := r.FormValue("state")

	sess, redirect, err := h.oauthSvc.HandleCallback(r.Context(), w, r, providerID, code, state)
	if err != nil {
		errors.WriteHTTP(w, err)
		return
	}
	// Branch rule: bearer/JSON clients get 200 JSON, browser web flows get
	// 302. Both branches pass through safeOAuthRedirect: the initiate step
	// accepts an arbitrary ?redirect_url= into the signed state, so an
	// unsanitized JSON echo would be an open redirector (CWE-601).
	if wantsOAuthJSON(r) {
		if _, cerr := csrf.IssueCookie(w, &h.cfg); cerr != nil {
			slog.ErrorContext(r.Context(), "failed to issue csrf cookie on oauth callback", "error", cerr)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":      sess.UserID,
			"expires_at":   sess.AbsoluteExpiresAt,
			"redirect_url": safeOAuthRedirect(redirect),
		})
		return
	}
	http.Redirect(w, r, safeOAuthRedirect(redirect), http.StatusFound)
}

// wantsOAuthJSON selects the 200-JSON branch: explicit bearer flow or a
// JSON-accepting client. Default browser web flow gets the 302 redirect.
func wantsOAuthJSON(r *http.Request) bool {
	if r.Header.Get("X-Auth-Type") == "bearer" {
		return true
	}
	if r.URL.Query().Get("type") == "bearer" {
		return true
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "application/json")
}

// safeOAuthRedirect allows only same-origin redirect targets to avoid turning
// the post-login redirect into an open redirector. Absolute URLs, protocol-
// relative URLs, and backslash tricks fall back to "/".
func safeOAuthRedirect(target string) string {
	if target == "" || target[0] != '/' {
		return "/"
	}
	if len(target) > 1 && (target[1] == '/' || target[1] == '\\') {
		return "/"
	}
	if strings.ContainsAny(target, "\\ \t\r\n") {
		return "/"
	}
	return target
}
