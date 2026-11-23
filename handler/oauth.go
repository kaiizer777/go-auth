package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/kaiizer777/go-auth/csrf"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/oauth"
	"github.com/kaiizer777/go-auth/ratelimit"
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
	if !h.allowOAuth(w, r, providerID) {
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
// Success is 302 for browser flows, 200 JSON for JSON-accepting clients.
// Explicit bearer selectors additionally mint a bearer-typed session and
// receive its raw token; a bare Accept: application/json stays cookie-typed.
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
	if !h.allowOAuth(w, r, providerID) {
		return
	}
	if r.Method == http.MethodPost {
		// Bound the form read so a hostile IdP-shaped POST cannot OOM the callback.
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			oauth.ClearStateCookie(w, &h.cfg, providerID)
			// Cause kept for operators: errors.WriteJSON rewrites 400-class
			// bodies from the code, so the wrapped error never reaches the wire.
			errors.WriteHTTP(w, errors.New(errors.CodeValidationError, "invalid callback form", err))
			return
		}
	}
	// FormValue covers query and POST bodies: form_post providers deliver
	// error/code/state in the body, GET providers in the query.
	if r.FormValue("error") != "" {
		slog.InfoContext(r.Context(), "oauth_callback_failure",
			"provider", providerID,
			"reason", "provider_error",
			"ip", realIP(r),
			"user_agent", r.UserAgent(),
		)
		// Single-use state must not survive a failed flow.
		oauth.ClearStateCookie(w, &h.cfg, providerID)
		errors.WriteHTTP(w, errors.New(errors.CodeOAuthProviderError, "oauth provider returned an error", nil))
		return
	}
	code := r.FormValue("code")
	state := r.FormValue("state")

	// Only explicit bearer selectors mint bearer sessions; the password
	// Login handler uses the same X-Auth-Type/type=bearer contract. One
	// evaluation covers both the session type and the body shape.
	bearer, wantJSON := oauthTransport(r)
	sessType := db.SessionTypeCookie
	if bearer {
		sessType = db.SessionTypeBearer
	}
	sess, rawToken, redirect, err := h.oauthSvc.HandleCallback(r.Context(), w, r, providerID, code, state, sessType)
	if err != nil {
		if retryAfter, ok := oauth.RetryAfterFromError(err); ok {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		}
		errors.WriteHTTP(w, err)
		return
	}
	if bearer {
		// Mirror the password Login bearer contract: raw token in the body,
		// no session cookie, no CSRF cookie (bearer is CSRF-immune).
		// Bearer responses carry a raw token; never let caches store them.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":    sess.UserID,
			"token":      rawToken,
			"expires_at": sess.AbsoluteExpiresAt,
		})
		return
	}
	// Branch rule: JSON-accepting cookie clients get 200 JSON, browser web
	// flows get 302. Both branches pass through safeOAuthRedirect: the
	// initiate step accepts an arbitrary ?redirect_url= into the signed state,
	// so an unsanitized JSON echo would be an open redirector (CWE-601).
	// CSRF rides alongside the fresh session cookie on both branches, and the
	// JSON body also carries the token: a cookie jar cannot read Set-Cookie,
	// so password Login issues eagerly for the same reason.
	csrfToken, cerr := csrf.IssueCookie(w, &h.cfg)
	if cerr != nil {
		slog.ErrorContext(r.Context(), "failed to issue csrf cookie on oauth callback", "error", cerr)
	}
	if wantJSON {
		// The JSON body carries the CSRF token and the per-user redirect:
		// never let a cache or proxy store a success response.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":      sess.UserID,
			"csrf_token":   csrfToken,
			"expires_at":   sess.AbsoluteExpiresAt,
			"redirect_url": safeOAuthRedirect(redirect),
		})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	http.Redirect(w, r, safeOAuthRedirect(redirect), http.StatusFound)
}

// allowOAuth enforces the per-IP OAuth limiter on initiate and callback.
// No account-tier key exists: no identity is authenticated before the
// callback completes, and keying on the unauthenticated email would let one
// client burn another address's quota. The provider qualifier keeps one
// provider's flood from blocking the others.
func (h *Handler) allowOAuth(w http.ResponseWriter, r *http.Request, providerID string) bool {
	if h.oauthIPLimiter == nil {
		return true
	}
	ip := realIP(r)
	key := ratelimit.Key(ip, "oauth:"+providerID)
	if !h.oauthIPLimiter.Allow(key) {
		slog.WarnContext(r.Context(), "rate_limit_exceeded",
			"ip", ip,
			"endpoint", r.URL.Path,
			"provider", providerID,
		)
		ratelimit.WriteRateLimitError(w, h.oauthIPLimiter.RetryAfter(key))
		return false
	}
	return true
}

// oauthTransport evaluates the transport selectors once. Explicit bearer wins on
// the X-Auth-Type header or the type query parameter; Accept: application/json
// alone only selects the JSON body shape, so a pure-JSON cookie client never
// silently becomes bearer. The selector is read from the URL even on POST: a
// form_post body field named "type" is provider-controlled data.
func oauthTransport(r *http.Request) (bearer, wantJSON bool) {
	if r.Header.Get("X-Auth-Type") == "bearer" || r.URL.Query().Get("type") == "bearer" {
		return true, true
	}
	return false, strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
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
