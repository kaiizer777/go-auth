package handler

import (
	"bytes"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/csrf"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/oauth"
	"github.com/kaiizer777/go-auth/ratelimit"
	"github.com/kaiizer777/go-auth/session"
	"github.com/kaiizer777/go-auth/totp"
)

// Handler maintains the HTTP router, database connection, and configuration.
type Handler struct {
	mux             *http.ServeMux
	db              *gorm.DB
	store           db.Store
	cfg             config.Config
	authSvc         auth.Service
	sessionSvc      session.Service
	oauthSvc        oauth.Service
	oauthProviders  map[string]oauth.Provider
	oauthRegistry   oauth.Registry
	sessHandler     *SessionHandler
	loginLimiter    *ratelimit.Limiter
	signupLimiter   *ratelimit.Limiter
	resetLimiter    *ratelimit.Limiter
	loginIPLimiter  *ratelimit.Limiter
	signupIPLimiter *ratelimit.Limiter
	resetIPLimiter  *ratelimit.Limiter
	oauthIPLimiter  *ratelimit.Limiter
	totpSvc         totp.Service
	totpLimiter     *ratelimit.Limiter
}

// Option configures optional dependencies for Handler.
type Option func(*Handler)

// WithStore attaches a db.Store to the Handler.
func WithStore(store db.Store) Option {
	return func(h *Handler) {
		h.store = store
	}
}

// WithSessionService attaches a session service to the Handler.
func WithSessionService(svc session.Service) Option {
	return func(h *Handler) {
		h.sessionSvc = svc
	}
}

// WithSessionHandler attaches a pre-configured SessionHandler.
func WithSessionHandler(sh *SessionHandler) Option {
	return func(h *Handler) {
		h.sessHandler = sh
	}
}

// WithOAuthService attaches the OAuth linking service and its providers.
func WithOAuthService(svc oauth.Service, providers map[string]oauth.Provider) Option {
	return func(h *Handler) {
		h.oauthSvc = svc
		h.oauthProviders = providers
	}
}

// WithOAuthRegistry attaches the OAuth linking service and dynamic provider registry.
func WithOAuthRegistry(svc oauth.Service, registry oauth.Registry) Option {
	return func(h *Handler) {
		h.oauthSvc = svc
		h.oauthRegistry = registry
	}
}

// WithRateLimiters attaches custom in-memory rate limiters to the Handler.
func WithRateLimiters(login, reset, signup *ratelimit.Limiter) Option {
	return func(h *Handler) {
		h.loginLimiter = login
		h.resetLimiter = reset
		h.signupLimiter = signup
	}
}

// WithIPRateLimiters attaches custom in-memory IP-tier rate limiters to the Handler.
func WithIPRateLimiters(loginIP, resetIP, signupIP *ratelimit.Limiter) Option {
	return func(h *Handler) {
		h.loginIPLimiter = loginIP
		h.resetIPLimiter = resetIP
		h.signupIPLimiter = signupIP
	}
}

// WithOAuthIPLimiters attaches a custom in-memory IP-tier rate limiter for the
// OAuth initiate/callback routes. No account tier exists: no identity is
// authenticated before the callback completes.
func WithOAuthIPLimiters(oauthIP *ratelimit.Limiter) Option {
	return func(h *Handler) {
		h.oauthIPLimiter = oauthIP
	}
}

// WithTotpService attaches a TOTP two-factor authentication service to the Handler.
func WithTotpService(svc totp.Service) Option {
	return func(h *Handler) {
		h.totpSvc = svc
	}
}

// WithTotpLimiter attaches a custom in-memory rate limiter for TOTP verification.
func WithTotpLimiter(limiter *ratelimit.Limiter) Option {
	return func(h *Handler) {
		h.totpLimiter = limiter
	}
}

// New initializes the handler scaffold, registers routes, and applies CORS middleware.
func New(db *gorm.DB, cfg config.Config, authSvc auth.Service, opts ...Option) http.Handler {
	h := &Handler{
		mux:     http.NewServeMux(),
		db:      db,
		cfg:     cfg,
		authSvc: authSvc,
	}
	for _, opt := range opts {
		opt(h)
	}

	// OAuth limiter default mirrors the login IP tier. Zero Max disables
	// throttling, matching the login/signup/reset behavior. Mounted routes
	// stay outside csrf.Middleware: throttling applies as its own wrapper.
	if h.oauthIPLimiter == nil && h.cfg.RateLimitOAuthIPMax > 0 {
		h.oauthIPLimiter = ratelimit.NewLimiter(h.cfg.RateLimitOAuthWindow, h.cfg.RateLimitOAuthIPMax)
	}

	if h.sessionSvc == nil {
		if h.store != nil {
			h.sessionSvc = session.NewServiceWithStore(h.store, &cfg)
		} else if db != nil {
			h.sessionSvc = session.NewService(db, &cfg)
		}
	}

	if h.sessHandler == nil && h.sessionSvc != nil {
		if h.store != nil {
			h.sessHandler = NewSessionHandlerWithStore(h.sessionSvc, h.store, &cfg)
		} else if db != nil {
			h.sessHandler = NewSessionHandler(h.sessionSvc, db, &cfg)
		}
	}

	if h.totpLimiter == nil && h.cfg.TOTP.MaxAttemptsPerWindow > 0 {
		window := h.cfg.TOTP.AttemptWindow
		if window <= 0 {
			window = 5 * time.Minute
		}
		h.totpLimiter = ratelimit.NewLimiter(window, h.cfg.TOTP.MaxAttemptsPerWindow)
	}

	if h.totpSvc == nil && cfg.TOTP.EncryptionKey != "" {
		if h.store != nil {
			h.totpSvc = totp.NewServiceWithStore(h.store, cfg.TOTP, h.totpLimiter, slog.Default())
		} else if db != nil {
			h.totpSvc = totp.NewService(db, cfg.TOTP, h.totpLimiter, slog.Default())
		}
	}

	h.registerRoutes()
	return SecurityHeaders(&cfg)(CORS(cfg)(h))
}

// ServeHTTP handles requests, dispatching to the router and translating 404/405 to standardized JSON responses.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ri := &responseInterceptor{ResponseWriter: w}
	h.mux.ServeHTTP(ri, r)

	if !ri.headerWritten {
		if ri.statusCode == http.StatusNotFound {
			h.NotFound(w, r)
			return
		}
		if ri.statusCode == http.StatusMethodNotAllowed {
			h.MethodNotAllowed(w, r)
			return
		}
		if ri.statusCode != 0 {
			w.WriteHeader(ri.statusCode)
		}
		if ri.body.Len() > 0 {
			_, _ = w.Write(ri.body.Bytes())
		}
	}
}

// NotFound writes a standardized 404 NOT_FOUND JSON error response.
func (h *Handler) NotFound(w http.ResponseWriter, r *http.Request) {
	errors.WriteJSON(w, errors.New(errors.CodeNotFound, "not found", nil))
}

// MethodNotAllowed writes a standardized 405 METHOD_NOT_ALLOWED JSON error response.
func (h *Handler) MethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	errors.WriteJSON(w, errors.New(errors.CodeMethodNotAllowed, "method not allowed", nil))
}

// NotFoundHandler returns an http.Handler that writes a 404 NOT_FOUND JSON response.
func NotFoundHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		errors.WriteJSON(w, errors.New(errors.CodeNotFound, "not found", nil))
	})
}

// MethodNotAllowedHandler returns an http.Handler that writes a 405 METHOD_NOT_ALLOWED JSON response.
func MethodNotAllowedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		errors.WriteJSON(w, errors.New(errors.CodeMethodNotAllowed, "method not allowed", nil))
	})
}

// registerRoutes configures default and endpoint routes on the internal multiplexer.
func (h *Handler) registerRoutes() {
	// Base routes mounted in Phase 1; additional auth routes mount in subsequent phases.
	h.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if h.store != nil {
			if err := h.store.Ping(r.Context()); err != nil {
				errors.WriteJSON(w, errors.New(errors.CodeDatabaseUnavailable, "database unavailable", nil))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if h.db == nil {
			errors.WriteJSON(w, errors.New(errors.CodeDatabaseUnavailable, "database unavailable", nil))
			return
		}
		sqlDB, err := h.db.DB()
		if err != nil || sqlDB.PingContext(r.Context()) != nil {
			errors.WriteJSON(w, errors.New(errors.CodeDatabaseUnavailable, "database unavailable", nil))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	if h.authSvc != nil {
		authH := NewAuthHandler(h.authSvc,
			WithAuthSessionService(h.sessionSvc),
			WithAuthTotpService(h.totpSvc),
			WithAuthConfig(&h.cfg),
			WithAuthLimiters(h.loginLimiter, h.signupLimiter, h.resetLimiter),
			WithAuthIPLimiters(h.loginIPLimiter, h.signupIPLimiter, h.resetIPLimiter),
		)
		// Pre-auth handlers never consume the Authorization header, so the
		// bearer exemption must not apply here (login CSRF bypass).
		csrfMw := csrf.PreAuthMiddleware(&h.cfg)
		wrap := func(hf http.HandlerFunc) http.Handler { return csrfMw(hf) }

		// Canonical routes:
		h.mux.Handle("POST /auth/signup", wrap(authH.Signup))
		h.mux.Handle("POST /auth/login", wrap(authH.Login))
		if h.sessHandler == nil || h.sessionSvc == nil {
			h.mux.Handle("POST /auth/logout", wrap(authH.Logout))
		}
		h.mux.Handle("POST /auth/verify", wrap(authH.VerifyEmail))
		h.mux.Handle("POST /auth/password/reset-request", wrap(authH.RequestPasswordReset))
		h.mux.Handle("POST /auth/password/reset", wrap(authH.ResetPassword))

		// Aliases:
		h.mux.Handle("POST /api/auth/signup", wrap(authH.Signup))
		h.mux.Handle("POST /api/auth/login", wrap(authH.Login))
		if h.sessHandler == nil || h.sessionSvc == nil {
			h.mux.Handle("POST /api/auth/logout", wrap(authH.Logout))
		}
		h.mux.Handle("POST /api/auth/verify-email", wrap(authH.VerifyEmail))
		h.mux.Handle("POST /api/auth/request-password-reset", wrap(authH.RequestPasswordReset))
		h.mux.Handle("POST /api/auth/reset-password", wrap(authH.ResetPassword))

		// Pre-auth token acquisition for SPA clients:
		h.mux.HandleFunc("GET /auth/csrf", h.GetCSRFToken)
		h.mux.HandleFunc("GET /api/auth/csrf", h.GetCSRFToken)
	}

	if h.sessHandler != nil && h.sessionSvc != nil {
		authMw := RequireAuth(h.sessionSvc, &h.cfg)
		csrfMw := csrf.Middleware(&h.cfg)
		sessionWrap := func(hf http.HandlerFunc) http.Handler {
			return csrfMw(authMw(hf))
		}

		// Canonical session routes:
		h.mux.Handle("GET /auth/session", sessionWrap(h.sessHandler.GetCurrentSession))
		h.mux.Handle("DELETE /auth/session", sessionWrap(h.sessHandler.Logout))
		if h.authSvc != nil {
			h.mux.Handle("POST /auth/logout", sessionWrap(h.sessHandler.Logout))
		}
		h.mux.Handle("GET /auth/sessions", sessionWrap(h.sessHandler.ListSessions))
		h.mux.Handle("DELETE /auth/sessions", sessionWrap(h.sessHandler.InvalidateAllSessions))
		h.mux.Handle("POST /auth/session/rotate", sessionWrap(h.sessHandler.RotateSession))

		// Aliases:
		h.mux.Handle("GET /api/auth/session", sessionWrap(h.sessHandler.GetCurrentSession))
		h.mux.Handle("DELETE /api/auth/session", sessionWrap(h.sessHandler.Logout))
		if h.authSvc != nil {
			h.mux.Handle("POST /api/auth/logout", sessionWrap(h.sessHandler.Logout))
		}
		h.mux.Handle("GET /api/auth/sessions", sessionWrap(h.sessHandler.ListSessions))
		h.mux.Handle("DELETE /api/auth/sessions", sessionWrap(h.sessHandler.InvalidateAllSessions))
		h.mux.Handle("POST /api/auth/session/rotate", sessionWrap(h.sessHandler.RotateSession))

		h.mux.Handle("GET /sessions/me", sessionWrap(h.sessHandler.GetCurrentSession))
		h.mux.Handle("DELETE /sessions/me", sessionWrap(h.sessHandler.Logout))
		h.mux.Handle("GET /sessions", sessionWrap(h.sessHandler.ListSessions))
		h.mux.Handle("DELETE /sessions", sessionWrap(h.sessHandler.InvalidateAllSessions))
		h.mux.Handle("POST /sessions/rotate", sessionWrap(h.sessHandler.RotateSession))
	}

	if h.oauthSvc != nil {
		// Mounted RAW outside csrf.Middleware/PreAuthMiddleware: Apple
		// form_post callbacks carry no CSRF cookie+header, and RFC 6749
		// state validation in HandleCallback is the CSRF defense.
		h.mux.HandleFunc("GET /auth/oauth/{provider}", h.OAuthInitiate)
		h.mux.HandleFunc("GET /auth/oauth/{provider}/callback", h.OAuthCallback)
		h.mux.HandleFunc("POST /auth/oauth/{provider}/callback", h.OAuthCallback)
		h.mux.HandleFunc("GET /api/auth/oauth/{provider}", h.OAuthInitiate)
		h.mux.HandleFunc("GET /api/auth/oauth/{provider}/callback", h.OAuthCallback)
		h.mux.HandleFunc("POST /api/auth/oauth/{provider}/callback", h.OAuthCallback)
	}

	if h.totpSvc != nil {
		authMw := RequireAuth(h.sessionSvc, &h.cfg)
		csrfMw := csrf.Middleware(&h.cfg)
		preAuthCsrfMw := csrf.PreAuthMiddleware(&h.cfg)

		authedWrap := func(hf http.HandlerFunc) http.Handler {
			return csrfMw(authMw(hf))
		}
		preAuthWrap := func(hf http.HandlerFunc) http.Handler {
			return preAuthCsrfMw(hf)
		}

		// Authenticated endpoints
		h.mux.Handle("POST /auth/totp/enroll", authedWrap(h.HandleTotpEnroll))
		h.mux.Handle("POST /auth/totp/confirm", authedWrap(h.HandleTotpConfirm))
		h.mux.Handle("POST /auth/totp/disable", authedWrap(h.HandleTotpDisable))
		h.mux.Handle("DELETE /auth/totp", authedWrap(h.HandleTotpDisable))
		h.mux.Handle("GET /auth/totp/status", authedWrap(h.HandleTotpStatus))

		// Pre-auth challenge endpoints
		h.mux.Handle("POST /auth/totp/verify", preAuthWrap(h.HandleTotpVerify))
		h.mux.Handle("POST /auth/totp/backup", preAuthWrap(h.HandleTotpBackup))
		h.mux.Handle("POST /auth/totp/backup-code", preAuthWrap(h.HandleTotpBackup))

		// Aliases
		h.mux.Handle("POST /api/auth/totp/enroll", authedWrap(h.HandleTotpEnroll))
		h.mux.Handle("POST /api/auth/totp/confirm", authedWrap(h.HandleTotpConfirm))
		h.mux.Handle("POST /api/auth/totp/disable", authedWrap(h.HandleTotpDisable))
		h.mux.Handle("DELETE /api/auth/totp", authedWrap(h.HandleTotpDisable))
		h.mux.Handle("GET /api/auth/totp/status", authedWrap(h.HandleTotpStatus))

		h.mux.Handle("POST /api/auth/totp/verify", preAuthWrap(h.HandleTotpVerify))
		h.mux.Handle("POST /api/auth/totp/backup", preAuthWrap(h.HandleTotpBackup))
		h.mux.Handle("POST /api/auth/totp/backup-code", preAuthWrap(h.HandleTotpBackup))
	}
}

type responseInterceptor struct {
	http.ResponseWriter
	statusCode    int
	headerWritten bool
	body          bytes.Buffer
}

func (rw *responseInterceptor) WriteHeader(code int) {
	if rw.headerWritten || rw.statusCode != 0 {
		return
	}
	rw.statusCode = code
	if code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
		rw.headerWritten = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func isJSONContentType(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json")
	}
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func (rw *responseInterceptor) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		if rw.statusCode == 0 {
			rw.statusCode = http.StatusOK
		}
		if isJSONContentType(rw.Header().Get("Content-Type")) {
			rw.headerWritten = true
			rw.ResponseWriter.WriteHeader(rw.statusCode)
			return rw.ResponseWriter.Write(b)
		}
		if rw.statusCode != http.StatusNotFound && rw.statusCode != http.StatusMethodNotAllowed {
			rw.headerWritten = true
			rw.ResponseWriter.WriteHeader(rw.statusCode)
			return rw.ResponseWriter.Write(b)
		}
	}
	if (rw.statusCode == http.StatusNotFound || rw.statusCode == http.StatusMethodNotAllowed) && !isJSONContentType(rw.Header().Get("Content-Type")) {
		return rw.body.Write(b)
	}
	return rw.ResponseWriter.Write(b)
}

func (rw *responseInterceptor) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func (rw *responseInterceptor) Flush() {
	flusher, ok := rw.ResponseWriter.(http.Flusher)
	if !ok {
		return
	}
	if !rw.headerWritten {
		if rw.statusCode == 0 {
			rw.statusCode = http.StatusOK
		}
		if (rw.statusCode == http.StatusNotFound || rw.statusCode == http.StatusMethodNotAllowed) && !isJSONContentType(rw.Header().Get("Content-Type")) {
			return
		}
		rw.headerWritten = true
		rw.ResponseWriter.WriteHeader(rw.statusCode)
	}
	flusher.Flush()
}
