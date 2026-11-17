package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/csrf"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/ratelimit"
	"github.com/kaiizer777/go-auth/session"
)

// AuthHandler handles HTTP requests for user authentication and lifecycle operations.
type AuthHandler struct {
	svc             auth.Service
	sessionSvc      session.Service
	cfg             *config.Config
	loginLimiter    *ratelimit.Limiter
	loginIPLimiter  *ratelimit.Limiter
	signupLimiter   *ratelimit.Limiter
	signupIPLimiter *ratelimit.Limiter
	resetLimiter    *ratelimit.Limiter
	resetIPLimiter  *ratelimit.Limiter
}

// AuthOption configures optional dependencies for AuthHandler.
type AuthOption func(*AuthHandler)

// WithAuthSessionService configures the session service for AuthHandler.
func WithAuthSessionService(sessionSvc session.Service) AuthOption {
	return func(h *AuthHandler) {
		h.sessionSvc = sessionSvc
	}
}

// WithAuthConfig configures the runtime configuration for AuthHandler.
func WithAuthConfig(cfg *config.Config) AuthOption {
	return func(h *AuthHandler) {
		h.cfg = cfg
	}
}

// WithAuthLimiters configures in-memory account-tier rate limiters for AuthHandler.
func WithAuthLimiters(login, signup, reset *ratelimit.Limiter) AuthOption {
	return func(h *AuthHandler) {
		h.loginLimiter = login
		h.signupLimiter = signup
		h.resetLimiter = reset
	}
}

// WithAuthIPLimiters configures in-memory IP-tier rate limiters for AuthHandler.
func WithAuthIPLimiters(loginIP, signupIP, resetIP *ratelimit.Limiter) AuthOption {
	return func(h *AuthHandler) {
		h.loginIPLimiter = loginIP
		h.signupIPLimiter = signupIP
		h.resetIPLimiter = resetIP
	}
}

// NewAuthHandler constructs a new AuthHandler.
func NewAuthHandler(svc auth.Service, opts ...AuthOption) *AuthHandler {
	h := &AuthHandler{svc: svc}
	for _, opt := range opts {
		opt(h)
	}
	if h.cfg == nil {
		defaultCfg := config.DefaultConfig()
		h.cfg = &defaultCfg
	}
	if h.loginIPLimiter == nil && h.cfg.RateLimitLoginIPMax > 0 {
		h.loginIPLimiter = ratelimit.NewLimiter(h.cfg.RateLimitLoginWindow, h.cfg.RateLimitLoginIPMax)
	}
	if h.signupIPLimiter == nil && h.cfg.RateLimitSignupIPMax > 0 {
		h.signupIPLimiter = ratelimit.NewLimiter(h.cfg.RateLimitSignupWindow, h.cfg.RateLimitSignupIPMax)
	}
	if h.resetIPLimiter == nil && h.cfg.RateLimitResetIPMax > 0 {
		h.resetIPLimiter = ratelimit.NewLimiter(h.cfg.RateLimitResetWindow, h.cfg.RateLimitResetIPMax)
	}
	return h
}

func decodeJSON[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var target T
	if r.Body == nil {
		errors.WriteJSON(w, errors.New(errors.CodeValidationError, "invalid request body", nil))
		return target, false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&target); err != nil {
		errors.WriteJSON(w, errors.New(errors.CodeValidationError, "invalid request body", err))
		return target, false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		errors.WriteJSON(w, errors.New(errors.CodeValidationError, "unexpected trailing data in request body", nil))
		return target, false
	}
	return target, true
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// Signup handles user registration.
func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[db.SignupRequest](w, r)
	if !ok {
		return
	}
	if err := req.Validate(); err != nil {
		errors.WriteJSON(w, err)
		return
	}

	ip := realIP(r)
	ipKey := ratelimit.IPKey(ip)
	if h.signupIPLimiter != nil && !h.signupIPLimiter.Allow(ipKey) {
		ratelimit.WriteRateLimitError(w, h.signupIPLimiter.RetryAfter(ipKey))
		return
	}

	accountKey := ratelimit.AccountKey(db.NormalizeEmail(req.Email))
	if h.signupLimiter != nil && !h.signupLimiter.Allow(accountKey) {
		ratelimit.WriteRateLimitError(w, h.signupLimiter.RetryAfter(accountKey))
		return
	}

	if _, _, err := h.svc.Signup(r.Context(), req); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, db.MessageResponse{
		Message: "if this email is new, a verification link has been sent",
	})
}

// Login handles user authentication and credential verification.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[db.LoginRequest](w, r)
	if !ok {
		return
	}
	if err := req.Validate(); err != nil {
		errors.WriteJSON(w, err)
		return
	}

	ip := realIP(r)
	ipKey := ratelimit.IPKey(ip)
	if h.loginIPLimiter != nil && !h.loginIPLimiter.Allow(ipKey) {
		ratelimit.WriteRateLimitError(w, h.loginIPLimiter.RetryAfter(ipKey))
		return
	}

	accountKey := ratelimit.AccountKey(db.NormalizeEmail(req.Email))
	if h.loginLimiter != nil && !h.loginLimiter.Allow(accountKey) {
		ratelimit.WriteRateLimitError(w, h.loginLimiter.RetryAfter(accountKey))
		return
	}

	user, err := h.svc.Login(r.Context(), req)
	if err != nil {
		slog.WarnContext(r.Context(), "login_failure",
			"ip", ip,
			"user_agent", r.UserAgent(),
			"reason", "invalid_credentials",
		)
		errors.WriteJSON(w, err)
		return
	}

	if h.loginLimiter != nil {
		h.loginLimiter.Reset(accountKey)
	}

	if h.sessionSvc != nil {
		sessType := db.SessionTypeCookie
		if r.Header.Get("X-Auth-Type") == "bearer" || r.URL.Query().Get("type") == "bearer" {
			sessType = db.SessionTypeBearer
		}

		sess, rawID, err := h.sessionSvc.CreateSession(r.Context(), user.ID, user.CredentialVersion, sessType, ip, r.UserAgent())
		if err != nil {
			// Stale credentials at mint (e.g. reset won the race after Login
			// captured the version) surface as 401, not 500.
			var appErr *errors.Error
			if errors.As(err, &appErr) && appErr != nil {
				if appErr.Code() == errors.CodeSessionInvalid {
					slog.InfoContext(r.Context(), "session_create_rejected_stale_credentials", "user_id", user.ID.String())
					errors.WriteJSON(w, err)
					return
				}
			}
			slog.ErrorContext(r.Context(), "session_create_failed", "user_id", user.ID.String(), "error", err)
			errors.WriteJSON(w, errors.New(errors.CodeInternalError, "failed to create session", err))
			return
		}

		slog.InfoContext(r.Context(), "login_success",
			"user_id", user.ID.String(),
			"ip", ip,
			"user_agent", r.UserAgent(),
			"session_type", string(sessType),
		)

		if sessType == db.SessionTypeBearer {
			writeJSON(w, http.StatusOK, map[string]any{
				"user_id":    user.ID,
				"token":      rawID,
				"expires_at": sess.AbsoluteExpiresAt,
			})
			return
		}

		cfg := h.cfg
		if cfg == nil {
			defaultCfg := config.DefaultConfig()
			cfg = &defaultCfg
		}
		session.SetSessionCookie(w, rawID, cfg)
		if _, err := csrf.IssueCookie(w, cfg); err != nil {
			slog.ErrorContext(r.Context(), "failed to issue csrf cookie on login", "err", err)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user_id": user.ID,
			"message": "Login successful",
		})
		return
	}

	writeJSON(w, http.StatusOK, db.LoginResponse{
		UserID: user.ID,
	})
}

// Logout terminates the current session.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var sessionID string
	if rawID, err := session.ReadSessionCookie(r, h.cfg); err == nil {
		sessionID = rawID
	} else if rawID, err := session.ReadBearerToken(r); err == nil {
		sessionID = rawID
	}

	if h.sessionSvc != nil && sessionID != "" {
		if err := h.sessionSvc.InvalidateSession(r.Context(), sessionID); err != nil {
			errors.WriteJSON(w, err)
			return
		}
	}
	session.ClearSessionCookie(w, h.cfg)
	csrf.ClearCookie(w, h.cfg)

	if h.svc != nil {
		if err := h.svc.Logout(r.Context(), sessionID); err != nil {
			errors.WriteJSON(w, err)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

// VerifyEmail verifies a user's email with a single-use token.
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[db.VerifyEmailRequest](w, r)
	if !ok {
		return
	}
	if err := req.Validate(); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	if err := h.svc.VerifyEmail(r.Context(), req); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, db.MessageResponse{
		Message: "email verified",
	})
}

// RequestPasswordReset initiates a password reset flow.
func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[db.PasswordResetRequest](w, r)
	if !ok {
		return
	}
	if err := req.Validate(); err != nil {
		errors.WriteJSON(w, err)
		return
	}

	ip := realIP(r)
	ipKey := ratelimit.IPKey(ip)
	if h.resetIPLimiter != nil && !h.resetIPLimiter.Allow(ipKey) {
		ratelimit.WriteRateLimitError(w, h.resetIPLimiter.RetryAfter(ipKey))
		return
	}

	accountKey := ratelimit.AccountKey(db.NormalizeEmail(req.Email))
	if h.resetLimiter != nil && !h.resetLimiter.Allow(accountKey) {
		ratelimit.WriteRateLimitError(w, h.resetLimiter.RetryAfter(accountKey))
		return
	}

	if _, err := h.svc.RequestPasswordReset(r.Context(), req); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, db.MessageResponse{
		Message: "if an account with that email exists, a password reset link has been sent",
	})
}

// ResetPassword completes a password reset using a single-use token.
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[db.PasswordResetConfirmRequest](w, r)
	if !ok {
		return
	}
	if err := req.Validate(); err != nil {
		errors.WriteJSON(w, err)
		return
	}

	ip := realIP(r)
	key := ratelimit.Key(ip, "reset-confirm")
	limiter := h.resetIPLimiter
	if limiter == nil {
		limiter = h.resetLimiter
	}
	if limiter != nil && !limiter.Allow(key) {
		ratelimit.WriteRateLimitError(w, limiter.RetryAfter(key))
		return
	}
	if h.resetLimiter != nil && limiter != h.resetLimiter && !h.resetLimiter.Allow(key) {
		ratelimit.WriteRateLimitError(w, h.resetLimiter.RetryAfter(key))
		return
	}

	if err := h.svc.ResetPassword(r.Context(), req); err != nil {
		errors.WriteJSON(w, err)
		return
	}

	session.ClearSessionCookie(w, h.cfg)

	writeJSON(w, http.StatusOK, db.MessageResponse{
		Message: "password reset successful",
	})
}
