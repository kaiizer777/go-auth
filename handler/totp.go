package handler

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/kaiizer777/go-auth/csrf"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/ratelimit"
	"github.com/kaiizer777/go-auth/session"
)

type totpConfirmRequest struct {
	Code string `json:"code"`
}

type totpVerifyRequest struct {
	ChallengeToken string `json:"challenge_token"`
	Code           string `json:"code"`
}

type totpBackupRequest struct {
	ChallengeToken string `json:"challenge_token"`
	BackupCode     string `json:"backup_code"`
}

type totpDisableRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
	TotpCode string `json:"totp_code"`
}

func isSixDigits(code string) bool {
	if len(code) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// HandleTotpEnroll initiates TOTP setup for the authenticated user and returns the provisioning URI and QR code.
func (h *Handler) HandleTotpEnroll(w http.ResponseWriter, r *http.Request) {
	if h.totpSvc == nil {
		errors.WriteHTTP(w, errors.New(errors.CodeInternalError, "totp service unavailable", nil))
		return
	}
	userID := userIDFromContext(r.Context())
	if userID == uuid.Nil {
		errors.WriteHTTP(w, errors.ErrUnauthenticated)
		return
	}

	res, err := h.totpSvc.Enroll(r.Context(), userID.String())
	if err != nil {
		errors.WriteHTTP(w, err)
		return
	}

	slog.InfoContext(r.Context(), "totp_enrolled",
		"user_id", userID.String(),
		"ip", realIP(r),
		"user_agent", r.UserAgent(),
	)

	writeJSON(w, http.StatusOK, res)
}

// HandleTotpConfirm verifies the initial setup code and activates TOTP for the authenticated user.
func (h *Handler) HandleTotpConfirm(w http.ResponseWriter, r *http.Request) {
	if h.totpSvc == nil {
		errors.WriteHTTP(w, errors.New(errors.CodeInternalError, "totp service unavailable", nil))
		return
	}
	userID := userIDFromContext(r.Context())
	if userID == uuid.Nil {
		errors.WriteHTTP(w, errors.ErrUnauthenticated)
		return
	}

	req, ok := decodeJSON[totpConfirmRequest](w, r)
	if !ok {
		return
	}

	code := strings.TrimSpace(req.Code)
	if !isSixDigits(code) {
		errors.WriteHTTP(w, errors.ErrTOTPCodeInvalid)
		return
	}

	backupCodes, err := h.totpSvc.ConfirmEnrollment(r.Context(), userID.String(), code)
	if err != nil {
		errors.WriteHTTP(w, err)
		return
	}

	slog.InfoContext(r.Context(), "totp_confirmed",
		"user_id", userID.String(),
		"ip", realIP(r),
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"confirmed":    true,
		"backup_codes": backupCodes,
	})
}

// HandleTotpVerify validates a challenge token and TOTP code, issuing an authenticated session on success.
func (h *Handler) HandleTotpVerify(w http.ResponseWriter, r *http.Request) {
	if h.totpSvc == nil {
		errors.WriteHTTP(w, errors.New(errors.CodeInternalError, "totp service unavailable", nil))
		return
	}

	req, ok := decodeJSON[totpVerifyRequest](w, r)
	if !ok {
		return
	}

	tokenStr := strings.TrimSpace(req.ChallengeToken)
	code := strings.TrimSpace(req.Code)
	if tokenStr == "" {
		errors.WriteHTTP(w, errors.ErrTwoFactorTokenInvalid)
		return
	}
	if !isSixDigits(code) {
		errors.WriteHTTP(w, errors.ErrTOTPCodeInvalid)
		return
	}

	ip := realIP(r)

	// Step 1: Rate limit by client IP before token lookup
	if h.totpLimiter != nil {
		ipKey := ratelimit.TOTPIPKey(ip)
		if !h.totpLimiter.Allow(ipKey) {
			slog.WarnContext(r.Context(), "rate_limit_exceeded",
				"ip", ip,
				"endpoint", r.URL.Path,
			)
			ratelimit.WriteRateLimitError(w, h.totpLimiter.RetryAfter(ipKey))
			return
		}
	}

	// Validate challenge token non-destructively
	token, err := h.totpSvc.ValidateChallengeToken(r.Context(), tokenStr)
	if err != nil {
		errors.WriteHTTP(w, err)
		return
	}

	// Verify the TOTP code (VerifyCode validates user-level rate limit and code)
	if err := h.totpSvc.VerifyCode(r.Context(), token.UserID.String(), code, ""); err != nil {
		if _, attemptErr := h.totpSvc.RecordTokenAttempt(r.Context(), tokenStr); attemptErr != nil {
			errors.WriteHTTP(w, attemptErr)
			return
		}
		errors.WriteHTTP(w, err)
		return
	}

	if h.totpLimiter != nil {
		h.totpLimiter.Reset(ratelimit.TOTPIPKey(ip))
	}

	// Consume challenge token (hard delete) and retrieve user
	user, err := h.totpSvc.ConsumeChallengeToken(r.Context(), tokenStr)
	if err != nil {
		errors.WriteHTTP(w, err)
		return
	}

	h.issueTotpSession(w, r, user, "totp_verified")
}

// HandleTotpBackup validates a challenge token and single-use backup code, issuing a session on success.
func (h *Handler) HandleTotpBackup(w http.ResponseWriter, r *http.Request) {
	if h.totpSvc == nil {
		errors.WriteHTTP(w, errors.New(errors.CodeInternalError, "totp service unavailable", nil))
		return
	}

	req, ok := decodeJSON[totpBackupRequest](w, r)
	if !ok {
		return
	}

	tokenStr := strings.TrimSpace(req.ChallengeToken)
	backupCode := strings.TrimSpace(req.BackupCode)
	if tokenStr == "" {
		errors.WriteHTTP(w, errors.ErrTwoFactorTokenInvalid)
		return
	}
	if backupCode == "" {
		errors.WriteHTTP(w, errors.ErrBackupCodeInvalid)
		return
	}

	ip := realIP(r)

	// Step 1: Rate limit by client IP before token lookup
	if h.totpLimiter != nil {
		ipKey := ratelimit.TOTPIPKey(ip)
		if !h.totpLimiter.Allow(ipKey) {
			slog.WarnContext(r.Context(), "rate_limit_exceeded",
				"ip", ip,
				"endpoint", r.URL.Path,
			)
			ratelimit.WriteRateLimitError(w, h.totpLimiter.RetryAfter(ipKey))
			return
		}
	}

	// Validate challenge token non-destructively
	token, err := h.totpSvc.ValidateChallengeToken(r.Context(), tokenStr)
	if err != nil {
		errors.WriteHTTP(w, err)
		return
	}

	// Verify the backup code (VerifyBackupCode validates user-level rate limit and code)
	if err := h.totpSvc.VerifyBackupCode(r.Context(), token.UserID.String(), backupCode, ""); err != nil {
		if _, attemptErr := h.totpSvc.RecordTokenAttempt(r.Context(), tokenStr); attemptErr != nil {
			errors.WriteHTTP(w, attemptErr)
			return
		}
		errors.WriteHTTP(w, err)
		return
	}

	if h.totpLimiter != nil {
		h.totpLimiter.Reset(ratelimit.TOTPIPKey(ip))
	}

	// Consume challenge token (hard delete) and retrieve user
	user, err := h.totpSvc.ConsumeChallengeToken(r.Context(), tokenStr)
	if err != nil {
		errors.WriteHTTP(w, err)
		return
	}

	h.issueTotpSession(w, r, user, "backup_code_used")
}

// HandleTotpDisable verifies credentials and disables TOTP for the authenticated user.
func (h *Handler) HandleTotpDisable(w http.ResponseWriter, r *http.Request) {
	if h.totpSvc == nil {
		errors.WriteHTTP(w, errors.New(errors.CodeInternalError, "totp service unavailable", nil))
		return
	}
	userID := userIDFromContext(r.Context())
	if userID == uuid.Nil {
		errors.WriteHTTP(w, errors.ErrUnauthenticated)
		return
	}

	req, ok := decodeJSON[totpDisableRequest](w, r)
	if !ok {
		return
	}

	code := strings.TrimSpace(req.Code)
	if code == "" {
		code = strings.TrimSpace(req.TotpCode)
	}
	password := strings.TrimSpace(req.Password)

	if password == "" && code == "" {
		errors.WriteHTTP(w, errors.ErrInvalidCredentials)
		return
	}

	if err := h.totpSvc.DisableTOTP(r.Context(), userID.String(), password, code); err != nil {
		errors.WriteHTTP(w, err)
		return
	}

	slog.InfoContext(r.Context(), "totp_disabled",
		"user_id", userID.String(),
		"ip", realIP(r),
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"disabled": true,
		"message":  "Two-factor authentication disabled",
	})
}

// HandleTotpStatus returns whether TOTP is enabled for the authenticated user.
func (h *Handler) HandleTotpStatus(w http.ResponseWriter, r *http.Request) {
	if h.totpSvc == nil {
		errors.WriteHTTP(w, errors.New(errors.CodeInternalError, "totp service unavailable", nil))
		return
	}
	userID := userIDFromContext(r.Context())
	if userID == uuid.Nil {
		errors.WriteHTTP(w, errors.ErrUnauthenticated)
		return
	}

	enabled, err := h.totpSvc.Status(r.Context(), userID.String())
	if err != nil {
		errors.WriteHTTP(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": enabled,
	})
}

func (h *Handler) issueTotpSession(w http.ResponseWriter, r *http.Request, user *db.User, eventName string) {
	ip := realIP(r)
	if h.sessionSvc != nil {
		sessType := db.SessionTypeCookie
		if r.Header.Get("X-Auth-Type") == "bearer" || r.URL.Query().Get("type") == "bearer" {
			sessType = db.SessionTypeBearer
		}

		sess, rawID, err := h.sessionSvc.CreateSession(r.Context(), user.ID, user.CredentialVersion, sessType, ip, r.UserAgent())
		if err != nil {
			var appErr *errors.Error
			if errors.As(err, &appErr) && appErr != nil {
				if appErr.Code() == errors.CodeSessionInvalid {
					slog.InfoContext(r.Context(), "session_create_rejected_stale_credentials", "user_id", user.ID.String())
					errors.WriteHTTP(w, err)
					return
				}
			}
			slog.ErrorContext(r.Context(), "session_create_failed", "user_id", user.ID.String(), "error", err)
			errors.WriteHTTP(w, errors.New(errors.CodeInternalError, "failed to create session", err))
			return
		}

		slog.InfoContext(r.Context(), eventName,
			"user_id", user.ID.String(),
			"ip", ip,
			"user_agent", r.UserAgent(),
			"session_type", string(sessType),
		)

		if sessType == db.SessionTypeBearer {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			writeJSON(w, http.StatusOK, map[string]any{
				"user_id":    user.ID,
				"token":      rawID,
				"expires_at": sess.AbsoluteExpiresAt,
			})
			return
		}

		session.SetSessionCookie(w, rawID, &h.cfg)
		csrfToken, err := csrf.IssueCookie(w, &h.cfg)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to issue csrf cookie on totp session creation", "err", err)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user_id":    user.ID,
			"csrf_token": csrfToken,
			"message":    "Two-factor authentication successful",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": user.ID,
		"message": "Two-factor authentication successful",
	})
}
