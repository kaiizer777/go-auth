package errors

import (
	"encoding/json"
	stderrors "errors"
	"net/http"
	"strings"
)

// Code represents a machine-readable error classification.
type Code string

const (
	CodeInvalidConfig       Code = "INVALID_CONFIG"
	CodeDatabaseError       Code = "DATABASE_ERROR"
	CodeDatabaseUnavailable Code = "DATABASE_UNAVAILABLE"
	CodeMigrationFailed     Code = "MIGRATION_FAILED"
	CodeInternalError       Code = "INTERNAL_ERROR"
	CodeNotFound            Code = "NOT_FOUND"
	CodeMethodNotAllowed    Code = "METHOD_NOT_ALLOWED"

	// Phase 2: email hook dispatch (log correlation only)
	CodeEmailHookNil         Code = "EMAIL_HOOK_NIL"
	CodeEmailDispatchFailed  Code = "EMAIL_DISPATCH_FAILED"
	CodeEmailDispatchTimeout Code = "EMAIL_DISPATCH_TIMEOUT"

	// Phase 3 Core Auth error codes
	CodeInvalidCredentials Code = "INVALID_CREDENTIALS" // #nosec G101 -- error code constant, not a credential
	CodeUnauthenticated    Code = "UNAUTHENTICATED"
	CodeEmailNotVerified   Code = "EMAIL_NOT_VERIFIED"
	CodePasswordTooShort   Code = "PASSWORD_TOO_SHORT"
	CodePasswordTooLong    Code = "PASSWORD_TOO_LONG"
	CodePasswordTooCommon  Code = "PASSWORD_TOO_COMMON"
	CodeInvalidEmail       Code = "INVALID_EMAIL"
	CodeValidationError    Code = "VALIDATION_ERROR"
	CodeInvalidToken       Code = "INVALID_TOKEN"
	CodeTokenExpired       Code = "TOKEN_EXPIRED"
	CodeTokenNotFound      Code = "TOKEN_NOT_FOUND"
	CodeUserAlreadyExists  Code = "USER_ALREADY_EXISTS"
	CodeEmailAlreadyExists Code = "EMAIL_ALREADY_EXISTS"
	CodeUserNotFound       Code = "USER_NOT_FOUND"

	// Multi-Factor Authentication (MFA) error codes
	CodeMFARequired    Code = "MFA_REQUIRED"
	CodeMFAInvalidCode Code = "MFA_INVALID_CODE"

	// OAuth2 and OIDC error codes
	CodeOAuthStateInvalid         Code = "OAUTH_STATE_INVALID"
	CodeOAuthCallbackFailed       Code = "OAUTH_CALLBACK_FAILED"
	CodeOAuthProviderError        Code = "OAUTH_PROVIDER_ERROR"
	CodeOAuthAccountAlreadyLinked Code = "OAUTH_ACCOUNT_ALREADY_LINKED"
	CodeOAuthAccountNotLinked     Code = "OAUTH_ACCOUNT_NOT_LINKED"
	CodeOAuthCodeInvalid          Code = "OAUTH_CODE_INVALID"
	CodeOAuthEmailUnverified      Code = "OAUTH_EMAIL_UNVERIFIED"
	CodeOAuthAccountLinkConflict  Code = "OAUTH_ACCOUNT_LINK_CONFLICT"
	CodeOAuthProviderNotFound     Code = "OAUTH_PROVIDER_NOT_FOUND"

	// Phase 4 Session errors
	CodeSessionNotFound Code = "SESSION_NOT_FOUND" // 401
	CodeSessionExpired  Code = "SESSION_EXPIRED"   // 401
	CodeSessionInvalid  Code = "SESSION_INVALID"   // 401

	// Phase 4 CSRF errors
	CodeCSRFTokenMissing Code = "CSRF_TOKEN_MISSING" // 403
	CodeCSRFTokenInvalid Code = "CSRF_TOKEN_INVALID" // 403

	// Phase 4 Rate limiting
	CodeRateLimitExceeded Code = "RATE_LIMIT_EXCEEDED" // 429

	// Deprecated: Use CodeInvalidConfig instead.
	INVALID_CONFIG = CodeInvalidConfig
	// Deprecated: Use CodeDatabaseError instead.
	DATABASE_ERROR = CodeDatabaseError
	// Deprecated: Use CodeDatabaseUnavailable instead.
	DATABASE_UNAVAILABLE = CodeDatabaseUnavailable
	// Deprecated: Use CodeMigrationFailed instead.
	MIGRATION_FAILED = CodeMigrationFailed
	// Deprecated: Use CodeInternalError instead.
	INTERNAL_ERROR = CodeInternalError
	// Deprecated: Use CodeNotFound instead.
	NOT_FOUND = CodeNotFound
	// Deprecated: Use CodeMethodNotAllowed instead.
	METHOD_NOT_ALLOWED = CodeMethodNotAllowed

	// Deprecated: Use CodeEmailHookNil instead.
	EMAIL_HOOK_NIL = CodeEmailHookNil
	// Deprecated: Use CodeEmailDispatchFailed instead.
	EMAIL_DISPATCH_FAILED = CodeEmailDispatchFailed
	// Deprecated: Use CodeEmailDispatchTimeout instead.
	EMAIL_DISPATCH_TIMEOUT = CodeEmailDispatchTimeout

	// Deprecated: Use CodeSessionNotFound instead.
	SESSION_NOT_FOUND = CodeSessionNotFound
	// Deprecated: Use CodeSessionExpired instead.
	SESSION_EXPIRED = CodeSessionExpired
	// Deprecated: Use CodeSessionInvalid instead.
	SESSION_INVALID = CodeSessionInvalid
	// Deprecated: Use CodeCSRFTokenMissing instead.
	CSRF_TOKEN_MISSING = CodeCSRFTokenMissing
	// Deprecated: Use CodeCSRFTokenInvalid instead.
	CSRF_TOKEN_INVALID = CodeCSRFTokenInvalid
	// Deprecated: Use CodeRateLimitExceeded instead.
	RATE_LIMIT_EXCEEDED = CodeRateLimitExceeded
)

// HTTPStatus maps error codes deterministically to HTTP response status codes.
func (c Code) HTTPStatus() int {
	switch c {
	case CodePasswordTooShort, CodePasswordTooLong, CodePasswordTooCommon,
		CodeInvalidEmail, CodeValidationError, CodeInvalidToken, CodeTokenExpired,
		CodeOAuthCallbackFailed, CodeOAuthCodeInvalid, CodeOAuthEmailUnverified:
		return http.StatusBadRequest
	case CodeInvalidCredentials, CodeUnauthenticated,
		CodeSessionNotFound, CodeSessionExpired, CodeSessionInvalid,
		CodeMFARequired, CodeMFAInvalidCode:
		return http.StatusUnauthorized
	case CodeEmailNotVerified, CodeCSRFTokenMissing, CodeCSRFTokenInvalid, CodeOAuthStateInvalid:
		return http.StatusForbidden
	case CodeRateLimitExceeded:
		return http.StatusTooManyRequests
	case CodeNotFound, CodeUserNotFound, CodeTokenNotFound, CodeOAuthAccountNotLinked, CodeOAuthProviderNotFound:
		return http.StatusNotFound
	case CodeUserAlreadyExists, CodeEmailAlreadyExists, CodeOAuthAccountAlreadyLinked, CodeOAuthAccountLinkConflict:
		return http.StatusConflict
	case CodeMethodNotAllowed:
		return http.StatusMethodNotAllowed
	case CodeOAuthProviderError:
		return http.StatusBadGateway
	case CodeDatabaseUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// Response represents the unified wire error envelope.
type Response struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

// Error represents a structured domain error with code, message, and optional cause.
// Fields are unexported to ensure sentinel error instances remain immutable.
type Error struct {
	code    Code
	message string
	cause   error
}

// Code returns the error code classification.
func (e *Error) Code() Code {
	if e == nil {
		return ""
	}
	return e.code
}

// Message returns the human-readable error message.
func (e *Error) Message() string {
	if e == nil {
		return ""
	}
	return e.message
}

// Error returns the human-readable string representation of the error.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.cause != nil {
		if e.message != "" {
			return e.message + ": " + e.cause.Error()
		}
		return e.cause.Error()
	}
	if e.message != "" {
		return e.message
	}
	return string(e.code)
}

// Unwrap returns the underlying cause error.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Is reports whether this error matches the target error.
func (e *Error) Is(target error) bool {
	if e == nil && target == nil {
		return true
	}
	if target == nil {
		return false
	}
	t, ok := target.(*Error)
	if !ok {
		return e != nil && e.cause != nil && stderrors.Is(e.cause, target)
	}
	if e == t {
		return true
	}
	if e == nil || t == nil {
		return false
	}
	// An empty *Error (no code, message, or cause) matches only by identity.
	if t.code == "" && t.message == "" && t.cause == nil {
		return false
	}
	if t.code != "" && e.code != t.code {
		return false
	}
	if t.message != "" && e.message != t.message {
		return false
	}
	if t.cause != nil && !stderrors.Is(e.cause, t.cause) {
		return false
	}
	return true
}

// HTTPStatus returns the mapped HTTP status code for this error.
func (e *Error) HTTPStatus() int {
	if e == nil {
		return http.StatusOK
	}
	return e.code.HTTPStatus()
}

// New constructs a new Error instance.
func New(code Code, message string, cause error) *Error {
	return &Error{
		code:    code,
		message: message,
		cause:   cause,
	}
}

// Wrap wraps an existing error with a classified domain error. If cause is already
// an *Error with a non-empty code, its code is preserved; otherwise defaultCode is used.
// It returns error (rather than *Error) so a nil cause safely returns a true nil interface.
func Wrap(cause error, defaultCode Code, message string) error {
	if cause == nil {
		return nil
	}
	code := defaultCode
	var appErr *Error
	if As(cause, &appErr) && appErr != nil && appErr.code != "" {
		code = appErr.code
	}
	return New(code, message, cause)
}

// WrapOverride wraps cause error with the specified code unconditionally,
// even if cause is already a classified *Error with a different code.
func WrapOverride(cause error, code Code, message string) error {
	if cause == nil {
		return nil
	}
	return New(code, message, cause)
}

// Is reports whether any error in err's tree matches target.
func Is(err, target error) bool {
	return stderrors.Is(err, target)
}

// As finds the first error in err's tree that matches target, and if one is found, sets
// target to that error value and returns true. Otherwise, it returns false.
func As(err error, target any) bool {
	return stderrors.As(err, target)
}

// Unwrap returns the result of calling the Unwrap method on err, if err's
// type contains an Unwrap method returning error.
// Otherwise, Unwrap returns nil.
func Unwrap(err error) error {
	return stderrors.Unwrap(err)
}

// Predefined sentinel errors for config.Validate().
var (
	ErrDatabaseURLRequired             = New(CodeInvalidConfig, "database URL is required", nil)
	ErrDatabaseURLInvalid              = New(CodeInvalidConfig, "database URL is invalid", nil)
	ErrMaxOpenConnsNegative            = New(CodeInvalidConfig, "max open conns cannot be negative", nil)
	ErrMaxIdleConnsNegative            = New(CodeInvalidConfig, "max idle conns cannot be negative", nil)
	ErrMaxIdleExceedsOpen              = New(CodeInvalidConfig, "max idle conns cannot exceed max open conns", nil)
	ErrConnMaxLifetimeNegative         = New(CodeInvalidConfig, "conn max lifetime cannot be negative", nil)
	ErrConnMaxIdleTimeNegative         = New(CodeInvalidConfig, "conn max idle time cannot be negative", nil)
	ErrBaseURLRequired                 = New(CodeInvalidConfig, "base URL is required", nil)
	ErrBaseURLInvalid                  = New(CodeInvalidConfig, "base URL is invalid", nil)
	ErrAllowedOriginInvalid            = New(CodeInvalidConfig, "allowed origin is invalid", nil)
	ErrEmailDispatchTimeoutNegative    = New(CodeInvalidConfig, "email dispatch timeout cannot be negative", nil)
	ErrArgon2MemoryTooLow              = New(CodeInvalidConfig, "argon2 memory too low", nil)
	ErrArgon2TimeTooLow                = New(CodeInvalidConfig, "argon2 time too low", nil)
	ErrArgon2ParallelismZero           = New(CodeInvalidConfig, "argon2 parallelism must be at least 1", nil)
	ErrArgon2SaltLengthTooShort        = New(CodeInvalidConfig, "argon2 salt length too short", nil)
	ErrArgon2KeyLengthTooShort         = New(CodeInvalidConfig, "argon2 key length too short", nil)
	ErrPasswordMinLengthTooShort       = New(CodeInvalidConfig, "password min length must be at least 8", nil)
	ErrPasswordMaxLengthInvalid        = New(CodeInvalidConfig, "password max length must be greater than min length and at most 128", nil)
	ErrVerificationTokenExpiryInvalid  = New(CodeInvalidConfig, "verification token expiry must be between 15m and 60m", nil)
	ErrPasswordResetTokenExpiryInvalid = New(CodeInvalidConfig, "password reset token expiry must be between 15m and 60m", nil)
	ErrSessionIdleTimeoutInvalid       = New(CodeInvalidConfig, "SessionIdleTimeout must be greater than zero", nil)
	ErrSessionAbsoluteMaxAgeInvalid    = New(CodeInvalidConfig, "SessionAbsoluteMaxAge must be greater than SessionIdleTimeout", nil)
	ErrSessionSameSiteNoneInsecure     = New(CodeInvalidConfig, "SessionCookieSameSite=None requires SessionCookieSecure=true", nil)
	ErrRateLimitWindowInvalid          = New(CodeInvalidConfig, "rate limit window and cleanup tick must be greater than zero", nil)
	ErrRateLimitMaxInvalid             = New(CodeInvalidConfig, "rate limit max must be >= 1", nil)
	ErrSessionCookieNameInvalid        = New(CodeInvalidConfig, "session cookie name is invalid", nil)
	ErrSessionCookiePathInvalid        = New(CodeInvalidConfig, "session cookie path is invalid", nil)
	ErrSessionCookieDomainInvalid      = New(CodeInvalidConfig, "session cookie domain is invalid", nil)
	ErrCSRFCookieNameInvalid           = New(CodeInvalidConfig, "CSRF cookie name is invalid", nil)
	ErrCSRFHeaderNameInvalid           = New(CodeInvalidConfig, "CSRF header name is invalid", nil)
	ErrCSRFCookieNameCollision         = New(CodeInvalidConfig, "CSRF cookie name must not match session cookie name", nil)
	ErrFrameOptionsInvalid             = New(CodeInvalidConfig, "frame options must be DENY or SAMEORIGIN", nil)
	ErrHSTSMaxAgeNegative              = New(CodeInvalidConfig, "HSTS max age cannot be negative", nil)
	ErrHSTSMaxAgeTooSmall              = New(CodeInvalidConfig, "HSTS max age must be at least one second", nil)
	ErrReferrerPolicyInvalid           = New(CodeInvalidConfig, "referrer policy is invalid", nil)
	ErrCSRFCookieMaxAgeInvalid         = New(CodeInvalidConfig, "CSRF cookie max age must be at least one second", nil)
	ErrOAuthProviderUnknown            = New(CodeInvalidConfig, "unknown oauth provider", nil)
	ErrOAuthClientIDRequired           = New(CodeInvalidConfig, "oauth provider client ID is required", nil)
	ErrOAuthRedirectURLRequired        = New(CodeInvalidConfig, "oauth provider redirect URL is required", nil)
	ErrOAuthClientSecretRequired       = New(CodeInvalidConfig, "oauth provider client secret is required", nil)
	ErrOAuthStateTTLInvalid            = New(CodeInvalidConfig, "oauth state TTL must be positive", nil)
	ErrOAuthStateCookieNameInvalid     = New(CodeInvalidConfig, "oauth state cookie name is invalid", nil)
	ErrOAuthStateCookiePathInvalid     = New(CodeInvalidConfig, "oauth state cookie path is invalid", nil)
	ErrOAuthStateSecretTooShort        = New(CodeInvalidConfig, "oauth state secret length too short", nil)
	ErrOAuthStateSecretRequired        = New(CodeInvalidConfig, "oauth state secret is required when providers are configured", nil)
	ErrOAuthStateCookieNameCollision   = New(CodeInvalidConfig, "oauth state cookie name must not match session or CSRF cookie name", nil)

	// Predefined sentinel errors for Phase 3 Core Auth.
	ErrInvalidCredentials = New(CodeInvalidCredentials, "invalid email or password", nil)
	ErrUnauthenticated    = New(CodeUnauthenticated, "authentication required", nil)
	ErrEmailNotVerified   = New(CodeEmailNotVerified, "email address not verified", nil)
	ErrUserAlreadyExists  = New(CodeUserAlreadyExists, "user already exists", nil)
	ErrEmailAlreadyExists = New(CodeEmailAlreadyExists, "email already exists", nil)
	ErrUserNotFound       = New(CodeUserNotFound, "user not found", nil)
	ErrInvalidToken       = New(CodeInvalidToken, "token is invalid or malformed", nil)
	ErrTokenExpired       = New(CodeTokenExpired, "token has expired", nil)
	ErrTokenNotFound      = New(CodeTokenNotFound, "token not found", nil)
	ErrPasswordTooShort   = New(CodePasswordTooShort, "password is too short", nil)
	ErrPasswordTooLong    = New(CodePasswordTooLong, "password is too long", nil)
	ErrPasswordTooCommon  = New(CodePasswordTooCommon, "password is too common", nil)
	ErrInvalidEmail       = New(CodeInvalidEmail, "invalid email address", nil)
	ErrValidationError    = New(CodeValidationError, "validation failed", nil)

	// Predefined sentinel errors for Multi-Factor Authentication (MFA).
	ErrMFARequired    = New(CodeMFARequired, "mfa verification required", nil)
	ErrMFAInvalidCode = New(CodeMFAInvalidCode, "invalid mfa code", nil)

	// Predefined sentinel errors for OAuth2 and OIDC.
	ErrOAuthStateInvalid         = New(CodeOAuthStateInvalid, "invalid oauth state", nil)
	ErrOAuthCallbackFailed       = New(CodeOAuthCallbackFailed, "oauth callback failed", nil)
	ErrOAuthProviderError        = New(CodeOAuthProviderError, "oauth provider error", nil)
	ErrOAuthAccountAlreadyLinked = New(CodeOAuthAccountAlreadyLinked, "oauth account already linked", nil)
	ErrOAuthAccountNotLinked     = New(CodeOAuthAccountNotLinked, "oauth account not linked", nil)
	ErrOAuthCodeInvalid          = New(CodeOAuthCodeInvalid, "oauth code is invalid", nil)
	ErrOAuthEmailUnverified      = New(CodeOAuthEmailUnverified, "oauth provider email is not verified", nil)
	ErrOAuthAccountLinkConflict  = New(CodeOAuthAccountLinkConflict, "cannot link oauth identity to unverified local account", nil)
	ErrOAuthProviderNotFound     = New(CodeOAuthProviderNotFound, "oauth provider not found", nil)

	// Predefined sentinel errors for Phase 4 Session, CSRF, and Rate Limiting.
	ErrSessionNotFound   = New(CodeSessionNotFound, "Session is invalid or has expired", nil)
	ErrSessionExpired    = New(CodeSessionExpired, "Session is invalid or has expired", nil)
	ErrSessionInvalid    = New(CodeSessionInvalid, "Session is invalid or has expired", nil)
	ErrCSRFTokenMissing  = New(CodeCSRFTokenMissing, "CSRF token is missing", nil)
	ErrCSRFTokenInvalid  = New(CodeCSRFTokenInvalid, "CSRF token is invalid", nil)
	ErrRateLimitExceeded = New(CodeRateLimitExceeded, "Too many requests, try again later", nil)

	// Aliases
	ErrInvalidCookieName   = ErrSessionCookieNameInvalid
	ErrInvalidCookiePath   = ErrSessionCookiePathInvalid
	ErrInvalidCookieDomain = ErrSessionCookieDomainInvalid
	ErrInvalidSession      = ErrSessionInvalid
)

// WriteJSON writes an error response envelope to the response writer with the appropriate HTTP status.
// For 500 status responses, internal details are withheld and a fixed generic message is returned.
func WriteJSON(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	var appErr *Error
	var resp Response
	var status int

	if As(err, &appErr) && appErr != nil {
		status = appErr.code.HTTPStatus()
		code := appErr.code
		if code == CodeSessionNotFound || code == CodeSessionExpired {
			code = CodeSessionInvalid
		}
		msg := appErr.message
		if msg == "" {
			switch appErr.code {
			case CodeSessionNotFound, CodeSessionExpired, CodeSessionInvalid:
				msg = "Session is invalid or has expired"
			case CodeCSRFTokenMissing:
				msg = "CSRF token is missing"
			case CodeCSRFTokenInvalid:
				msg = "CSRF token is invalid"
			case CodeRateLimitExceeded:
				msg = "Too many requests, try again later"
			default:
				if status == http.StatusInternalServerError {
					msg = "internal server error"
				} else {
					msg = strings.ToLower(http.StatusText(status))
				}
			}
		}
		resp = Response{
			Code:    code,
			Message: msg,
		}
	} else {
		status = http.StatusInternalServerError
		resp = Response{
			Code:    CodeInternalError,
			Message: "internal server error",
		}
	}

	if status == http.StatusInternalServerError {
		resp = Response{
			Code:    CodeInternalError,
			Message: "internal server error",
		}
	}

	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// WriteHTTP writes an error response envelope to the response writer conforming to wire response standards.
func WriteHTTP(w http.ResponseWriter, err error) {
	WriteJSON(w, err)
}
