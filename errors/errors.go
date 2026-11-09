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

	// Aliases
	INVALID_CONFIG       = CodeInvalidConfig
	DATABASE_ERROR       = CodeDatabaseError
	DATABASE_UNAVAILABLE = CodeDatabaseUnavailable
	MIGRATION_FAILED     = CodeMigrationFailed
	INTERNAL_ERROR       = CodeInternalError
	NOT_FOUND            = CodeNotFound
	METHOD_NOT_ALLOWED   = CodeMethodNotAllowed
)

// HTTPStatus maps error codes deterministically to HTTP response status codes.
func (c Code) HTTPStatus() int {
	switch c {
	case CodeDatabaseUnavailable:
		return http.StatusServiceUnavailable
	case CodeNotFound:
		return http.StatusNotFound
	case CodeMethodNotAllowed:
		return http.StatusMethodNotAllowed
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
		return false
	}
	if e == t {
		return true
	}
	if e == nil || t == nil {
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
func Wrap(cause error, defaultCode Code, message string) *Error {
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

// Re-exports of standard library errors package functions.
var (
	Is     = stderrors.Is
	As     = stderrors.As
	Unwrap = stderrors.Unwrap
)

// Predefined sentinel errors for config.Validate().
var (
	ErrDatabaseURLRequired     = New(CodeInvalidConfig, "database URL is required", nil)
	ErrMaxOpenConnsNegative    = New(CodeInvalidConfig, "max open conns cannot be negative", nil)
	ErrMaxIdleConnsNegative    = New(CodeInvalidConfig, "max idle conns cannot be negative", nil)
	ErrMaxIdleExceedsOpen      = New(CodeInvalidConfig, "max idle conns cannot exceed max open conns", nil)
	ErrConnMaxLifetimeNegative = New(CodeInvalidConfig, "conn max lifetime cannot be negative", nil)
	ErrConnMaxIdleTimeNegative = New(CodeInvalidConfig, "conn max idle time cannot be negative", nil)
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
		msg := appErr.message
		if msg == "" {
			if status == http.StatusInternalServerError {
				msg = "internal server error"
			} else {
				msg = strings.ToLower(http.StatusText(status))
			}
		}
		resp = Response{
			Code:    appErr.code,
			Message: msg,
		}
	} else {
		status = http.StatusInternalServerError
		resp = Response{
			Code:    CodeInternalError,
			Message: "internal server error",
		}
	}

	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
