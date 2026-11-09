package errors

import (
	"encoding/json"
	stderrors "errors"
	"net/http"
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
type Error struct {
	Code    Code
	Message string
	Cause   error
}

// Error returns the human-readable string representation of the error.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause != nil {
		if e.Message != "" {
			return e.Message + ": " + e.Cause.Error()
		}
		return e.Cause.Error()
	}
	if e.Message != "" {
		return e.Message
	}
	return string(e.Code)
}

// Unwrap returns the underlying cause error.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is reports whether this error matches the target error.
func (e *Error) Is(target error) bool {
	if e == nil && target == nil {
		return true
	}
	if e == nil || target == nil {
		return false
	}
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	if e == t {
		return true
	}
	if t.Code != "" && e.Code != t.Code {
		return false
	}
	if t.Message != "" && e.Message != t.Message {
		return false
	}
	if t.Cause != nil && !stderrors.Is(e.Cause, t.Cause) {
		return false
	}
	return true
}

// HTTPStatus returns the mapped HTTP status code for this error.
func (e *Error) HTTPStatus() int {
	if e == nil {
		return http.StatusOK
	}
	return e.Code.HTTPStatus()
}

// New constructs a new Error instance.
func New(code Code, message string, cause error) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
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
		status = appErr.Code.HTTPStatus()
		msg := appErr.Message
		if msg == "" {
			msg = appErr.Error()
		}
		resp = Response{
			Code:    appErr.Code,
			Message: msg,
		}
	} else {
		status = http.StatusInternalServerError
		resp = Response{
			Code:    CodeInternalError,
			Message: err.Error(),
		}
	}

	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
