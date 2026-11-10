package errors

import (
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		expected string
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: "",
		},
		{
			name:     "message only",
			err:      New(CodeInvalidConfig, "invalid config supplied", nil),
			expected: "invalid config supplied",
		},
		{
			name:     "message with cause",
			err:      New(CodeDatabaseError, "db query failed", stderrors.New("connection reset")),
			expected: "db query failed: connection reset",
		},
		{
			name:     "cause only without message",
			err:      New(CodeInternalError, "", stderrors.New("disk full")),
			expected: "disk full",
		},
		{
			name:     "code only without message or cause",
			err:      New(CodeNotFound, "", nil),
			expected: "NOT_FOUND",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	cause := stderrors.New("root cause")
	err := New(CodeDatabaseError, "wrapper error", cause)

	if got := err.Unwrap(); got != cause {
		t.Fatalf("Unwrap() = %v, want %v", got, cause)
	}

	var nilErr *Error
	if got := nilErr.Unwrap(); got != nil {
		t.Fatalf("nil.Unwrap() = %v, want nil", got)
	}
}

func TestError_Is(t *testing.T) {
	root := stderrors.New("base failure")
	err1 := New(CodeInvalidConfig, "bad input", root)
	err2 := New(CodeInvalidConfig, "bad input", root)
	errDifferentCode := New(CodeDatabaseError, "bad input", root)

	if !Is(err1, err2) {
		t.Error("expected err1 to match err2 with identical code, message, and cause")
	}
	if Is(err1, errDifferentCode) {
		t.Error("expected err1 not to match errDifferentCode")
	}
	if !Is(err1, root) {
		t.Error("expected err1 to match root cause via unwrap")
	}
	if !Is(ErrDatabaseURLRequired, ErrDatabaseURLRequired) {
		t.Error("expected sentinel to match itself")
	}

	var typedNil *Error
	if Is(err1, typedNil) {
		t.Error("expected non-nil error not to match typed-nil target")
	}
	if Is(typedNil, err1) {
		t.Error("expected typed-nil error not to match non-nil target")
	}
}

func TestError_As(t *testing.T) {
	orig := New(CodeNotFound, "user not found", nil)
	wrapped := New(CodeInternalError, "service layer", orig)

	var target *Error
	if !As(wrapped, &target) {
		t.Fatal("expected As to find *Error")
	}
	if target.Code() != CodeInternalError {
		t.Errorf("got code %s, want %s", target.Code(), CodeInternalError)
	}
}

func TestCode_HTTPStatus(t *testing.T) {
	tests := []struct {
		code       Code
		wantStatus int
	}{
		{CodeDatabaseUnavailable, http.StatusServiceUnavailable},
		{CodeNotFound, http.StatusNotFound},
		{CodeMethodNotAllowed, http.StatusMethodNotAllowed},
		{CodeInvalidConfig, http.StatusInternalServerError},
		{CodeDatabaseError, http.StatusInternalServerError},
		{CodeMigrationFailed, http.StatusInternalServerError},
		{CodeInternalError, http.StatusInternalServerError},
		{CodeInvalidCredentials, http.StatusUnauthorized},
		{CodeUnauthenticated, http.StatusUnauthorized},
		{CodeEmailNotVerified, http.StatusForbidden},
		{CodePasswordTooShort, http.StatusBadRequest},
		{CodePasswordTooLong, http.StatusBadRequest},
		{CodePasswordTooCommon, http.StatusBadRequest},
		{CodeInvalidEmail, http.StatusBadRequest},
		{CodeValidationError, http.StatusBadRequest},
		{CodeInvalidToken, http.StatusBadRequest},
		{CodeTokenExpired, http.StatusBadRequest},
		{CodeUserAlreadyExists, http.StatusInternalServerError},
		{CodeUserNotFound, http.StatusInternalServerError},
		{Code("CUSTOM_UNKNOWN"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			if got := tt.code.HTTPStatus(); got != tt.wantStatus {
				t.Errorf("HTTPStatus() = %d, want %d", got, tt.wantStatus)
			}
			err := New(tt.code, "test", nil)
			if got := err.HTTPStatus(); got != tt.wantStatus {
				t.Errorf("Error.HTTPStatus() = %d, want %d", got, tt.wantStatus)
			}
		})
	}

	var nilErr *Error
	if got := nilErr.HTTPStatus(); got != http.StatusOK {
		t.Errorf("nil Error.HTTPStatus() = %d, want %d", got, http.StatusOK)
	}
}

func TestWriteJSON(t *testing.T) {
	t.Run("typed domain error with mapped status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		err := New(CodeDatabaseUnavailable, "database unavailable", nil)

		WriteJSON(rec, err)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", got)
		}

		var resp Response
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Code != CodeDatabaseUnavailable {
			t.Errorf("got code %q, want %q", resp.Code, CodeDatabaseUnavailable)
		}
		if resp.Message != "database unavailable" {
			t.Errorf("got message %q, want %q", resp.Message, "database unavailable")
		}
	})

	t.Run("standard library error defaults to 500 internal error", func(t *testing.T) {
		rec := httptest.NewRecorder()
		err := stderrors.New("unexpected crash")

		WriteJSON(rec, err)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
		}

		var resp Response
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Code != CodeInternalError {
			t.Errorf("got code %q, want %q", resp.Code, CodeInternalError)
		}
		if resp.Message != "internal server error" {
			t.Errorf("got message %q, want %q", resp.Message, "internal server error")
		}
	})

	t.Run("internal error with empty message masks underlying cause", func(t *testing.T) {
		rec := httptest.NewRecorder()
		err := New(CodeInternalError, "", stderrors.New("pq: password authentication failed"))

		WriteJSON(rec, err)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
		}

		var resp Response
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Code != CodeInternalError {
			t.Errorf("got code %q, want %q", resp.Code, CodeInternalError)
		}
		if resp.Message != "internal server error" {
			t.Errorf("got message %q, want %q", resp.Message, "internal server error")
		}
	})

	t.Run("nil error writes 200 OK", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteJSON(rec, nil)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
		if got := strings.TrimSpace(rec.Body.String()); got != "" {
			t.Errorf("expected empty body, got %q", got)
		}
	})
}

func TestSentinels(t *testing.T) {
	sentinels := []*Error{
		ErrDatabaseURLRequired,
		ErrBaseURLRequired,
		ErrBaseURLInvalid,
		ErrMaxOpenConnsNegative,
		ErrMaxIdleConnsNegative,
		ErrMaxIdleExceedsOpen,
		ErrConnMaxLifetimeNegative,
		ErrConnMaxIdleTimeNegative,
		ErrEmailDispatchTimeoutNegative,
		ErrArgon2MemoryTooLow,
		ErrArgon2TimeTooLow,
		ErrArgon2ParallelismZero,
		ErrArgon2SaltLengthTooShort,
		ErrArgon2KeyLengthTooShort,
		ErrPasswordMinLengthTooShort,
		ErrPasswordMaxLengthInvalid,
		ErrVerificationTokenExpiryInvalid,
		ErrPasswordResetTokenExpiryInvalid,
	}

	for _, s := range sentinels {
		if s.Code() != CodeInvalidConfig {
			t.Errorf("expected %s to have CodeInvalidConfig, got %s", s.Message(), s.Code())
		}
		if s.Message() == "" {
			t.Errorf("sentinel %v has empty message", s)
		}
	}
}

func TestWrap(t *testing.T) {
	t.Run("nil cause returns true nil interface", func(t *testing.T) {
		var err error = Wrap(nil, CodeDatabaseError, "wrapped")
		if err != nil {
			t.Fatalf("expected nil interface, got non-nil: %v", err)
		}
	})

	t.Run("untyped error uses default code", func(t *testing.T) {
		cause := stderrors.New("disk failure")
		wrapped := Wrap(cause, CodeDatabaseError, "failed to read")
		var appErr *Error
		if !As(wrapped, &appErr) {
			t.Fatalf("expected *Error, got %T", wrapped)
		}
		if appErr.Code() != CodeDatabaseError {
			t.Errorf("got code %s, want %s", appErr.Code(), CodeDatabaseError)
		}
		if appErr.Message() != "failed to read" {
			t.Errorf("got message %q, want %q", appErr.Message(), "failed to read")
		}
		if appErr.Unwrap() != cause {
			t.Errorf("got cause %v, want %v", appErr.Unwrap(), cause)
		}
	})

	t.Run("typed error preserves original code", func(t *testing.T) {
		cause := New(CodeDatabaseUnavailable, "db unreachable", nil)
		wrapped := Wrap(cause, CodeDatabaseError, "outer layer")
		var appErr *Error
		if !As(wrapped, &appErr) {
			t.Fatalf("expected *Error, got %T", wrapped)
		}
		if appErr.Code() != CodeDatabaseUnavailable {
			t.Errorf("got code %s, want %s", appErr.Code(), CodeDatabaseUnavailable)
		}
		if !Is(wrapped, cause) {
			t.Errorf("expected wrapped error to match cause via Is")
		}
	})
}
