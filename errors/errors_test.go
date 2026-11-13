package errors

import (
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"slices"
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
	if !err1.Is(root) {
		t.Error("expected direct err1.Is(root) to match wrapped stdlib error")
	}
	unrelated := stderrors.New("unrelated error")
	if err1.Is(unrelated) {
		t.Error("expected err1.Is(unrelated) to be false")
	}
	errNoCause := New(CodeInvalidConfig, "no cause", nil)
	if errNoCause.Is(root) {
		t.Error("expected errNoCause.Is(root) to be false")
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
		{CodeUserAlreadyExists, http.StatusConflict},
		{CodeUserNotFound, http.StatusNotFound},
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

	t.Run("internal error with explicit sensitive message is masked", func(t *testing.T) {
		rec := httptest.NewRecorder()
		err := New(CodeInternalError, "sensitive database credentials leaked", stderrors.New("pq: password authentication failed"))

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

	t.Run("database error 500 status is masked", func(t *testing.T) {
		rec := httptest.NewRecorder()
		err := New(CodeDatabaseError, "SELECT * FROM users WHERE password = secret", nil)

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
		ErrAllowedOriginInvalid,
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

func TestWriteJSON_EmptyMessageNon500(t *testing.T) {
	tests := []struct {
		code           Code
		expectedStatus int
		expectedMsg    string
	}{
		{CodeValidationError, http.StatusBadRequest, "bad request"},
		{CodeInvalidEmail, http.StatusBadRequest, "bad request"},
		{CodeInvalidCredentials, http.StatusUnauthorized, "unauthorized"},
		{CodeEmailNotVerified, http.StatusForbidden, "forbidden"},
		{CodeNotFound, http.StatusNotFound, "not found"},
		{CodeUserNotFound, http.StatusNotFound, "not found"},
		{CodeMethodNotAllowed, http.StatusMethodNotAllowed, "method not allowed"},
		{CodeUserAlreadyExists, http.StatusConflict, "conflict"},
		{CodeDatabaseUnavailable, http.StatusServiceUnavailable, "service unavailable"},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			rec := httptest.NewRecorder()
			err := New(tt.code, "", nil)

			WriteJSON(rec, err)

			if rec.Code != tt.expectedStatus {
				t.Fatalf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("expected Content-Type application/json, got %q", got)
			}

			var resp Response
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if resp.Code != tt.code {
				t.Errorf("got code %q, want %q", resp.Code, tt.code)
			}
			if resp.Message != tt.expectedMsg {
				t.Errorf("got message %q, want %q", resp.Message, tt.expectedMsg)
			}
		})
	}
}

type nonComparableError struct {
	tags []string
}

func (e nonComparableError) Error() string {
	return strings.Join(e.tags, ",")
}

func (e nonComparableError) Is(target error) bool {
	t, ok := target.(nonComparableError)
	if !ok {
		return false
	}
	return slices.Equal(e.tags, t.tags)
}

func TestError_Is_EdgeCases(t *testing.T) {
	t.Run("empty target identity comparison", func(t *testing.T) {
		empty1 := &Error{}
		empty2 := &Error{}
		errWithCode := New(CodeNotFound, "", nil)
		errWithMsg := New("", "some message", nil)
		errWithCause := New("", "", stderrors.New("cause"))

		if !Is(empty1, empty1) {
			t.Error("expected empty error to match itself by identity")
		}
		if Is(empty1, empty2) {
			t.Error("expected distinct empty errors not to match")
		}
		if Is(errWithCode, empty1) {
			t.Error("expected error with code not to match empty error")
		}
		if Is(errWithMsg, empty1) {
			t.Error("expected error with message not to match empty error")
		}
		if Is(errWithCause, empty1) {
			t.Error("expected error with cause not to match empty error")
		}
	})

	t.Run("code and message mismatch combinations", func(t *testing.T) {
		root1 := stderrors.New("cause 1")
		root2 := stderrors.New("cause 2")

		errA := New(CodeNotFound, "msg", root1)
		errB := New(CodeNotFound, "msg", root2)
		if errA.Is(errB) {
			t.Error("expected errA not to match errB with different cause")
		}

		errC := New(CodeNotFound, "msg1", nil)
		errD := New(CodeNotFound, "msg2", nil)
		if errC.Is(errD) {
			t.Error("expected errC not to match errD with different message")
		}

		errE := New(CodeNotFound, "msg", nil)
		errF := New(CodeValidationError, "msg", nil)
		if errE.Is(errF) {
			t.Error("expected errE not to match errF with different code")
		}
	})

	t.Run("nil receiver and nil target edge cases", func(t *testing.T) {
		var nilErr *Error
		nonNilErr := New(CodeNotFound, "msg", nil)

		if nilErr.Is(nonNilErr) {
			t.Error("expected nil *Error not to match non-nil *Error")
		}
		if !nilErr.Is(nil) {
			t.Error("expected nil *Error to match nil error")
		}
		if nonNilErr.Is(nil) {
			t.Error("expected non-nil *Error not to match nil error")
		}
	})

	t.Run("non-comparable error target", func(t *testing.T) {
		target := nonComparableError{tags: []string{"a", "b"}}
		err := New(CodeInternalError, "wrapper", nil)
		if err.Is(target) {
			t.Error("expected err without cause not to match nonComparableError")
		}

		errWithSameCause := New(CodeInternalError, "wrapper", target)
		if !errWithSameCause.Is(target) {
			t.Error("expected err with nonComparableError cause to match via unwrap")
		}

		differentTarget := nonComparableError{tags: []string{"different"}}
		if errWithSameCause.Is(differentTarget) {
			t.Error("expected err with different nonComparableError tags not to match")
		}
	})

	t.Run("non-comparable target with map field without custom Is", func(t *testing.T) {
		// Non-comparable error with map field and no Is method
		mErr := struct {
			error
			meta map[string]string
		}{
			error: stderrors.New("map error"),
			meta:  map[string]string{"key": "value"},
		}

		err := New(CodeInternalError, "wrapper", stderrors.New("other cause"))
		// Must not panic under errors.Is
		if Is(err, mErr) {
			t.Error("expected non-matching non-comparable error not to match")
		}
	})

	t.Run("errors.Join traversal in cause", func(t *testing.T) {
		cause1 := New(CodeNotFound, "user not found", nil)
		cause2 := stderrors.New("low-level network error")
		joinedCause := stderrors.Join(cause1, cause2)

		wrapper := Wrap(joinedCause, CodeInternalError, "wrapper failure")

		// Assert wrapper matches cause1 via errors.Is
		if !Is(wrapper, cause1) {
			t.Error("expected wrapper to match cause1 within joined cause")
		}
		// Assert wrapper matches cause2 via errors.Is
		if !Is(wrapper, cause2) {
			t.Error("expected wrapper to match cause2 within joined cause")
		}
		// Assert wrapper does not match an unrelated error
		unrelated := stderrors.New("unrelated error")
		if Is(wrapper, unrelated) {
			t.Error("expected wrapper not to match unrelated error")
		}

		// Assert errors.As finds *Error inside the joined tree
		var targetAppErr *Error
		if !As(wrapper, &targetAppErr) {
			t.Fatal("expected As to extract *Error from wrapper")
		}
		// Wrap preserves the inner *Error's CodeNotFound
		if targetAppErr.Code() != CodeNotFound {
			t.Errorf("expected preserved code %s, got %s", CodeNotFound, targetAppErr.Code())
		}
	})

	t.Run("errors.Join at root containing multiple *Error types", func(t *testing.T) {
		errA := New(CodeNotFound, "entity A not found", nil)
		errB := New(CodeInvalidCredentials, "invalid creds", nil)
		joinedRoot := stderrors.Join(errA, errB)

		if !Is(joinedRoot, errA) {
			t.Error("expected joinedRoot to match errA")
		}
		if !Is(joinedRoot, errB) {
			t.Error("expected joinedRoot to match errB")
		}

		// As extracts the first matching *Error
		var extracted *Error
		if !As(joinedRoot, &extracted) {
			t.Fatal("expected As to extract *Error from joinedRoot")
		}
		if extracted.Code() != CodeNotFound {
			t.Errorf("expected first *Error to have code %s, got %s", CodeNotFound, extracted.Code())
		}

		// WriteJSON with joined root containing *Error
		rec := httptest.NewRecorder()
		WriteJSON(rec, joinedRoot)
		if rec.Code != http.StatusNotFound {
			t.Errorf("expected WriteJSON to extract 404 from joined root, got %d", rec.Code)
		}
	})
}
