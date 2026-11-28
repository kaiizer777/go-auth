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
		{CodeSessionNotFound, http.StatusUnauthorized},
		{CodeSessionExpired, http.StatusUnauthorized},
		{CodeSessionInvalid, http.StatusUnauthorized},
		{CodeCSRFTokenMissing, http.StatusForbidden},
		{CodeCSRFTokenInvalid, http.StatusForbidden},
		{CodeRateLimitExceeded, http.StatusTooManyRequests},
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
		ErrInvalidConfig,
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
		expectedCode   Code
	}{
		{CodeValidationError, http.StatusBadRequest, "bad request", ""},
		{CodeInvalidEmail, http.StatusBadRequest, "bad request", ""},
		{CodeInvalidCredentials, http.StatusUnauthorized, "unauthorized", ""},
		{CodeEmailNotVerified, http.StatusForbidden, "forbidden", ""},
		{CodeNotFound, http.StatusNotFound, "not found", ""},
		{CodeUserNotFound, http.StatusNotFound, "not found", ""},
		{CodeMethodNotAllowed, http.StatusMethodNotAllowed, "method not allowed", ""},
		{CodeUserAlreadyExists, http.StatusConflict, "conflict", ""},
		{CodeDatabaseUnavailable, http.StatusServiceUnavailable, "service unavailable", ""},
		{CodeSessionNotFound, http.StatusUnauthorized, "Session is invalid or has expired", CodeSessionInvalid},
		{CodeSessionExpired, http.StatusUnauthorized, "Session is invalid or has expired", CodeSessionInvalid},
		{CodeSessionInvalid, http.StatusUnauthorized, "Session is invalid or has expired", ""},
		{CodeCSRFTokenMissing, http.StatusForbidden, "CSRF token is missing", ""},
		{CodeCSRFTokenInvalid, http.StatusForbidden, "CSRF token is invalid", ""},
		{CodeRateLimitExceeded, http.StatusTooManyRequests, "Too many requests, try again later", ""},
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
			wantCode := tt.code
			if tt.expectedCode != "" {
				wantCode = tt.expectedCode
			}
			if resp.Code != wantCode {
				t.Errorf("got code %q, want %q", resp.Code, wantCode)
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

func TestErrorCode_SessionNotFound_HTTPStatus(t *testing.T) {
	if got := CodeSessionNotFound.HTTPStatus(); got != http.StatusUnauthorized {
		t.Fatalf("CodeSessionNotFound.HTTPStatus() = %d; want %d", got, http.StatusUnauthorized)
	}
}

func TestErrorCode_SessionExpired_HTTPStatus(t *testing.T) {
	if got := CodeSessionExpired.HTTPStatus(); got != http.StatusUnauthorized {
		t.Fatalf("CodeSessionExpired.HTTPStatus() = %d; want %d", got, http.StatusUnauthorized)
	}
}

func TestErrorCode_SessionInvalid_HTTPStatus(t *testing.T) {
	if got := CodeSessionInvalid.HTTPStatus(); got != http.StatusUnauthorized {
		t.Fatalf("CodeSessionInvalid.HTTPStatus() = %d; want %d", got, http.StatusUnauthorized)
	}
}

func TestErrorCode_CSRFMissing_HTTPStatus(t *testing.T) {
	if got := CodeCSRFTokenMissing.HTTPStatus(); got != http.StatusForbidden {
		t.Fatalf("CodeCSRFTokenMissing.HTTPStatus() = %d; want %d", got, http.StatusForbidden)
	}
}

func TestErrorCode_CSRFInvalid_HTTPStatus(t *testing.T) {
	if got := CodeCSRFTokenInvalid.HTTPStatus(); got != http.StatusForbidden {
		t.Fatalf("CodeCSRFTokenInvalid.HTTPStatus() = %d; want %d", got, http.StatusForbidden)
	}
}

func TestErrorCode_RateLimitExceeded_HTTPStatus(t *testing.T) {
	if got := CodeRateLimitExceeded.HTTPStatus(); got != http.StatusTooManyRequests {
		t.Fatalf("CodeRateLimitExceeded.HTTPStatus() = %d; want %d", got, http.StatusTooManyRequests)
	}
}

func TestErrorCode_WireJSON_SessionExpired(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTP(rec, ErrSessionExpired)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	var resp Response
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Code != CodeSessionInvalid {
		t.Errorf("resp.Code = %q; want %q", resp.Code, CodeSessionInvalid)
	}
	if resp.Message != "Session is invalid or has expired" {
		t.Errorf("resp.Message = %q; want %q", resp.Message, "Session is invalid or has expired")
	}
}

func TestErrorCode_WireJSON_SessionNotFound(t *testing.T) {
	recExpired := httptest.NewRecorder()
	WriteHTTP(recExpired, ErrSessionExpired)

	recNotFound := httptest.NewRecorder()
	WriteHTTP(recNotFound, ErrSessionNotFound)

	if recNotFound.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recNotFound.Code)
	}

	var respExpired, respNotFound Response
	if err := json.NewDecoder(recExpired.Body).Decode(&respExpired); err != nil {
		t.Fatalf("failed to decode expired response: %v", err)
	}
	if err := json.NewDecoder(recNotFound.Body).Decode(&respNotFound); err != nil {
		t.Fatalf("failed to decode not-found response: %v", err)
	}

	if respNotFound.Code != CodeSessionInvalid {
		t.Errorf("respNotFound.Code = %q; want %q", respNotFound.Code, CodeSessionInvalid)
	}
	if respNotFound.Code != respExpired.Code {
		t.Fatalf("anti-enumeration code failure: respNotFound.Code %q != respExpired.Code %q", respNotFound.Code, respExpired.Code)
	}
	// Anti-enumeration invariant: exact same message as SESSION_EXPIRED
	if respNotFound.Message != respExpired.Message {
		t.Fatalf("anti-enumeration failure: respNotFound.Message %q != respExpired.Message %q", respNotFound.Message, respExpired.Message)
	}
	if respNotFound.Message != "Session is invalid or has expired" {
		t.Errorf("respNotFound.Message = %q; want %q", respNotFound.Message, "Session is invalid or has expired")
	}
}

func TestWriteHTTP_Alias(t *testing.T) {
	rec1 := httptest.NewRecorder()
	WriteJSON(rec1, ErrCSRFTokenInvalid)

	rec2 := httptest.NewRecorder()
	WriteHTTP(rec2, ErrCSRFTokenInvalid)

	if rec1.Code != rec2.Code {
		t.Errorf("status mismatch: WriteJSON=%d vs WriteHTTP=%d", rec1.Code, rec2.Code)
	}
	if rec1.Body.String() != rec2.Body.String() {
		t.Errorf("body mismatch: WriteJSON=%s vs WriteHTTP=%s", rec1.Body.String(), rec2.Body.String())
	}
}

func TestSentinels_Phase4(t *testing.T) {
	tests := []struct {
		err         *Error
		wantCode    Code
		wantMessage string
	}{
		{ErrSessionNotFound, CodeSessionNotFound, "Session is invalid or has expired"},
		{ErrSessionExpired, CodeSessionExpired, "Session is invalid or has expired"},
		{ErrSessionInvalid, CodeSessionInvalid, "Session is invalid or has expired"},
		{ErrCSRFTokenMissing, CodeCSRFTokenMissing, "CSRF token is missing"},
		{ErrCSRFTokenInvalid, CodeCSRFTokenInvalid, "CSRF token is invalid"},
		{ErrRateLimitExceeded, CodeRateLimitExceeded, "Too many requests, try again later"},
	}

	for _, tt := range tests {
		t.Run(string(tt.wantCode), func(t *testing.T) {
			if tt.err.Code() != tt.wantCode {
				t.Errorf("Code() = %q; want %q", tt.err.Code(), tt.wantCode)
			}
			if tt.err.Message() != tt.wantMessage {
				t.Errorf("Message() = %q; want %q", tt.err.Message(), tt.wantMessage)
			}
		})
	}
}

func TestSentinels_Phase3(t *testing.T) {
	tests := []struct {
		err         *Error
		wantCode    Code
		wantMessage string
		wantStatus  int
	}{
		{ErrInvalidCredentials, CodeInvalidCredentials, "invalid email or password", http.StatusUnauthorized},
		{ErrUnauthenticated, CodeUnauthenticated, "authentication required", http.StatusUnauthorized},
		{ErrEmailNotVerified, CodeEmailNotVerified, "email address not verified", http.StatusForbidden},
		{ErrUserAlreadyExists, CodeUserAlreadyExists, "user already exists", http.StatusConflict},
		{ErrEmailAlreadyExists, CodeEmailAlreadyExists, "email already exists", http.StatusConflict},
		{ErrEmailClaimed, CodeEmailAlreadyExists, "email address is claimed by another account", http.StatusConflict},
		{ErrUserNotFound, CodeUserNotFound, "user not found", http.StatusNotFound},
		{ErrInvalidToken, CodeInvalidToken, "token is invalid or malformed", http.StatusBadRequest},
		{ErrTokenExpired, CodeTokenExpired, "token has expired", http.StatusBadRequest},
		{ErrTokenNotFound, CodeTokenNotFound, "token not found", http.StatusNotFound},
		{ErrPasswordTooShort, CodePasswordTooShort, "password is too short", http.StatusBadRequest},
		{ErrPasswordTooLong, CodePasswordTooLong, "password is too long", http.StatusBadRequest},
		{ErrPasswordTooCommon, CodePasswordTooCommon, "password is too common", http.StatusBadRequest},
		{ErrInvalidEmail, CodeInvalidEmail, "invalid email address", http.StatusBadRequest},
		{ErrValidationError, CodeValidationError, "validation failed", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(string(tt.wantCode), func(t *testing.T) {
			if tt.err.Code() != tt.wantCode {
				t.Errorf("Code() = %q; want %q", tt.err.Code(), tt.wantCode)
			}
			if tt.err.Message() != tt.wantMessage {
				t.Errorf("Message() = %q; want %q", tt.err.Message(), tt.wantMessage)
			}
			if got := tt.err.HTTPStatus(); got != tt.wantStatus {
				t.Errorf("HTTPStatus() = %d; want %d", got, tt.wantStatus)
			}
			if !Is(tt.err, tt.err) {
				t.Error("expected sentinel to match itself via Is")
			}
		})
	}
}

func TestSentinels_MFAAndOAuth(t *testing.T) {
	tests := []struct {
		err         *Error
		wantCode    Code
		wantMessage string
		wantStatus  int
	}{
		{ErrMFARequired, CodeMFARequired, "mfa verification required", http.StatusUnauthorized},
		{ErrMFAInvalidCode, CodeMFAInvalidCode, "invalid mfa code", http.StatusUnauthorized},
		{ErrOAuthStateInvalid, CodeOAuthStateInvalid, "invalid oauth state", http.StatusForbidden},
		{ErrOAuthCallbackFailed, CodeOAuthCallbackFailed, "oauth callback failed", http.StatusBadRequest},
		{ErrOAuthProviderError, CodeOAuthProviderError, "oauth provider error", http.StatusBadGateway},
		{ErrOAuthAccountAlreadyLinked, CodeOAuthAccountAlreadyLinked, "oauth account already linked", http.StatusConflict},
		{ErrOAuthAccountNotLinked, CodeOAuthAccountNotLinked, "oauth account not linked", http.StatusNotFound},
		{ErrOAuthCodeInvalid, CodeOAuthCodeInvalid, "oauth code is invalid", http.StatusBadRequest},
		{ErrOAuthEmailUnverified, CodeOAuthEmailUnverified, "oauth provider email is not verified", http.StatusBadRequest},
		{ErrOAuthAccountLinkConflict, CodeOAuthAccountLinkConflict, "cannot link oauth identity to unverified local account", http.StatusConflict},
		{ErrOAuthProviderNotFound, CodeOAuthProviderNotFound, "oauth provider not found", http.StatusNotFound},
		{ErrOAuthTokenKeyNotFound, CodeOAuthTokenDecryptionFailed, "oauth token encryption key not found", http.StatusInternalServerError},
		{ErrOAuthTokenCorrupt, CodeOAuthTokenDecryptionFailed, "oauth token failed authentication", http.StatusInternalServerError},
		{ErrOAuthReauthRequired, CodeOAuthReauthRequired, "oauth grant is no longer usable; re-authentication required", http.StatusUnauthorized},
		{ErrOAuthRefreshUnsupported, CodeOAuthRefreshUnsupported, "oauth provider does not support token refresh", http.StatusNotImplemented},
		{ErrOAuthGrantRejected, CodeOAuthReauthRequired, "oauth provider rejected the grant", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(string(tt.wantCode), func(t *testing.T) {
			if tt.err.Code() != tt.wantCode {
				t.Errorf("Code() = %q; want %q", tt.err.Code(), tt.wantCode)
			}
			if tt.err.Message() != tt.wantMessage {
				t.Errorf("Message() = %q; want %q", tt.err.Message(), tt.wantMessage)
			}
			if got := tt.err.HTTPStatus(); got != tt.wantStatus {
				t.Errorf("HTTPStatus() = %d; want %d", got, tt.wantStatus)
			}
		})
	}
}

func TestOAuthTokenSentinels_Distinguishable(t *testing.T) {
	if Is(ErrOAuthTokenKeyNotFound, ErrOAuthTokenCorrupt) || Is(ErrOAuthTokenCorrupt, ErrOAuthTokenKeyNotFound) {
		t.Fatal("key-not-found and corrupt must stay distinguishable in-process")
	}
	if ErrOAuthTokenKeyNotFound.Message() == ErrOAuthTokenCorrupt.Message() {
		t.Fatal("key-not-found and corrupt must carry distinct messages")
	}
	if ErrOAuthGrantRejected.Code() != CodeOAuthReauthRequired {
		t.Errorf("grant rejected code = %q; want %q", ErrOAuthGrantRejected.Code(), CodeOAuthReauthRequired)
	}

	for _, sentinel := range []*Error{
		ErrOAuthTokenKeyNotFound,
		ErrOAuthTokenCorrupt,
		ErrOAuthReauthRequired,
		ErrOAuthRefreshUnsupported,
		ErrOAuthGrantRejected,
	} {
		if !Is(sentinel, sentinel) {
			t.Errorf("%s does not match itself via Is", sentinel.Code())
		}
		wrapped := Wrap(sentinel, CodeInternalError, "wrapped")
		if !Is(wrapped, sentinel) {
			t.Errorf("%s does not match through one Wrap layer", sentinel.Code())
		}
	}
}

func TestEmailClaimSentinels_Distinguishable(t *testing.T) {
	// Both carry CodeEmailAlreadyExists on the wire; in-process the signup and link
	// paths must still be able to tell a lost claim from a duplicate signup.
	if Is(ErrEmailClaimed, ErrEmailAlreadyExists) || Is(ErrEmailAlreadyExists, ErrEmailClaimed) {
		t.Fatal("claim and duplicate sentinels must stay distinguishable in-process")
	}
	if ErrEmailClaimed.Message() == ErrEmailAlreadyExists.Message() {
		t.Fatal("claim and duplicate sentinels must carry distinct messages")
	}
}

func TestSentinels_Phase7TOTP(t *testing.T) {
	tests := []struct {
		err         *Error
		wantCode    Code
		wantMessage string
		wantStatus  int
	}{
		{ErrTOTPNotEnrolled, CodeTOTPNotEnrolled, "user has no active totp enrollment", http.StatusBadRequest},
		{ErrTOTPAlreadyEnabled, CodeTOTPAlreadyEnabled, "totp is already enabled for this user", http.StatusConflict},
		{ErrTOTPCodeInvalid, CodeTOTPCodeInvalid, "totp code is invalid", http.StatusBadRequest},
		{ErrTOTPCodeReplayed, CodeTOTPCodeReplayed, "totp code has already been used in this window", http.StatusBadRequest},
		{ErrBackupCodeInvalid, CodeTOTPBackupCodeInvalid, "backup code is invalid", http.StatusBadRequest},
		{ErrTOTPBackupCodeInvalid, CodeTOTPBackupCodeInvalid, "backup code is invalid", http.StatusBadRequest},
		{ErrTotpBackupCodeInvalid, CodeTOTPBackupCodeInvalid, "backup code is invalid", http.StatusBadRequest},
		{ErrTwoFactorTokenInvalid, CodeTwoFactorTokenInvalid, "two factor challenge token is invalid", http.StatusUnauthorized},
		{ErrTwoFactorTokenExpired, CodeTwoFactorTokenExpired, "two factor challenge token has expired", http.StatusUnauthorized},
		{ErrTwoFactorMaxAttemptsExceeded, CodeTwoFactorMaxAttemptsExceeded, "maximum verification attempts exceeded", http.StatusTooManyRequests},
		{ErrTOTPRateLimitExceeded, CodeTOTPRateLimitExceeded, "totp verification rate limit exceeded", http.StatusTooManyRequests},
	}

	for _, tt := range tests {
		t.Run(string(tt.wantCode), func(t *testing.T) {
			if tt.err.Code() != tt.wantCode {
				t.Errorf("Code() = %q; want %q", tt.err.Code(), tt.wantCode)
			}
			if tt.err.Message() != tt.wantMessage {
				t.Errorf("Message() = %q; want %q", tt.err.Message(), tt.wantMessage)
			}
			if got := tt.err.HTTPStatus(); got != tt.wantStatus {
				t.Errorf("HTTPStatus() = %d; want %d", got, tt.wantStatus)
			}
			if !Is(tt.err, tt.err) {
				t.Error("expected sentinel to match itself via Is")
			}
		})
	}
}

func TestWrapOverride(t *testing.T) {
	t.Run("nil cause returns nil", func(t *testing.T) {
		if got := WrapOverride(nil, CodeInvalidCredentials, "ignored"); got != nil {
			t.Fatalf("WrapOverride(nil) = %v; want nil", got)
		}
	})

	t.Run("overrides code of existing domain error", func(t *testing.T) {
		orig := New(CodeNotFound, "user missing", nil)
		wrapped := WrapOverride(orig, CodeInvalidCredentials, "bad credentials")

		var appErr *Error
		if !As(wrapped, &appErr) {
			t.Fatal("expected As to find *Error")
		}
		if appErr.Code() != CodeInvalidCredentials {
			t.Errorf("got code %q; want %q", appErr.Code(), CodeInvalidCredentials)
		}
		if appErr.Message() != "bad credentials" {
			t.Errorf("got message %q; want %q", appErr.Message(), "bad credentials")
		}
		if !Is(wrapped, orig) {
			t.Error("expected wrapped error to match original cause via Is")
		}
	})

	t.Run("wraps standard error with specified code", func(t *testing.T) {
		stdErr := stderrors.New("connection failed")
		wrapped := WrapOverride(stdErr, CodeOAuthProviderError, "provider unreachable")

		var appErr *Error
		if !As(wrapped, &appErr) {
			t.Fatal("expected As to find *Error")
		}
		if appErr.Code() != CodeOAuthProviderError {
			t.Errorf("got code %q; want %q", appErr.Code(), CodeOAuthProviderError)
		}
	})
}

func TestSentinelAliasesAndConfigSentinels(t *testing.T) {
	if !Is(ErrInvalidSession, ErrSessionInvalid) {
		t.Error("expected ErrInvalidSession to equal ErrSessionInvalid")
	}
	if ErrDatabaseURLInvalid.Code() != CodeInvalidConfig {
		t.Errorf("ErrDatabaseURLInvalid code = %q; want %q", ErrDatabaseURLInvalid.Code(), CodeInvalidConfig)
	}
	if ErrDatabaseURLInvalid.Message() != "database URL is invalid" {
		t.Errorf("ErrDatabaseURLInvalid message = %q; want %q", ErrDatabaseURLInvalid.Message(), "database URL is invalid")
	}
}
