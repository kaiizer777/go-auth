package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

type mockSessionService struct {
	getSessionFn func(ctx context.Context, rawID string) (*session.Session, error)
	createSessFn func(ctx context.Context, userID uuid.UUID, credentialVersion int, sessionType db.SessionType, ip, userAgent string) (*session.Session, string, error)
}

func (m *mockSessionService) CreateSession(ctx context.Context, userID uuid.UUID, credentialVersion int, sessionType db.SessionType, ip, userAgent string) (*session.Session, string, error) {
	if m.createSessFn != nil {
		return m.createSessFn(ctx, userID, credentialVersion, sessionType, ip, userAgent)
	}
	return nil, "", nil
}

func (m *mockSessionService) GetSession(ctx context.Context, rawID string) (*session.Session, error) {
	if m.getSessionFn != nil {
		return m.getSessionFn(ctx, rawID)
	}
	return nil, nil
}

func (m *mockSessionService) InvalidateSession(ctx context.Context, rawID string) error {
	return nil
}

func (m *mockSessionService) InvalidateAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	return nil
}

func (m *mockSessionService) RotateSession(ctx context.Context, oldRawID string, ip, userAgent string) (*session.Session, string, error) {
	return nil, "", nil
}

func (m *mockSessionService) ListSessions(ctx context.Context, userID uuid.UUID) ([]*session.Session, error) {
	return nil, nil
}

func (m *mockSessionService) PurgeExpired(ctx context.Context) (int64, error) {
	return 0, nil
}

const validTestToken = "0123456789abcdef0123456789abcdef"

func TestRequireAuth_CookieSession_Valid(t *testing.T) {
	cfg := config.DefaultConfig()
	expectedUserID := uuid.New()
	expectedSessionID := uuid.New()
	expectedSession := &session.Session{
		ID:                expectedSessionID,
		UserID:            expectedUserID,
		IDHash:            "dummyhash",
		Type:              db.SessionTypeCookie,
		LastActiveAt:      time.Now().UTC(),
		AbsoluteExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	mockSvc := &mockSessionService{
		getSessionFn: func(ctx context.Context, rawID string) (*session.Session, error) {
			if rawID != validTestToken {
				t.Fatalf("expected rawID %q, got %q", validTestToken, rawID)
			}
			return expectedSession, nil
		},
	}

	var handlerCalled bool
	var capturedUserID uuid.UUID
	var capturedSessionID uuid.UUID
	var capturedSession *session.Session
	var capturedRawID string

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		capturedUserID = userIDFromContext(r.Context())
		capturedSessionID = sessionIDFromContext(r.Context())
		capturedSession = sessionFromContext(r.Context())
		capturedRawID = rawIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	mw := RequireAuth(mockSvc, &cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: validTestToken,
	})
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Fatalf("expected next handler to be called")
	}
	if capturedUserID != expectedUserID {
		t.Errorf("expected UserID %v, got %v", expectedUserID, capturedUserID)
	}
	if capturedSessionID != expectedSessionID {
		t.Errorf("expected SessionID %v, got %v", expectedSessionID, capturedSessionID)
	}
	if capturedSession != expectedSession {
		t.Errorf("expected Session %v, got %v", expectedSession, capturedSession)
	}
	if capturedRawID != validTestToken {
		t.Errorf("expected rawID %q, got %q", validTestToken, capturedRawID)
	}
}

func TestRequireAuth_BearerSession_Valid(t *testing.T) {
	cfg := config.DefaultConfig()
	expectedUserID := uuid.New()
	expectedSessionID := uuid.New()
	expectedSession := &session.Session{
		ID:                expectedSessionID,
		UserID:            expectedUserID,
		IDHash:            "dummyhash",
		Type:              db.SessionTypeBearer,
		LastActiveAt:      time.Now().UTC(),
		AbsoluteExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	mockSvc := &mockSessionService{
		getSessionFn: func(ctx context.Context, rawID string) (*session.Session, error) {
			if rawID != validTestToken {
				t.Fatalf("expected rawID %q, got %q", validTestToken, rawID)
			}
			return expectedSession, nil
		},
	}

	var handlerCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		uID, ok := UserIDFromContext(r.Context())
		if !ok || uID != expectedUserID {
			t.Errorf("UserIDFromContext returned (%v, %v), want (%v, true)", uID, ok, expectedUserID)
		}
		w.WriteHeader(http.StatusOK)
	})

	mw := RequireAuth(mockSvc, &cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+validTestToken)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Fatalf("expected next handler to be called")
	}
}

func TestRequireAuth_NoCookieNoBearer(t *testing.T) {
	cfg := config.DefaultConfig()
	mockSvc := &mockSessionService{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next handler should not be called")
	})

	mw := RequireAuth(mockSvc, &cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}

	var errResp apperrors.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error body: %v", err)
	}
	if errResp.Code != apperrors.CodeSessionInvalid {
		t.Fatalf("expected Code=%s, got %s", apperrors.CodeSessionInvalid, errResp.Code)
	}
}

func TestRequireAuth_ExpiredSession(t *testing.T) {
	cfg := config.DefaultConfig()
	mockSvc := &mockSessionService{
		getSessionFn: func(ctx context.Context, rawID string) (*session.Session, error) {
			return nil, apperrors.ErrSessionExpired
		},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next handler should not be called")
	})

	mw := RequireAuth(mockSvc, &cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: validTestToken,
	})
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}

	var errResp apperrors.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error body: %v", err)
	}
	if errResp.Code != apperrors.CodeSessionInvalid {
		t.Fatalf("expected Code=%s, got %s", apperrors.CodeSessionInvalid, errResp.Code)
	}
}

func TestRequireAuth_ContextKeys(t *testing.T) {
	expectedUserID := uuid.New()
	expectedSessionID := uuid.New()
	expectedSession := &session.Session{
		ID:     expectedSessionID,
		UserID: expectedUserID,
	}
	rawID := validTestToken

	ctx := context.Background()
	ctx = context.WithValue(ctx, contextKeyUserID, expectedUserID)
	ctx = context.WithValue(ctx, contextKeySessionID, expectedSessionID)
	ctx = context.WithValue(ctx, contextKeySession, expectedSession)
	ctx = context.WithValue(ctx, contextKeyRawID, rawID)

	// Test unexported getters
	if got := userIDFromContext(ctx); got != expectedUserID {
		t.Errorf("userIDFromContext = %v, want %v", got, expectedUserID)
	}
	if got := sessionIDFromContext(ctx); got != expectedSessionID {
		t.Errorf("sessionIDFromContext = %v, want %v", got, expectedSessionID)
	}
	if got := sessionFromContext(ctx); got != expectedSession {
		t.Errorf("sessionFromContext = %v, want %v", got, expectedSession)
	}
	if got := rawIDFromContext(ctx); got != rawID {
		t.Errorf("rawIDFromContext = %q, want %q", got, rawID)
	}

	// Test exported getters
	uID, ok := UserIDFromContext(ctx)
	if !ok || uID != expectedUserID {
		t.Errorf("UserIDFromContext = (%v, %v), want (%v, true)", uID, ok, expectedUserID)
	}
	sID, ok := SessionIDFromContext(ctx)
	if !ok || sID != expectedSessionID {
		t.Errorf("SessionIDFromContext = (%v, %v), want (%v, true)", sID, ok, expectedSessionID)
	}
	if sess := SessionFromContext(ctx); sess != expectedSession {
		t.Errorf("SessionFromContext = %v, want %v", sess, expectedSession)
	}
	rID, ok := RawSessionIDFromContext(ctx)
	if !ok || rID != rawID {
		t.Errorf("RawSessionIDFromContext = (%q, %v), want (%q, true)", rID, ok, rawID)
	}
	rID2, ok := RawIDFromContext(ctx)
	if !ok || rID2 != rawID {
		t.Errorf("RawIDFromContext = (%q, %v), want (%q, true)", rID2, ok, rawID)
	}

	// Test empty context
	emptyCtx := context.Background()
	if _, ok := UserIDFromContext(emptyCtx); ok {
		t.Errorf("UserIDFromContext on empty context returned ok=true")
	}
	if _, ok := SessionIDFromContext(emptyCtx); ok {
		t.Errorf("SessionIDFromContext on empty context returned ok=true")
	}
	if sess := SessionFromContext(emptyCtx); sess != nil {
		t.Errorf("SessionFromContext on empty context returned non-nil")
	}
	if _, ok := RawSessionIDFromContext(emptyCtx); ok {
		t.Errorf("RawSessionIDFromContext on empty context returned ok=true")
	}
}

func TestRequireAuth_NilSession_Returns401(t *testing.T) {
	cfg := config.DefaultConfig()
	mockSvc := &mockSessionService{
		getSessionFn: func(ctx context.Context, rawID string) (*session.Session, error) {
			return nil, nil
		},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next handler should not be called when session is nil")
	})

	mw := RequireAuth(mockSvc, &cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: validTestToken,
	})
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestRequireAuth_AuthorizationHeaderSpoof_DoesNotFallbackToCookie(t *testing.T) {
	cfg := config.DefaultConfig()
	mockSvc := &mockSessionService{
		getSessionFn: func(ctx context.Context, rawID string) (*session.Session, error) {
			t.Fatalf("session service should not be called with spoofed bearer header")
			return nil, nil
		},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next handler must not be called when Authorization header is invalid")
	})

	mw := RequireAuth(mockSvc, &cfg)(next)

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: validTestToken,
	})
	req.Header.Set("Authorization", "Bearer invalid-dummy-token")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized, got %d", rec.Code)
	}
}

func TestRequireAuth_TransportBinding_CookiePresentedViaBearer(t *testing.T) {
	cfg := config.DefaultConfig()
	cookieSession := &session.Session{
		ID:                uuid.New(),
		UserID:            uuid.New(),
		IDHash:            "cookiehash",
		Type:              db.SessionTypeCookie,
		LastActiveAt:      time.Now().UTC(),
		AbsoluteExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	mockSvc := &mockSessionService{
		getSessionFn: func(ctx context.Context, rawID string) (*session.Session, error) {
			return cookieSession, nil
		},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next handler must not be called on transport mismatch")
	})

	mw := RequireAuth(mockSvc, &cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+validTestToken)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
	var resp apperrors.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Code != apperrors.CodeSessionInvalid {
		t.Errorf("expected code %s, got %s", apperrors.CodeSessionInvalid, resp.Code)
	}
}

func TestRequireAuth_TransportBinding_BearerPresentedViaCookie(t *testing.T) {
	cfg := config.DefaultConfig()
	bearerSession := &session.Session{
		ID:                uuid.New(),
		UserID:            uuid.New(),
		IDHash:            "bearerhash",
		Type:              db.SessionTypeBearer,
		LastActiveAt:      time.Now().UTC(),
		AbsoluteExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	mockSvc := &mockSessionService{
		getSessionFn: func(ctx context.Context, rawID string) (*session.Session, error) {
			return bearerSession, nil
		},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next handler must not be called on transport mismatch")
	})

	mw := RequireAuth(mockSvc, &cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: validTestToken,
	})
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
	var resp apperrors.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Code != apperrors.CodeSessionInvalid {
		t.Errorf("expected code %s, got %s", apperrors.CodeSessionInvalid, resp.Code)
	}
}

func TestRequireAuth_NilConfig_DefaultsSafely(t *testing.T) {
	mockSvc := &mockSessionService{}
	mw := RequireAuth(mockSvc, nil)
	if mw == nil {
		t.Fatal("expected non-nil middleware")
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireAuth_NilSessionService_ReturnsInternalError(t *testing.T) {
	cfg := config.DefaultConfig()
	mw := RequireAuth(nil, &cfg)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: validTestToken,
	})
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on nil session service, got %d", rec.Code)
	}
	var resp apperrors.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Code != apperrors.CodeInternalError {
		t.Errorf("expected code %s, got %s", apperrors.CodeInternalError, resp.Code)
	}
}

func TestSecurityHeaders_Middleware(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SessionCookieSecure = true

	mw := SecurityHeaders(&cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy = %q, want strict-origin-when-cross-origin", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'none'; frame-ancestors 'none'" {
		t.Errorf("Content-Security-Policy = %q, want default-src 'none'; frame-ancestors 'none'", got)
	}
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains; preload" {
		t.Errorf("Strict-Transport-Security = %q, want HSTS header when secure", got)
	}
}

func TestRecovery_Middleware(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	secretPanicValue := "secret-panic-token-12345"
	mw := Recovery(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(secretPanicValue)
	}))

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}

	var resp apperrors.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode error body: %v", err)
	}
	if resp.Code != apperrors.CodeInternalError {
		t.Errorf("expected INTERNAL_ERROR, got %s", resp.Code)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "panic recovered in http handler") {
		t.Errorf("expected recovery message in log, got: %s", logOutput)
	}
	if strings.Contains(logOutput, secretPanicValue) {
		t.Fatalf("secret panic value leaked into log: %s", logOutput)
	}
}

func TestRecovery_RePanicsErrAbortHandler(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	mw := Recovery(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	}))

	req := httptest.NewRequest(http.MethodGet, "/abort", nil)
	rec := httptest.NewRecorder()

	var panickedVal any
	func() {
		defer func() {
			panickedVal = recover()
		}()
		mw.ServeHTTP(rec, req)
	}()

	if panickedVal != http.ErrAbortHandler {
		t.Fatalf("expected re-panic with http.ErrAbortHandler, got: %v", panickedVal)
	}

	if strings.Contains(logBuf.String(), "panic recovered in http handler") {
		t.Errorf("expected no recovery log for http.ErrAbortHandler, got: %s", logBuf.String())
	}
}

func TestRecover_DefaultLogger(t *testing.T) {
	mw := Recover()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("testing default recover")
	}))

	req := httptest.NewRequest(http.MethodGet, "/recover-test", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 from default Recover(), got %d", rec.Code)
	}
}

func TestRecovery_RePanicsWhenResponseCommitted_WriteHeader(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	mw := Recovery(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		panic("panic after WriteHeader")
	}))

	req := httptest.NewRequest(http.MethodGet, "/committed-header", nil)
	rec := httptest.NewRecorder()

	var panickedVal any
	func() {
		defer func() {
			panickedVal = recover()
		}()
		mw.ServeHTTP(rec, req)
	}()

	if panickedVal != http.ErrAbortHandler {
		t.Fatalf("expected re-panic with http.ErrAbortHandler, got: %v", panickedVal)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected original status code 200, got %d", rec.Code)
	}

	if !strings.Contains(logBuf.String(), "panic recovered in http handler") {
		t.Errorf("expected recovery message in log, got: %s", logBuf.String())
	}
}

func TestRecovery_RePanicsWhenResponseCommitted_Write(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	mw := Recovery(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("early payload"))
		panic("panic after Write")
	}))

	req := httptest.NewRequest(http.MethodGet, "/committed-body", nil)
	rec := httptest.NewRecorder()

	var panickedVal any
	func() {
		defer func() {
			panickedVal = recover()
		}()
		mw.ServeHTTP(rec, req)
	}()

	if panickedVal != http.ErrAbortHandler {
		t.Fatalf("expected re-panic with http.ErrAbortHandler, got: %v", panickedVal)
	}

	if rec.Body.String() != "early payload" {
		t.Fatalf("expected body %q, got %q", "early payload", rec.Body.String())
	}

	if !strings.Contains(logBuf.String(), "panic recovered in http handler") {
		t.Errorf("expected recovery message in log, got: %s", logBuf.String())
	}
}

func TestRecovery_RePanicsWhenResponseCommitted_Interceptor(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	mw := Recovery(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		panic("panic after interceptor write")
	}))

	req := httptest.NewRequest(http.MethodPost, "/interceptor", nil)
	rec := httptest.NewRecorder()
	interceptor := &responseInterceptor{ResponseWriter: rec}

	var panickedVal any
	func() {
		defer func() {
			panickedVal = recover()
		}()
		mw.ServeHTTP(interceptor, req)
	}()

	if panickedVal != http.ErrAbortHandler {
		t.Fatalf("expected re-panic with http.ErrAbortHandler, got: %v", panickedVal)
	}

	if !interceptor.headerWritten {
		t.Fatal("expected interceptor.headerWritten to be true")
	}

	if !strings.Contains(logBuf.String(), "panic recovered in http handler") {
		t.Errorf("expected recovery message in log, got: %s", logBuf.String())
	}
}

func TestRecovery_Flush_NonFlusherDoesNotCommit(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	mw := Recovery(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic("panic after flush attempt on non-flusher")
	}))

	req := httptest.NewRequest(http.MethodGet, "/flush-nonflusher", nil)
	rec := &nonFlusherRecorder{}

	var panickedVal any
	func() {
		defer func() {
			panickedVal = recover()
		}()
		mw.ServeHTTP(rec, req)
	}()

	if panickedVal != nil {
		t.Fatalf("expected panic to be recovered without re-panic, got: %v", panickedVal)
	}

	if rec.code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error, got: %d", rec.code)
	}

	var resp apperrors.Response
	if err := json.Unmarshal(rec.body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode json error response: %v", err)
	}
	if resp.Code != apperrors.CodeInternalError {
		t.Fatalf("expected CodeInternalError, got: %s", resp.Code)
	}
}

func TestRecovery_Flush_FlusherCommitsAndRePanics(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	mw := Recovery(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic("panic after flush on flusher")
	}))

	req := httptest.NewRequest(http.MethodGet, "/flush-flusher", nil)
	rec := &mockFlusherRecorder{ResponseRecorder: httptest.NewRecorder()}

	var panickedVal any
	func() {
		defer func() {
			panickedVal = recover()
		}()
		mw.ServeHTTP(rec, req)
	}()

	if panickedVal != http.ErrAbortHandler {
		t.Fatalf("expected re-panic with http.ErrAbortHandler, got: %v", panickedVal)
	}
	if !rec.flushed {
		t.Fatal("expected flusher to have flushed")
	}
}

func TestRequireAuth_PreservesTypedCookieError(t *testing.T) {
	cfg := config.DefaultConfig()
	mockSvc := &mockSessionService{}

	mw := RequireAuth(mockSvc, &cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	// Cookie is present but invalid hex
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: "invalid-token-not-hex",
	})
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	var resp apperrors.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if resp.Code != apperrors.CodeSessionInvalid {
		t.Fatalf("expected CodeSessionInvalid, got %s", resp.Code)
	}
}

func TestRequireAuth_ContextSecretRedacted(t *testing.T) {
	cfg := config.DefaultConfig()
	secretToken := validTestToken
	expectedUserID := uuid.New()
	expectedSession := &session.Session{
		ID:     uuid.New(),
		UserID: expectedUserID,
		Type:   db.SessionTypeCookie,
	}

	mockSvc := &mockSessionService{
		getSessionFn: func(ctx context.Context, rawID string) (*session.Session, error) {
			return expectedSession, nil
		},
	}

	var dumpedContext string
	mw := RequireAuth(mockSvc, &cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dumpedContext = fmt.Sprintf("%+v", r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: secretToken,
	})
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if strings.Contains(dumpedContext, secretToken) {
		t.Fatalf("raw secret token leaked in context dump: %s", dumpedContext)
	}
	if !strings.Contains(dumpedContext, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in context dump, got: %s", dumpedContext)
	}
}

func TestRequireAuth_DatabaseError(t *testing.T) {
	cfg := config.DefaultConfig()
	mockSvc := &mockSessionService{
		getSessionFn: func(ctx context.Context, rawID string) (*session.Session, error) {
			return nil, apperrors.New(apperrors.CodeInternalError, "database connection lost", nil)
		},
	}

	mw := RequireAuth(mockSvc, &cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: validTestToken,
	})
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", rec.Code)
	}
}
