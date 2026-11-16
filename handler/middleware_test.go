package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
