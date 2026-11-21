package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	apperrors "github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/ratelimit"
	"github.com/kaiizer777/go-auth/totp"
)

type mockTotpService struct {
	totp.Service
	confirmFn func(ctx context.Context, userID, code string) ([]string, error)
	disableFn func(ctx context.Context, userID, password, code string) error
	enrollFn  func(ctx context.Context, userID string) (*totp.EnrollmentResponse, error)
}

func (m *mockTotpService) ConfirmEnrollment(ctx context.Context, userID, code string) ([]string, error) {
	if m.confirmFn != nil {
		return m.confirmFn(ctx, userID, code)
	}
	return []string{"CODE1", "CODE2"}, nil
}

func (m *mockTotpService) DisableTOTP(ctx context.Context, userID, password, code string) error {
	if m.disableFn != nil {
		return m.disableFn(ctx, userID, password, code)
	}
	return nil
}

func (m *mockTotpService) Enroll(ctx context.Context, userID string) (*totp.EnrollmentResponse, error) {
	if m.enrollFn != nil {
		return m.enrollFn(ctx, userID)
	}
	return &totp.EnrollmentResponse{Secret: "JBSWY3DPEHPK3PXP"}, nil
}

func TestHandleTotpConfirm_RateLimiting(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	limiter := ratelimit.NewLimiter(time.Minute, 2)
	mockSvc := &mockTotpService{
		confirmFn: func(ctx context.Context, uID, code string) ([]string, error) {
			if code == "123456" {
				return []string{"BACKUP1"}, nil
			}
			return nil, apperrors.ErrTOTPCodeInvalid
		},
	}

	h := &Handler{
		totpSvc:     mockSvc,
		totpLimiter: limiter,
	}

	callConfirm := func(ip, code string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"code": code})
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/confirm", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if ip != "" {
			req.RemoteAddr = ip + ":12345"
		}
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		h.HandleTotpConfirm(rec, req)
		return rec
	}

	// Attempt 1: invalid code -> 400 Bad Request
	rec1 := callConfirm("192.168.1.1", "000000")
	if rec1.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 on attempt 1, got %d", rec1.Code)
	}

	// Attempt 2: invalid code -> 400 Bad Request
	rec2 := callConfirm("192.168.1.1", "000001")
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 on attempt 2, got %d", rec2.Code)
	}

	// Attempt 3: Rate limit exceeded -> 429 Too Many Requests
	rec3 := callConfirm("192.168.1.1", "000002")
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status 429 on attempt 3, got %d", rec3.Code)
	}
}

func TestHandleTotpConfirm_RateLimitResetOnSuccess(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	limiter := ratelimit.NewLimiter(time.Minute, 2)
	mockSvc := &mockTotpService{
		confirmFn: func(ctx context.Context, uID, code string) ([]string, error) {
			if code == "654321" {
				return []string{"BACKUP1"}, nil
			}
			return nil, apperrors.ErrTOTPCodeInvalid
		},
	}

	h := &Handler{
		totpSvc:     mockSvc,
		totpLimiter: limiter,
	}

	callConfirm := func(ip, code string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"code": code})
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/confirm", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":12345"
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		h.HandleTotpConfirm(rec, req)
		return rec
	}

	// 1 failure
	rec1 := callConfirm("192.168.1.2", "000000")
	if rec1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on failure, got %d", rec1.Code)
	}

	// Successful confirm resets rate limits
	rec2 := callConfirm("192.168.1.2", "654321")
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 on success, got %d", rec2.Code)
	}

	// Following failure can succeed again without hitting 429 immediately because limits were reset
	rec3 := callConfirm("192.168.1.2", "000000")
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 after reset, got %d", rec3.Code)
	}
}

func TestHandleTotpDisable_RateLimiting_IPAndUser(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	limiter := ratelimit.NewLimiter(time.Minute, 2)
	mockSvc := &mockTotpService{
		disableFn: func(ctx context.Context, uID, password, code string) error {
			return apperrors.ErrInvalidCredentials
		},
	}

	h := &Handler{
		totpSvc:     mockSvc,
		totpLimiter: limiter,
	}

	callDisable := func(ip string, uID uuid.UUID, password string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"password": password})
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/disable", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if ip != "" {
			req.RemoteAddr = ip + ":12345"
		}
		ctx := context.WithValue(req.Context(), contextKeyUserID, uID)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		h.HandleTotpDisable(rec, req)
		return rec
	}

	// 1. IP rate limiting test: same IP, 2 attempts allowed, 3rd blocked
	rec1 := callDisable("192.168.10.1", userID, "wrong1")
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on attempt 1, got %d", rec1.Code)
	}
	rec2 := callDisable("192.168.10.1", userID, "wrong2")
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on attempt 2, got %d", rec2.Code)
	}
	rec3 := callDisable("192.168.10.1", userID, "wrong3")
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on IP rate limit exceed, got %d", rec3.Code)
	}

	// 2. User rate limiting test: different IP, same user ID
	// Even from a new IP, user should already be throttled
	recUser := callDisable("192.168.10.99", userID, "wrong4")
	if recUser.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on User rate limit exceed, got %d", recUser.Code)
	}
}

func TestHandleTotpDisable_RateLimitResetOnSuccess(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	limiter := ratelimit.NewLimiter(time.Minute, 2)
	mockSvc := &mockTotpService{
		disableFn: func(ctx context.Context, uID, password, code string) error {
			if password == "correct-pass" {
				return nil
			}
			return apperrors.ErrInvalidCredentials
		},
	}

	h := &Handler{
		totpSvc:     mockSvc,
		totpLimiter: limiter,
	}

	callDisable := func(ip, password string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"password": password})
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/disable", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":12345"
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		h.HandleTotpDisable(rec, req)
		return rec
	}

	// 1 failure
	rec1 := callDisable("192.168.20.1", "bad-pass")
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on failure, got %d", rec1.Code)
	}

	// Success resets limiters
	rec2 := callDisable("192.168.20.1", "correct-pass")
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 on success, got %d", rec2.Code)
	}

	// Next failure does not hit 429 because counter was reset
	rec3 := callDisable("192.168.20.1", "bad-pass")
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after reset, got %d", rec3.Code)
	}
}

func TestHandleTotpDisable_PreservesPasswordWhitespace(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	var capturedPassword string
	mockSvc := &mockTotpService{
		disableFn: func(ctx context.Context, uID, password, code string) error {
			capturedPassword = password
			return nil
		},
	}

	h := &Handler{
		totpSvc: mockSvc,
	}

	inputPass := "  secret password with spaces  "
	body, _ := json.Marshal(map[string]string{"password": inputPass})
	req := httptest.NewRequest(http.MethodPost, "/auth/totp/disable", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.HandleTotpDisable(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if capturedPassword != inputPass {
		t.Fatalf("expected exact password %q, got %q", inputPass, capturedPassword)
	}
}

func TestHandleTotp_CacheControlHeaders(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	mockSvc := &mockTotpService{
		enrollFn: func(ctx context.Context, uID string) (*totp.EnrollmentResponse, error) {
			return &totp.EnrollmentResponse{Secret: "SECRET"}, nil
		},
		confirmFn: func(ctx context.Context, uID, code string) ([]string, error) {
			return []string{"BACKUP1"}, nil
		},
	}
	h := &Handler{totpSvc: mockSvc}

	// Enroll endpoint
	reqEnroll := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll", nil)
	reqEnroll = reqEnroll.WithContext(context.WithValue(reqEnroll.Context(), contextKeyUserID, userID))
	recEnroll := httptest.NewRecorder()
	h.HandleTotpEnroll(recEnroll, reqEnroll)

	if recEnroll.Code != http.StatusOK {
		t.Fatalf("enroll expected 200, got %d", recEnroll.Code)
	}
	if cc := recEnroll.Header().Get("Cache-Control"); cc != "no-store, private" {
		t.Errorf("enroll Cache-Control expected 'no-store, private', got %q", cc)
	}
	if pragma := recEnroll.Header().Get("Pragma"); pragma != "no-cache" {
		t.Errorf("enroll Pragma expected 'no-cache', got %q", pragma)
	}

	// Confirm endpoint
	bodyConfirm, _ := json.Marshal(map[string]string{"code": "123456"})
	reqConfirm := httptest.NewRequest(http.MethodPost, "/auth/totp/confirm", bytes.NewReader(bodyConfirm))
	reqConfirm.Header.Set("Content-Type", "application/json")
	reqConfirm = reqConfirm.WithContext(context.WithValue(reqConfirm.Context(), contextKeyUserID, userID))
	recConfirm := httptest.NewRecorder()
	h.HandleTotpConfirm(recConfirm, reqConfirm)

	if recConfirm.Code != http.StatusOK {
		t.Fatalf("confirm expected 200, got %d", recConfirm.Code)
	}
	if cc := recConfirm.Header().Get("Cache-Control"); cc != "no-store, private" {
		t.Errorf("confirm Cache-Control expected 'no-store, private', got %q", cc)
	}
	if pragma := recConfirm.Header().Get("Pragma"); pragma != "no-cache" {
		t.Errorf("confirm Pragma expected 'no-cache', got %q", pragma)
	}
}
