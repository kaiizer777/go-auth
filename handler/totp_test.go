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
}

func (m *mockTotpService) ConfirmEnrollment(ctx context.Context, userID, code string) ([]string, error) {
	if m.confirmFn != nil {
		return m.confirmFn(ctx, userID, code)
	}
	return []string{"CODE1", "CODE2"}, nil
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
