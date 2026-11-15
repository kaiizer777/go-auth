package ratelimit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestLimiter_Allow_UnderLimit(t *testing.T) {
	limiter := NewLimiter(1*time.Minute, 3)
	key := "test-key-under"

	if !limiter.Allow(key) {
		t.Fatalf("first attempt should be allowed")
	}
	if !limiter.Allow(key) {
		t.Fatalf("second attempt should be allowed")
	}
	if !limiter.Allow(key) {
		t.Fatalf("third attempt should be allowed")
	}
}

func TestLimiter_Allow_AtLimit(t *testing.T) {
	limiter := NewLimiter(1*time.Minute, 2)
	key := "test-key-at-limit"

	if !limiter.Allow(key) {
		t.Fatalf("attempt 1 should be allowed")
	}
	if !limiter.Allow(key) {
		t.Fatalf("attempt 2 should be allowed")
	}
	if limiter.Allow(key) {
		t.Fatalf("attempt 3 should be blocked")
	}
	if limiter.Allow(key) {
		t.Fatalf("attempt 4 should be blocked")
	}
}

func TestLimiter_Allow_SlidingWindow(t *testing.T) {
	window := 100 * time.Millisecond
	limiter := NewLimiter(window, 1)
	key := "test-key-sliding"

	if !limiter.Allow(key) {
		t.Fatalf("first attempt should be allowed")
	}
	if limiter.Allow(key) {
		t.Fatalf("second attempt should be blocked within window")
	}

	time.Sleep(120 * time.Millisecond)

	if !limiter.Allow(key) {
		t.Fatalf("attempt after window expired should be allowed")
	}
}

func TestLimiter_Reset_ClearsCounter(t *testing.T) {
	limiter := NewLimiter(1*time.Minute, 1)
	key := "test-key-reset"

	if !limiter.Allow(key) {
		t.Fatalf("first attempt should be allowed")
	}
	if limiter.Allow(key) {
		t.Fatalf("second attempt should be blocked")
	}

	limiter.Reset(key)

	if !limiter.Allow(key) {
		t.Fatalf("attempt after Reset should be allowed")
	}
}

func TestLimiter_Key_CompositeKey(t *testing.T) {
	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"
	acc1 := "user1@example.com"
	acc2 := "user2@example.com"

	k1 := Key(ip1, acc1)
	k2 := Key(ip1, acc2)
	k3 := Key(ip2, acc1)

	if k1 == k2 || k1 == k3 || k2 == k3 {
		t.Fatalf("composite keys must be distinct for different (ip, account) pairs")
	}

	limiter := NewLimiter(1*time.Minute, 1)
	if !limiter.Allow(k1) {
		t.Fatalf("k1 should be allowed")
	}
	if limiter.Allow(k1) {
		t.Fatalf("k1 should be blocked")
	}

	if !limiter.Allow(k2) {
		t.Fatalf("k2 should be independent from k1")
	}
	if !limiter.Allow(k3) {
		t.Fatalf("k3 should be independent from k1 and k2")
	}
}

func TestLimiter_Prune_RemovesExpired(t *testing.T) {
	window := 50 * time.Millisecond
	limiter := NewLimiter(window, 2)
	key := "test-prune"

	limiter.Allow(key)

	limiter.mu.Lock()
	if _, ok := limiter.windows[key]; !ok {
		limiter.mu.Unlock()
		t.Fatalf("key should exist in windows")
	}
	limiter.mu.Unlock()

	time.Sleep(80 * time.Millisecond)
	limiter.prune()

	limiter.mu.Lock()
	_, ok := limiter.windows[key]
	limiter.mu.Unlock()

	if ok {
		t.Fatalf("key should have been pruned from windows")
	}
}

func TestLimiter_ConcurrentAccess(t *testing.T) {
	limiter := NewLimiter(500*time.Millisecond, 20)
	concurrency := 50
	var wg sync.WaitGroup

	done := make(chan struct{})
	limiter.StartCleanup(50*time.Millisecond, done)
	defer close(done)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("ip-%d|acc-%d", id%5, id%3)
			for j := 0; j < 20; j++ {
				limiter.Allow(key)
				if j%5 == 0 {
					limiter.Reset(key)
				}
				_ = limiter.RetryAfter(key)
			}
		}(i)
	}

	wg.Wait()
}

func TestLimiter_RetryAfter(t *testing.T) {
	window := 200 * time.Millisecond
	limiter := NewLimiter(window, 2)
	key := "test-retry-after"

	if retry := limiter.RetryAfter(key); retry != 0 {
		t.Fatalf("expected 0 RetryAfter for unknown key, got %v", retry)
	}

	// 1 attempt under limit (max=2) -> must return 0
	limiter.Allow(key)
	if retry := limiter.RetryAfter(key); retry != 0 {
		t.Fatalf("expected 0 RetryAfter when under limit, got %v", retry)
	}

	// 2nd attempt reaches limit -> must return positive duration <= window
	limiter.Allow(key)
	retry := limiter.RetryAfter(key)
	if retry <= 0 || retry > window {
		t.Fatalf("expected 0 < RetryAfter <= window, got %v", retry)
	}
}

func TestLimiter_Close(t *testing.T) {
	limiter := NewLimiter(50*time.Millisecond, 2)
	done := make(chan struct{})
	limiter.StartCleanup(10*time.Millisecond, done)

	// Close limiter
	limiter.Close()

	// Calling Close() again must be safe and idempotent
	limiter.Close()

	select {
	case <-limiter.stopCh:
		// expected
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected limiter.stopCh to be closed")
	}
}

func TestLimiter_Prune_ConcurrentAllow(t *testing.T) {
	limiter := NewLimiter(20*time.Millisecond, 2)
	key := "test-prune-race"

	limiter.Allow(key)
	time.Sleep(30 * time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		limiter.prune()
	}()

	go func() {
		defer wg.Done()
		limiter.Allow(key)
	}()

	wg.Wait()
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{name: "IPv4 with port", remoteAddr: "192.0.2.1:12345", expected: "192.0.2.1"},
		{name: "IPv4 without port", remoteAddr: "192.0.2.1", expected: "192.0.2.1"},
		{name: "IPv6 with port", remoteAddr: "[2001:db8::1]:8080", expected: "2001:db8::1"},
		{name: "IPv6 without port", remoteAddr: "2001:db8::1", expected: "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			got := ClientIP(req)
			if got != tt.expected {
				t.Errorf("ClientIP() = %q, want %q", got, tt.expected)
			}
		})
	}

	if got := ClientIP(nil); got != "" {
		t.Errorf("ClientIP(nil) = %q, want empty", got)
	}
}

func TestWriteRateLimitError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteRateLimitError(rec, 1500*time.Millisecond)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter != "2" {
		t.Fatalf("expected Retry-After='2', got %q", retryAfter)
	}

	// Sub-second wait rounds up to 1
	rec2 := httptest.NewRecorder()
	WriteRateLimitError(rec2, 200*time.Millisecond)
	if rec2.Header().Get("Retry-After") != "1" {
		t.Fatalf("expected Retry-After='1', got %q", rec2.Header().Get("Retry-After"))
	}
}
