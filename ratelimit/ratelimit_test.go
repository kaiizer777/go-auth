package ratelimit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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

func TestLimiter_IPKey_And_AccountKey(t *testing.T) {
	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"
	acc1 := "user1@example.com"
	acc2 := "user2@example.com"

	kIP1 := IPKey(ip1)
	kIP2 := IPKey(ip2)
	kAcc1 := AccountKey(acc1)
	kAcc2 := AccountKey(acc2)

	if kIP1 != "ip:192.168.1.1" || kIP2 != "ip:192.168.1.2" {
		t.Fatalf("unexpected IPKey values: %s, %s", kIP1, kIP2)
	}
	if kAcc1 != "account:user1@example.com" || kAcc2 != "account:user2@example.com" {
		t.Fatalf("unexpected AccountKey values: %s, %s", kAcc1, kAcc2)
	}
	if kIP1 == kAcc1 || kIP1 == kIP2 || kAcc1 == kAcc2 {
		t.Fatalf("IP and Account keys must be mutually distinct")
	}

	limiter := NewLimiter(1*time.Minute, 1)
	if !limiter.Allow(kIP1) {
		t.Fatalf("kIP1 should be allowed")
	}
	if limiter.Allow(kIP1) {
		t.Fatalf("kIP1 should be blocked")
	}

	if !limiter.Allow(kAcc1) {
		t.Fatalf("kAcc1 should be independent from kIP1")
	}
	if limiter.Allow(kAcc1) {
		t.Fatalf("kAcc1 should be blocked on second attempt")
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

func TestLimiter_Prune_BatchesAcrossAllKeys(t *testing.T) {
	window := 300 * time.Millisecond
	limiter := NewLimiter(window, 5)

	const activeCount = 270
	const expiredCount = 60
	const total = activeCount + expiredCount // 330 entries (>300)

	// Populate expired entries with timestamps older than window.
	now := time.Now()
	expiredCutoff := now.Add(-2 * window)

	limiter.mu.Lock()
	for i := 0; i < expiredCount; i++ {
		key := fmt.Sprintf("expired-key-%04d", i)
		limiter.windows[key] = &windowEntry{
			timestamps: []time.Time{expiredCutoff},
		}
	}

	// Populate active entries with current timestamps.
	for i := 0; i < activeCount; i++ {
		key := fmt.Sprintf("active-key-%04d", i)
		limiter.windows[key] = &windowEntry{
			timestamps: []time.Time{now},
		}
	}
	limiter.mu.Unlock()

	limiter.mu.RLock()
	initialLen := len(limiter.windows)
	limiter.mu.RUnlock()
	if initialLen != total {
		t.Fatalf("expected %d initial keys, got %d", total, initialLen)
	}

	// Prune should scan all batches (batchSize=256) and not terminate early
	// when encountering batches without expired keys.
	limiter.Prune()

	limiter.mu.RLock()
	defer limiter.mu.RUnlock()

	if len(limiter.windows) != activeCount {
		t.Fatalf("expected exactly %d remaining active entries, got %d (leaked %d entries)",
			activeCount, len(limiter.windows), len(limiter.windows)-activeCount)
	}

	for i := 0; i < expiredCount; i++ {
		key := fmt.Sprintf("expired-key-%04d", i)
		if _, ok := limiter.windows[key]; ok {
			t.Fatalf("expired key %s was not pruned", key)
		}
	}

	for i := 0; i < activeCount; i++ {
		key := fmt.Sprintf("active-key-%04d", i)
		if _, ok := limiter.windows[key]; !ok {
			t.Fatalf("active key %s was unexpectedly removed", key)
		}
	}
}

func TestLimiter_Prune_BatchesAcrossAllKeys_WithAllow(t *testing.T) {
	window := 250 * time.Millisecond
	limiter := NewLimiter(window, 5)

	const expiredCount = 50
	const activeCount = 260
	// 1. Create expired entries via Allow
	for i := 0; i < expiredCount; i++ {
		key := fmt.Sprintf("expire-allow-%04d", i)
		limiter.Allow(key)
	}

	time.Sleep(window + 50*time.Millisecond)

	// 2. Create active entries via Allow
	for i := 0; i < activeCount; i++ {
		key := fmt.Sprintf("active-allow-%04d", i)
		limiter.Allow(key)
	}

	limiter.Prune()

	limiter.mu.RLock()
	defer limiter.mu.RUnlock()

	if len(limiter.windows) != activeCount {
		t.Fatalf("expected %d entries, got %d", activeCount, len(limiter.windows))
	}
	for i := 0; i < expiredCount; i++ {
		key := fmt.Sprintf("expire-allow-%04d", i)
		if _, ok := limiter.windows[key]; ok {
			t.Fatalf("expected key %s to be pruned", key)
		}
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

func TestLimiter_ConcurrentAllowAndReset(t *testing.T) {
	limiter := NewLimiter(500*time.Millisecond, 10)
	key := "shared-hot-key"
	concurrency := 50
	iterations := 100

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if id%2 == 0 {
					limiter.Allow(key)
				} else {
					limiter.Reset(key)
				}
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

func TestLimiter_Allow_PruneHandoffRace(t *testing.T) {
	const iterations = 50
	for it := 0; it < iterations; it++ {
		window := 50 * time.Millisecond
		max := 3
		limiter := NewLimiter(window, max)
		key := fmt.Sprintf("race-key-%d", it)

		var wg sync.WaitGroup
		var allowedCount int64

		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if limiter.Allow(key) {
					atomic.AddInt64(&allowedCount, 1)
				}
			}()
		}

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				limiter.prune()
			}()
		}

		wg.Wait()

		if allowedCount > int64(max) {
			t.Fatalf("iteration %d: allowed %d requests within window, exceeded max %d", it, allowedCount, max)
		}
	}
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
		{name: "IPv6 bracketed without port", remoteAddr: "[2001:db8::1]", expected: "2001:db8::1"},
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

func TestLimiter_StartCleanup_NonPositiveTickDoesNotPanic(t *testing.T) {
	limiter := NewLimiter(1*time.Minute, 5)
	done := make(chan struct{})
	defer close(done)

	limiter.StartCleanup(0, done)
	limiter.StartCleanup(-1*time.Second, done)
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

func TestLimiter_NonPositiveParamsSanitized(t *testing.T) {
	l := NewLimiter(0, 0)
	if l.duration <= 0 {
		t.Errorf("expected positive sanitized duration, got %v", l.duration)
	}
	if l.max <= 0 {
		t.Errorf("expected positive sanitized max, got %v", l.max)
	}
}

func TestLimiter_RWMutexReadContention(t *testing.T) {
	limiter := NewLimiter(1*time.Minute, 1000)
	key := "contended-key"

	limiter.Allow(key)

	var wg sync.WaitGroup
	const goroutines = 20
	const opsPerGoroutine = 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				_ = limiter.RetryAfter(key)
				_ = limiter.Allow(key)
			}
		}()
	}
	wg.Wait()
}

func TestLimiter_CapacityBounded_FailClosed(t *testing.T) {
	limiter := NewLimiter(1*time.Minute, 5)
	const capLimit = 10
	limiter.SetMaxEntries(capLimit)

	for i := 0; i < capLimit; i++ {
		key := fmt.Sprintf("key-%d", i)
		if !limiter.Allow(key) {
			t.Fatalf("expected key %s to be allowed under capacity limit", key)
		}
	}

	// 11th distinct key must fail closed because capacity is saturated
	if limiter.Allow("overflow-key") {
		t.Fatalf("expected overflow-key to be refused when capacity is saturated")
	}

	// Existing keys must still evaluate properly
	if !limiter.Allow("key-0") {
		t.Fatalf("expected existing key-0 to evaluate and be allowed under its attempt cap")
	}

	// Map size must not exceed capLimit
	limiter.mu.RLock()
	size := len(limiter.windows)
	limiter.mu.RUnlock()
	if size > capLimit {
		t.Fatalf("limiter map size = %d; want at most %d", size, capLimit)
	}
}

func TestLimiter_CapacityRecoversAfterPrune(t *testing.T) {
	window := 50 * time.Millisecond
	limiter := NewLimiter(window, 5)
	limiter.SetMaxEntries(2)

	if !limiter.Allow("key-1") || !limiter.Allow("key-2") {
		t.Fatal("initial keys should be allowed")
	}

	if limiter.Allow("key-3") {
		t.Fatal("key-3 should be refused when capacity is saturated")
	}

	// Wait for window to expire and prune
	time.Sleep(70 * time.Millisecond)
	limiter.Prune()

	// Capacity freed up, key-3 should now be allowed
	if !limiter.Allow("key-3") {
		t.Fatal("key-3 should be allowed after expired entries were pruned")
	}
}

func TestLimiter_Allow_AutoPruneOnCapacity(t *testing.T) {
	window := 50 * time.Millisecond
	limiter := NewLimiter(window, 5)
	limiter.SetMaxEntries(2)

	if !limiter.Allow("key-1") || !limiter.Allow("key-2") {
		t.Fatal("initial keys should be allowed")
	}

	if limiter.Allow("key-3") {
		t.Fatal("key-3 should be refused when capacity is saturated with active entries")
	}

	time.Sleep(70 * time.Millisecond)

	if !limiter.Allow("key-3") {
		t.Fatal("key-3 should be allowed after automatic inline eviction")
	}
}
