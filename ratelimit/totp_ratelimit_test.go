package ratelimit

import (
	"testing"
	"time"
)

func TestTOTPKeyFormats(t *testing.T) {
	t.Parallel()

	ip := "192.168.1.100"
	expectedIPKey := "totp:ip:192.168.1.100"
	if got := TOTPIPKey(ip); got != expectedIPKey {
		t.Errorf("TOTPIPKey(%q) = %q; want %q", ip, got, expectedIPKey)
	}

	userID := "550e8400-e29b-41d4-a716-446655440000"
	expectedUserKey := "totp:user:550e8400-e29b-41d4-a716-446655440000"
	if got := TOTPUserKey(userID); got != expectedUserKey {
		t.Errorf("TOTPUserKey(%q) = %q; want %q", userID, got, expectedUserKey)
	}
}

func TestTOTPIndependentDimensionRateLimiting(t *testing.T) {
	t.Parallel()

	limiter := NewLimiter(time.Minute, 3)

	ipA := TOTPIPKey("10.0.0.1")
	ipB := TOTPIPKey("10.0.0.2")

	// Exhaust ipA
	for i := 0; i < 3; i++ {
		if !limiter.Allow(ipA) {
			t.Fatalf("attempt %d for ipA rejected unexpectedly", i+1)
		}
	}
	if limiter.Allow(ipA) {
		t.Fatal("4th attempt for ipA should have been rejected by rate limiter")
	}

	// ipB should remain unaffected
	if !limiter.Allow(ipB) {
		t.Fatal("ipB was blocked by ipA's exhaustion")
	}

	// User dimension test
	userA := TOTPUserKey("user-aaa")
	userB := TOTPUserKey("user-bbb")

	// Exhaust userA
	for i := 0; i < 3; i++ {
		if !limiter.Allow(userA) {
			t.Fatalf("attempt %d for userA rejected unexpectedly", i+1)
		}
	}
	if limiter.Allow(userA) {
		t.Fatal("4th attempt for userA should have been rejected")
	}

	// userB should remain unaffected
	if !limiter.Allow(userB) {
		t.Fatal("userB was blocked by userA's exhaustion")
	}
}
