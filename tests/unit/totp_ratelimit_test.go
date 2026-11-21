package unit_test

import (
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/ratelimit"
)

func TestTOTPIPKeyFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
		want string
	}{
		{name: "standard ipv4", ip: "192.168.1.100", want: "totp:ip:192.168.1.100"},
		{name: "standard ipv6", ip: "2001:db8::1", want: "totp:ip:2001:db8::1"},
		{name: "loopback", ip: "127.0.0.1", want: "totp:ip:127.0.0.1"},
		{name: "empty string", ip: "", want: "totp:ip:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ratelimit.TOTPIPKey(tt.ip)
			if got != tt.want {
				t.Fatalf("TOTPIPKey(%q) = %q; want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestTOTPUserKeyFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		userID string
		want   string
	}{
		{name: "standard uuid", userID: "a0000000-0000-0000-0000-000000000001", want: "totp:user:a0000000-0000-0000-0000-000000000001"},
		{name: "alphanumeric id", userID: "user_99482", want: "totp:user:user_99482"},
		{name: "empty id", userID: "", want: "totp:user:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ratelimit.TOTPUserKey(tt.userID)
			if got != tt.want {
				t.Fatalf("TOTPUserKey(%q) = %q; want %q", tt.userID, got, tt.want)
			}
		})
	}
}

func TestTOTPRateLimiter_IndependentDimensions(t *testing.T) {
	t.Parallel()

	limiter := ratelimit.NewLimiter(1*time.Minute, 2)

	ipA := "10.0.0.1"
	ipB := "10.0.0.2"
	userA := "user-uuid-aaa"
	userB := "user-uuid-bbb"

	kIPA := ratelimit.TOTPIPKey(ipA)
	kIPB := ratelimit.TOTPIPKey(ipB)
	kUserA := ratelimit.TOTPUserKey(userA)
	kUserB := ratelimit.TOTPUserKey(userB)

	// Exhaust ipA (max = 2)
	if !limiter.Allow(kIPA) {
		t.Fatal("first attempt for ipA should be allowed")
	}
	if !limiter.Allow(kIPA) {
		t.Fatal("second attempt for ipA should be allowed")
	}
	if limiter.Allow(kIPA) {
		t.Fatal("third attempt for ipA should be blocked")
	}

	// ipB must still be allowed independently
	if !limiter.Allow(kIPB) {
		t.Fatal("ipB must not be blocked by ipA exhaustion")
	}

	// userA and userB must not be blocked by ipA exhaustion
	if !limiter.Allow(kUserA) {
		t.Fatal("userA must not be blocked by ipA exhaustion")
	}
	if !limiter.Allow(kUserB) {
		t.Fatal("userB must not be blocked by ipA exhaustion")
	}

	// Now exhaust userA
	if !limiter.Allow(kUserA) {
		t.Fatal("second attempt for userA should be allowed")
	}
	if limiter.Allow(kUserA) {
		t.Fatal("third attempt for userA should be blocked")
	}

	// userB must still be allowed under its own limit
	if !limiter.Allow(kUserB) {
		t.Fatal("userB must not be blocked by userA exhaustion")
	}
	if limiter.Allow(kUserB) {
		t.Fatal("third attempt for userB should be blocked")
	}
}

func TestTOTPRateLimiter_DistinctKeyPrefixes(t *testing.T) {
	t.Parallel()

	id := "test-identifier"
	keys := map[string]string{
		"ip":        ratelimit.IPKey(id),
		"account":   ratelimit.AccountKey(id),
		"totp_ip":   ratelimit.TOTPIPKey(id),
		"totp_user": ratelimit.TOTPUserKey(id),
	}

	seen := make(map[string]string)
	for name, k := range keys {
		if prev, ok := seen[k]; ok {
			t.Fatalf("key collision between %s and %s: %q", name, prev, k)
		}
		seen[k] = name
	}
}
