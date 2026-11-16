package ratelimit

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	apperrors "github.com/kaiizer777/go-auth/errors"
)

type windowEntry struct {
	mu         sync.Mutex
	timestamps []time.Time
}

// Limiter is a concurrency-safe sliding-window in-memory rate limiter with optimized RWMutex read paths.
type Limiter struct {
	mu       sync.RWMutex
	windows  map[string]*windowEntry
	duration time.Duration
	max      int
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewLimiter creates a Limiter with the given window duration and attempt cap.
// If duration <= 0, it defaults to 1 minute; if max <= 0, it defaults to 1.
func NewLimiter(duration time.Duration, max int) *Limiter {
	if duration <= 0 {
		duration = time.Minute
	}
	if max <= 0 {
		max = 1
	}
	return &Limiter{
		windows:  make(map[string]*windowEntry),
		duration: duration,
		max:      max,
		stopCh:   make(chan struct{}),
	}
}

// Key builds the composite IP and account rate limit key.
func Key(ip, account string) string {
	return fmt.Sprintf("%s|%s", ip, account)
}

// IPKey returns a rate limit key scoped to the client IP address.
func IPKey(ip string) string {
	return "ip:" + ip
}

// AccountKey returns a rate limit key scoped to the account identifier (e.g. normalized email).
func AccountKey(account string) string {
	return "account:" + account
}

// ClientIP extracts the client IP address from r.RemoteAddr, stripping the port
// and normalizing IPv6 bracket enclosing formats.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	return strings.Trim(host, "[]")
}

// Allow evaluates whether an action is permitted within the sliding window.
// Only successful attempts are recorded — blocked calls do not increment counter.
// Uses an RWMutex read path on existing keys to minimize lock contention.
func (l *Limiter) Allow(key string) bool {
	l.mu.RLock()
	entry, ok := l.windows[key]
	if ok {
		entry.mu.Lock()
		l.mu.RUnlock()
	} else {
		l.mu.RUnlock()
		l.mu.Lock()
		entry, ok = l.windows[key]
		if !ok {
			entry = &windowEntry{}
			l.windows[key] = entry
		}
		entry.mu.Lock()
		l.mu.Unlock()
	}

	defer entry.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.duration)

	valid := entry.timestamps[:0]
	for _, t := range entry.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	entry.timestamps = valid

	if len(entry.timestamps) >= l.max {
		return false
	}

	entry.timestamps = append(entry.timestamps, now)
	return true
}

// Reset clears the counter for key on successful authentication.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	if entry, ok := l.windows[key]; ok {
		entry.mu.Lock()
		delete(l.windows, key)
		entry.timestamps = nil
		entry.mu.Unlock()
	}
	l.mu.Unlock()
}

// StartCleanup runs a background eviction loop to prevent memory bloat.
// It stops when either done receives/closes, or Close() is called.
func (l *Limiter) StartCleanup(tick time.Duration, done <-chan struct{}) {
	if tick <= 0 {
		tick = 5 * time.Minute
	}
	go func() {
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				l.prune()
			case <-done:
				return
			case <-l.stopCh:
				return
			}
		}
	}()
}

// Close gracefully stops any background cleanup goroutines.
func (l *Limiter) Close() {
	l.stopOnce.Do(func() {
		close(l.stopCh)
	})
}

// Prune removes fully-expired window entries from the map.
func (l *Limiter) Prune() {
	l.prune()
}

func (l *Limiter) prune() {
	const batchSize = 256
	cutoff := time.Now().Add(-l.duration)

	type candidate struct {
		key   string
		entry *windowEntry
	}

	for {
		l.mu.RLock()
		if len(l.windows) == 0 {
			l.mu.RUnlock()
			return
		}

		candidates := make([]candidate, 0, batchSize)
		for k, entry := range l.windows {
			candidates = append(candidates, candidate{key: k, entry: entry})
			if len(candidates) >= batchSize {
				break
			}
		}
		l.mu.RUnlock()

		if len(candidates) == 0 {
			return
		}

		expiredKeys := make([]string, 0, len(candidates))
		for _, c := range candidates {
			c.entry.mu.Lock()
			allExpired := true
			for _, t := range c.entry.timestamps {
				if t.After(cutoff) {
					allExpired = false
					break
				}
			}
			if allExpired {
				c.entry.timestamps = nil
				expiredKeys = append(expiredKeys, c.key)
			}
			c.entry.mu.Unlock()
		}

		if len(expiredKeys) > 0 {
			l.mu.Lock()
			for _, k := range expiredKeys {
				if entry, ok := l.windows[k]; ok {
					entry.mu.Lock()
					if len(entry.timestamps) == 0 && l.windows[k] == entry {
						delete(l.windows, k)
					}
					entry.mu.Unlock()
				}
			}
			l.mu.Unlock()
		}

		if len(candidates) < batchSize || len(expiredKeys) == 0 {
			return
		}
	}
}

// RetryAfter returns the duration until the rate limit will permit a new attempt.
// If the key has not reached the attempt limit, 0 is returned.
func (l *Limiter) RetryAfter(key string) time.Duration {
	l.mu.RLock()
	entry, ok := l.windows[key]
	if !ok {
		l.mu.RUnlock()
		return 0
	}
	entry.mu.Lock()
	l.mu.RUnlock()

	defer entry.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.duration)
	validCount := 0
	var oldestValid time.Time
	for _, t := range entry.timestamps {
		if t.After(cutoff) {
			if oldestValid.IsZero() {
				oldestValid = t
			}
			validCount++
		}
	}

	if validCount < l.max {
		return 0
	}

	rem := oldestValid.Add(l.duration).Sub(now)
	if rem > 0 {
		return rem
	}
	return 0
}

// WriteRateLimitError writes a 429 response using errors.WriteHTTP and sets the Retry-After header.
func WriteRateLimitError(w http.ResponseWriter, retryAfter time.Duration) {
	if retryAfter > 0 {
		seconds := int(math.Ceil(retryAfter.Seconds()))
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
	apperrors.WriteHTTP(w, apperrors.ErrRateLimitExceeded)
}
