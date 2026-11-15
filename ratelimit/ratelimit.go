package ratelimit

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	apperrors "github.com/kaiizer777/go-auth/errors"
)

type windowEntry struct {
	timestamps []time.Time
	mu         sync.Mutex
}

// Limiter is a concurrency-safe sliding-window in-memory rate limiter.
type Limiter struct {
	mu       sync.Mutex
	windows  map[string]*windowEntry
	duration time.Duration
	max      int
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewLimiter creates a Limiter with the given window duration and attempt cap.
func NewLimiter(duration time.Duration, max int) *Limiter {
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

// Allow evaluates whether an action is permitted within the sliding window.
// Only successful attempts are recorded — blocked calls do not increment counter.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	entry, ok := l.windows[key]
	if !ok {
		entry = &windowEntry{}
		l.windows[key] = entry
	}
	l.mu.Unlock()

	entry.mu.Lock()
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
	delete(l.windows, key)
	l.mu.Unlock()
}

// StartCleanup runs a background eviction loop to prevent memory bloat.
// It stops when either done receives/closes, or Close() is called.
func (l *Limiter) StartCleanup(tick time.Duration, done <-chan struct{}) {
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
	l.mu.Lock()
	keys := make([]string, 0, len(l.windows))
	for k := range l.windows {
		keys = append(keys, k)
	}
	l.mu.Unlock()

	cutoff := time.Now().Add(-l.duration)

	for _, key := range keys {
		l.mu.Lock()
		entry, ok := l.windows[key]
		l.mu.Unlock()

		if !ok {
			continue
		}

		entry.mu.Lock()
		allExpired := true
		for _, t := range entry.timestamps {
			if t.After(cutoff) {
				allExpired = false
				break
			}
		}
		if allExpired {
			entry.timestamps = nil
		}
		entry.mu.Unlock()

		if allExpired {
			l.mu.Lock()
			delete(l.windows, key)
			l.mu.Unlock()
		}
	}
}

// RetryAfter returns the duration until the rate limit will permit a new attempt.
func (l *Limiter) RetryAfter(key string) time.Duration {
	l.mu.Lock()
	entry, ok := l.windows[key]
	l.mu.Unlock()
	if !ok {
		return 0
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.duration)
	for _, t := range entry.timestamps {
		if t.After(cutoff) {
			rem := t.Add(l.duration).Sub(now)
			if rem > 0 {
				return rem
			}
		}
	}
	return 0
}

// WriteRateLimitError writes a 429 response using errors.WriteHTTP and sets the Retry-After header.
func WriteRateLimitError(w http.ResponseWriter, retryAfter time.Duration) {
	if retryAfter > 0 {
		seconds := int(retryAfter.Seconds())
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
	apperrors.WriteHTTP(w, apperrors.ErrRateLimitExceeded)
}
