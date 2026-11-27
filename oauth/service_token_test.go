package oauth

import (
	stderrors "errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

// TestInitiateFlowRequiresTokenSealer pins the fail-closed gate: without a
// keyring no grant could be sealed, so the flow is refused before a state
// cookie is planted.
func TestInitiateFlowRequiresTokenSealer(t *testing.T) {
	cfg := serviceTestConfig()
	cfg.OAuth.TokenKEK = ""
	svc := NewService(serviceTestDB(t), nil, map[string]Provider{"google": &stubProvider{id: "google"}}, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google", nil)
	if _, err := svc.InitiateFlow(rec, req, "google"); !stderrors.Is(err, errors.ErrOAuthTokenKEKMissing) {
		t.Fatalf("InitiateFlow err = %v; want ErrOAuthTokenKEKMissing", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.OAuth.StateCookieName {
			t.Fatal("state cookie planted without a token keyring")
		}
	}
}

// TestHandleCallbackRequiresTokenSealer pins the guard ahead of the exchange:
// the authorization code is not burned and no user, link, or session appears.
func TestHandleCallbackRequiresTokenSealer(t *testing.T) {
	database, cfg, stub, svc := setupServiceTest(t, verifiedInfo())
	state, cookie := mustInitiate(t, svc, cfg, "google")

	noKEK := serviceTestConfig()
	noKEK.OAuth.TokenKEK = ""
	bare := NewService(database, session.NewService(database, noKEK), map[string]Provider{"google": stub}, noKEK)

	rec, req := callbackRequest(state, cookie)
	_, _, _, err := bare.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
	if !stderrors.Is(err, errors.ErrOAuthTokenKEKMissing) {
		t.Fatalf("HandleCallback err = %v; want ErrOAuthTokenKEKMissing", err)
	}
	if stub.exchanges != 0 {
		t.Fatalf("exchange calls = %d; want 0", stub.exchanges)
	}
	requireIdentityRows(t, database, 0, 0, 0)
}

func TestTokenExpiry(t *testing.T) {
	t.Run("no expiry for zero or negative expires_in", func(t *testing.T) {
		for _, expiresIn := range []int{0, -1, -3600} {
			if got := tokenExpiry(&OAuthToken{ExpiresIn: expiresIn}); got != nil {
				t.Fatalf("ExpiresIn %d = %v; want nil", expiresIn, got)
			}
		}
	})

	t.Run("derives now plus expires_in and ignores ExpiresAt", func(t *testing.T) {
		before := time.Now().UTC()
		got := tokenExpiry(&OAuthToken{ExpiresIn: 3600, ExpiresAt: time.Unix(1, 0)})
		after := time.Now().UTC()
		if got == nil {
			t.Fatal("expiry = nil; want now+3600s")
		}
		if got.Before(before.Add(time.Hour)) || got.After(after.Add(time.Hour)) {
			t.Fatalf("expiry = %v; want between %v and %v", got, before.Add(time.Hour), after.Add(time.Hour))
		}
	})

	t.Run("clamps an absurd expires_in to the duration limit instead of overflowing", func(t *testing.T) {
		huge := math.MaxInt64 / 2
		if int64(int(huge)) != int64(huge) {
			t.Skip("expires_in cannot exceed the clamp on this platform")
		}
		now := time.Now().UTC()
		got := tokenExpiry(&OAuthToken{ExpiresIn: int(huge)})
		if got == nil || !got.After(now) {
			t.Fatalf("expiry = %v; want a timestamp after %v", got, now)
		}
		if got.Before(now.Add(200 * 365 * 24 * time.Hour)) {
			t.Fatalf("expiry = %v; want the clamped horizon, not a wrapped one", got)
		}
	})
}
