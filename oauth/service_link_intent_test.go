package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

// failGetSessionSvc errors every session lookup to simulate a store outage.
type failGetSessionSvc struct {
	session.Service
	err error
}

func (f *failGetSessionSvc) GetSession(_ context.Context, _ string) (*session.Session, error) {
	return nil, f.err
}

func signedInitiate(t *testing.T, svc Service, cfg *config.Config, providerID, path, rawToken string) (string, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if rawToken != "" {
		req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rawToken})
	}
	rec := httptest.NewRecorder()
	authURL, err := svc.InitiateFlow(rec, req, providerID)
	if err != nil {
		t.Fatalf("InitiateFlow = %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authURL: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.OAuth.StateCookieName {
			return u.Query().Get("state"), c
		}
	}
	t.Fatalf("no %q cookie issued", cfg.OAuth.StateCookieName)
	return "", nil
}

func TestInitiateFlowLinkIntent(t *testing.T) {
	t.Run("signed-in bare login stays login", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-new", Email: "newuser@example.com", EmailVerified: true})
		sessSvc := session.NewService(database, cfg)
		user := db.User{ID: uuid.New(), Email: "signedin@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&user).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		_, rawToken, err := sessSvc.CreateSession(context.Background(), user.ID, 0, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		state, cookie := signedInitiate(t, svc, cfg, "google", "/auth/oauth/google", rawToken)
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v", err)
		}
		if sess.UserID == user.ID {
			t.Fatalf("bare login linked ambient session user %v; want fresh registration", user.ID)
		}
		requireIdentityRows(t, database, 2, 1, 2)
	})

	t.Run("link without session stays login", func(t *testing.T) {
		t.Parallel()
		_, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		state, cookie := signedInitiate(t, svc, cfg, "google", "/auth/oauth/google?link=true", "")
		if state == "" || cookie == nil {
			t.Fatal("link initiation without session must still issue state")
		}
	})

	t.Run("link with failing store is 500", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, _ := setupServiceTest(t, verifiedInfo())
		broken := &failGetSessionSvc{err: errors.New(errors.CodeInternalError, "db down", nil)}
		svc := NewService(database, broken, map[string]Provider{"google": &stubProvider{id: "google", info: verifiedInfo()}}, cfg)
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google?link=true", nil)
		req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: "0123456789abcdef0123456789abcdef"})
		_, err := svc.InitiateFlow(httptest.NewRecorder(), req, "google")
		requireCode(t, err, errors.CodeInternalError, http.StatusInternalServerError)
	})

	t.Run("link with bogus cookie degrades to login", func(t *testing.T) {
		t.Parallel()
		_, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		state, cookie := signedInitiate(t, svc, cfg, "google", "/auth/oauth/google?link=true", "not-a-session")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback", nil)
		req.AddCookie(cookie)
		payload, err := ValidateState(rec, req, cfg, "google", state)
		if err != nil {
			t.Fatalf("ValidateState = %v", err)
		}
		if payload.UserID != "" {
			t.Fatalf("state user = %q; want empty (login, not link)", payload.UserID)
		}
	})
}

func TestLinkOrCreateFailClosed(t *testing.T) {
	// Merge premise (oauth sync): an unresolvable link owner maps to the
	// domain-level OAUTH_ACCOUNT_NOT_LINKED (404), not a 500: nothing is
	// broken server-side, the selected owner just cannot be confirmed.
	// Genuine store failures stay 500 ("store failure stays a domain error").
	t.Run("unparsable link user fails closed with zero writes", func(t *testing.T) {
		t.Parallel()
		database, _, _, svc := setupServiceTest(t, verifiedInfo())
		inner, ok := svc.(*service)
		if !ok {
			t.Fatal("NewService did not return *service")
		}
		_, _, _, err := inner.linkOrCreate(context.Background(), "google", verifiedInfo(), "not-a-uuid", nil)
		requireCode(t, err, errors.CodeOAuthAccountNotLinked, http.StatusNotFound)
		requireIdentityRows(t, database, 0, 0, 0)
	})

	t.Run("missing link owner fails closed with zero writes", func(t *testing.T) {
		t.Parallel()
		database, _, _, svc := setupServiceTest(t, verifiedInfo())
		inner, ok := svc.(*service)
		if !ok {
			t.Fatal("NewService did not return *service")
		}
		_, _, _, err := inner.linkOrCreate(context.Background(), "google", verifiedInfo(), uuid.New().String(), nil)
		requireCode(t, err, errors.CodeOAuthAccountNotLinked, http.StatusNotFound)
		requireIdentityRows(t, database, 0, 0, 0)
	})
}

func TestCallbackSessionRecheck(t *testing.T) {
	t.Run("swapped session rejects link with 409", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-fix", Email: "fix@example.com", EmailVerified: true})
		sessSvc := session.NewService(database, cfg)
		mkUser := func(email string) (db.User, string) {
			t.Helper()
			u := db.User{ID: uuid.New(), Email: email, PasswordHash: "hash", EmailVerified: true}
			if err := database.Create(&u).Error; err != nil {
				t.Fatalf("seed user: %v", err)
			}
			_, tok, err := sessSvc.CreateSession(context.Background(), u.ID, 0, db.SessionTypeCookie, "127.0.0.1", "ua")
			if err != nil {
				t.Fatalf("create session: %v", err)
			}
			return u, tok
		}
		_, tokA := mkUser("victim-a@example.com")
		_, tokB := mkUser("victim-b@example.com")
		state, cookie := signedInitiate(t, svc, cfg, "google", "/auth/oauth/google?link=true", tokA)
		rec, req := callbackRequest(state, cookie)
		req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: tokB})
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthAccountAlreadyLinked, http.StatusConflict)
		if n := countRows(t, database, &db.OAuthAccount{}); n != 0 {
			t.Fatalf("oauth_accounts = %d; want 0 (no foreign link)", n)
		}
	})

	t.Run("expired session falls back to login", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-fb", Email: "fallback@example.com", EmailVerified: true})
		sessSvc := session.NewService(database, cfg)
		user := db.User{ID: uuid.New(), Email: "gone@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&user).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		_, rawToken, err := sessSvc.CreateSession(context.Background(), user.ID, 0, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		state, cookie := signedInitiate(t, svc, cfg, "google", "/auth/oauth/google?link=true", rawToken)
		// Session cookie withheld: expiry between initiate and callback.
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v; want login fallback, not rejection", err)
		}
		if sess.UserID == user.ID {
			t.Fatalf("fallback linked expired session user %v; want fresh login", user.ID)
		}
		requireIdentityRows(t, database, 2, 1, 2)
	})

	t.Run("failing store at callback is 500", func(t *testing.T) {
		t.Parallel()
		database, cfg, stub, svc := setupServiceTest(t, verifiedInfo())
		sessSvc := session.NewService(database, cfg)
		user := db.User{ID: uuid.New(), Email: "cb500@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&user).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		_, rawToken, err := sessSvc.CreateSession(context.Background(), user.ID, 0, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		state, cookie := signedInitiate(t, svc, cfg, "google", "/auth/oauth/google?link=true", rawToken)
		broken := NewService(database,
			&failGetSessionSvc{err: errors.New(errors.CodeInternalError, "db down", nil)},
			map[string]Provider{"google": stub}, cfg)
		rec, req := callbackRequest(state, cookie)
		req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rawToken})
		_, _, _, err = broken.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeInternalError, http.StatusInternalServerError)
	})
}
