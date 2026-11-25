package oauth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

// loginViaGoogle runs one full initiate/callback cycle and returns the session.
func loginViaGoogle(t *testing.T, svc Service, cfg *config.Config) (*session.Session, error) {
	t.Helper()
	state, cookie := mustInitiate(t, svc, cfg, "google")
	rec, req := callbackRequest(state, cookie)
	sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
	return sess, err
}

// signupPassword runs the real password signup for addr, which is the path that
// binds a caller-supplied password to an existing unverified row.
func signupPassword(t *testing.T, database *gorm.DB, cfg *config.Config, addr, password string) {
	t.Helper()
	authSvc, err := auth.New(*cfg, database, email.Hooks{})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	if _, _, err := authSvc.Signup(context.Background(), db.SignupRequest{Email: addr, Password: password}); err != nil {
		t.Fatalf("password signup: %v", err)
	}
}

// signupPasswordVerified runs the real password signup for addr, captures the
// verification token it dispatches, and consumes it: the flow that turns a
// caller-supplied password into a locally proven address.
func signupPasswordVerified(t *testing.T, database *gorm.DB, cfg *config.Config, addr, password string) {
	t.Helper()
	tokens := make(chan string, 1)
	authSvc, err := auth.New(*cfg, database, email.Hooks{
		SendVerificationEmail: func(_ context.Context, recipient, token string) error {
			if recipient == addr {
				select {
				case tokens <- token:
				default:
				}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	ctx := context.Background()
	if _, _, err := authSvc.Signup(ctx, db.SignupRequest{Email: addr, Password: password}); err != nil {
		t.Fatalf("password signup: %v", err)
	}
	select {
	case raw := <-tokens:
		if _, err := authSvc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: raw}); err != nil {
			t.Fatalf("VerifyEmail: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the verification email")
	}
}

// TestPasswordSquatCannotAttachLink is the squat chain end to end: an attacker
// binds a password to an address it does not own, the explicit ?link=true attach
// is refused because a caller-set password is not proof, and the owner's reset
// leaves no attacker link behind.
func TestPasswordSquatCannotAttachLink(t *testing.T) {
	const addr = "squatted@example.test"
	database, cfg, _, svc := setupServiceTest(t, &UserInfo{
		ProviderID: "google", ProviderUserID: "sub-squat",
		Email: addr, EmailVerified: true,
	})
	ctx := context.Background()

	signupPassword(t, database, cfg, addr, "CorrectHorseBattery9!")
	var squatter db.User
	if err := database.Where("email = ?", addr).First(&squatter).Error; err != nil {
		t.Fatalf("load squatted account: %v", err)
	}
	if squatter.EmailVerified || squatter.PasswordHash == "" {
		t.Fatalf("squatted account verified=%v hasPassword=%v; want an unverified password row",
			squatter.EmailVerified, squatter.PasswordHash != "")
	}
	_, rawSession, err := session.NewService(database, cfg).
		CreateSession(ctx, squatter.ID, squatter.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	state, cookie := initiateLinked(t, svc, cfg, "google", rawSession)
	rec, req := callbackRequestWithSession(state, cookie, cfg, rawSession)
	sess, _, _, err := svc.HandleCallback(ctx, rec, req, "google", "code-1", state, db.SessionTypeCookie)
	if sess != nil {
		t.Fatalf("session minted for %v; the squat must not authorize the link", sess.UserID)
	}
	requireCode(t, err, errors.CodeOAuthAccountLinkConflict, http.StatusConflict)
	requireIdentityRows(t, database, 1, 0, 1)

	// A link planted by the pre-hardening ?link=true path would be sitting on the
	// squatted row unverified; the owner's reset must remove it instead of
	// leaving it to mint sessions.
	planted := db.OAuthAccount{ID: uuid.New(), UserID: squatter.ID, ProviderID: "github",
		ProviderUserID: "sub-planted", Email: addr}
	if err := database.Create(&planted).Error; err != nil {
		t.Fatalf("seed planted link: %v", err)
	}
	authSvc, err := auth.New(*cfg, database, email.Hooks{})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	rawToken, err := authSvc.RequestPasswordReset(ctx, db.PasswordResetRequest{Email: addr})
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	owner, err := authSvc.ResetPassword(ctx, db.PasswordResetConfirmRequest{
		Token: rawToken, NewPassword: "OwnerPassword#2026!",
	})
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if !owner.EmailVerified {
		t.Fatal("reset must mark the recovered address verified")
	}
	if n := countRows(t, database, &db.OAuthAccount{}); n != 0 {
		t.Fatalf("oauth_accounts = %d; want 0 (the attacker's links must be purged)", n)
	}
}

func TestUnverifiedLinkAuthenticatesItsOwner(t *testing.T) {
	const addr = "unverified-owner@example.test"
	unverified := func(sub string) *UserInfo {
		return &UserInfo{ProviderID: "google", ProviderUserID: sub, Email: addr}
	}

	t.Run("repeat login reuses the unverified link", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, unverified("sub-repeat"))
		first, err := loginViaGoogle(t, svc, cfg)
		if err != nil {
			t.Fatalf("first login = %v", err)
		}
		second, err := loginViaGoogle(t, svc, cfg)
		if err != nil {
			t.Fatalf("second login = %v; want the persisted unverified link to sign in", err)
		}
		if second.UserID != first.UserID {
			t.Fatalf("second login user = %v; want %v", second.UserID, first.UserID)
		}
		var link db.OAuthAccount
		if err := database.Where("provider_id = ? AND provider_user_id = ?", "google", "sub-repeat").First(&link).Error; err != nil {
			t.Fatalf("load link: %v", err)
		}
		if link.Verified {
			t.Fatal("link for an unverified provider email must persist verified=false")
		}
		requireIdentityRows(t, database, 1, 1, 2)
	})

	t.Run("link resolves the owner ahead of the email path", func(t *testing.T) {
		// The owner's address and the provider's address differ, and no user
		// holds the provider address: only the link can resolve this callback.
		database, cfg, _, svc := setupServiceTest(t, &UserInfo{
			ProviderID: "google", ProviderUserID: "sub-owner-mismatch",
			Email: "provider-side@example.test",
		})
		owner := db.User{ID: uuid.New(), Email: "local-owner@example.test", PasswordHash: "", EmailVerified: false}
		if err := database.Create(&owner).Error; err != nil {
			t.Fatalf("seed owner: %v", err)
		}
		link := db.OAuthAccount{ID: uuid.New(), UserID: owner.ID, ProviderID: "google",
			ProviderUserID: "sub-owner-mismatch", Email: "provider-side@example.test"}
		if err := database.Create(&link).Error; err != nil {
			t.Fatalf("seed link: %v", err)
		}
		sess, err := loginViaGoogle(t, svc, cfg)
		if err != nil {
			t.Fatalf("login = %v", err)
		}
		if sess.UserID != owner.ID {
			t.Fatalf("session user = %v; want the link owner %v", sess.UserID, owner.ID)
		}
		requireIdentityRows(t, database, 1, 1, 1)
	})
}

// TestUnverifiedLinkTakeoverDefense pins the invariant that makes the trust
// flag safe: an unverified link signs in only the account it was created on, and
// only while that owner is unclaimed. Local proof of the address — a consumed
// verification token or a consumed password reset token — claims it, so the link
// is spent and can never grant access to the account afterwards.
func TestUnverifiedLinkTakeoverDefense(t *testing.T) {
	const addr = "victim@example.test"
	unverified := func() *UserInfo {
		return &UserInfo{ProviderID: "google", ProviderUserID: "sub-takeover", Email: addr}
	}
	requireLinkGone := func(t *testing.T, database *gorm.DB) {
		t.Helper()
		if n := countRows(t, database, &db.OAuthAccount{}); n != 0 {
			t.Fatalf("oauth_accounts = %d; want 0 (spent link must be invalidated)", n)
		}
	}

	// An unverified link must not survive a password claim. A password signup
	// atomically purges any unverified OAuth links on the account.
	t.Run("password-only signup purges the unverified link", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, unverified())
		first, err := loginViaGoogle(t, svc, cfg)
		if err != nil {
			t.Fatalf("unverified login = %v", err)
		}
		signupPassword(t, database, cfg, addr, "CorrectHorseBattery9!")

		var owner db.User
		if err := database.Where("id = ?", first.UserID).First(&owner).Error; err != nil {
			t.Fatalf("load owner: %v", err)
		}
		if owner.EmailVerified {
			t.Fatal("password signup must not mark the address verified")
		}
		if _, err := loginViaGoogle(t, svc, cfg); err == nil {
			t.Fatal("expected unverified login after a password-only signup to fail, got nil")
		}
		requireLinkGone(t, database)
	})

	t.Run("verification claims the address and purges the link", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, unverified())
		if _, err := loginViaGoogle(t, svc, cfg); err != nil {
			t.Fatalf("unverified login = %v", err)
		}
		signupPasswordVerified(t, database, cfg, addr, "CorrectHorseBattery9!")
		// The verification token came from the mailbox, so the account is claimed
		// and the unverified link is gone before its next callback.
		requireLinkGone(t, database)

		sess, err := loginViaGoogle(t, svc, cfg)
		if sess != nil {
			t.Fatalf("session minted for %v after verification claimed the address", sess.UserID)
		}
		requireCode(t, err, errors.CodeOAuthEmailUnverified, http.StatusBadRequest)
		requireLinkGone(t, database)
	})

	t.Run("password reset claims the address and purges the link", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, unverified())
		if _, err := loginViaGoogle(t, svc, cfg); err != nil {
			t.Fatalf("unverified login = %v", err)
		}
		authSvc, err := auth.New(*cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("auth.New: %v", err)
		}
		rawToken, err := authSvc.RequestPasswordReset(context.Background(), db.PasswordResetRequest{Email: addr})
		if err != nil {
			t.Fatalf("RequestPasswordReset: %v", err)
		}
		resetUser, err := authSvc.ResetPassword(context.Background(), db.PasswordResetConfirmRequest{
			Token: rawToken, NewPassword: "CorrectHorseBattery9!",
		})
		if err != nil {
			t.Fatalf("ResetPassword: %v", err)
		}
		if !resetUser.EmailVerified {
			t.Fatal("password reset must mark the address verified")
		}
		requireLinkGone(t, database)

		sess, err := loginViaGoogle(t, svc, cfg)
		if sess != nil {
			t.Fatalf("session minted for %v after recovery claimed the address", sess.UserID)
		}
		requireCode(t, err, errors.CodeOAuthEmailUnverified, http.StatusBadRequest)
		requireLinkGone(t, database)
	})

	t.Run("oauth into an occupied address never binds", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, unverified())
		signupPassword(t, database, cfg, addr, "CorrectHorseBattery9!")
		sess, err := loginViaGoogle(t, svc, cfg)
		if sess != nil {
			t.Fatalf("session minted for %v; want none", sess.UserID)
		}
		requireCode(t, err, errors.CodeOAuthEmailUnverified, http.StatusBadRequest)
		requireIdentityRows(t, database, 1, 0, 0)
	})

	t.Run("concurrent unverified links converge on one identity", func(t *testing.T) {
		database, _, _, rawSvc := setupServiceTest(t, nil)
		inner := rawSvc.(*service)
		type outcome struct {
			user db.User
			err  error
		}
		outs := make([]outcome, 2)
		var wg sync.WaitGroup
		for i := range outs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				u, _, _, err := inner.linkOrCreate(context.Background(), "google", unverified(), "")
				outs[i] = outcome{user: u, err: err}
			}(i)
		}
		wg.Wait()
		for i, o := range outs {
			if o.err != nil {
				t.Fatalf("goroutine %d: %v; want convergence", i, o.err)
			}
		}
		if outs[0].user.ID != outs[1].user.ID {
			t.Fatalf("converged users differ: %v vs %v", outs[0].user.ID, outs[1].user.ID)
		}
		requireIdentityRows(t, database, 1, 1, 0)
		var link db.OAuthAccount
		if err := database.First(&link).Error; err != nil {
			t.Fatalf("load link: %v", err)
		}
		if link.Verified {
			t.Fatal("raced unverified links must stay unverified")
		}
	})
}

// TestUnverifiedLinkScope pins where an unverified link stops counting: it
// never merges by its email, never resolves a different provider's identity,
// and never backs an explicit ?link=true attach.
func TestUnverifiedLinkScope(t *testing.T) {
	t.Run("link email never merges into another account", func(t *testing.T) {
		const victim = "scoped-victim@example.test"
		database, cfg, _, svc := setupServiceTest(t, &UserInfo{
			ProviderID: "google", ProviderUserID: "sub-scoped", Email: victim,
		})
		// A verified local account owns the address; an unrelated unclaimed
		// account owns an unverified link that claims it.
		verifiedOwner := db.User{ID: uuid.New(), Email: victim, PasswordHash: "hash", EmailVerified: true}
		stale := db.User{ID: uuid.New(), Email: "stale@example.test", PasswordHash: "", EmailVerified: false}
		for _, u := range []db.User{verifiedOwner, stale} {
			if err := database.Create(&u).Error; err != nil {
				t.Fatalf("seed user: %v", err)
			}
		}
		link := db.OAuthAccount{ID: uuid.New(), UserID: stale.ID, ProviderID: "google",
			ProviderUserID: "sub-scoped", Email: victim}
		if err := database.Create(&link).Error; err != nil {
			t.Fatalf("seed link: %v", err)
		}

		sess, err := loginViaGoogle(t, svc, cfg)
		if err != nil {
			t.Fatalf("login = %v", err)
		}
		if sess.UserID != stale.ID {
			t.Fatalf("session user = %v; want the link owner %v, never the verified %v", sess.UserID, stale.ID, verifiedOwner.ID)
		}
		var owner db.User
		if err := database.Where("id = ?", verifiedOwner.ID).First(&owner).Error; err != nil {
			t.Fatalf("load verified owner: %v", err)
		}
		if owner.PasswordHash != "hash" {
			t.Fatal("verified owner row was mutated by an unverified link")
		}
		requireIdentityRows(t, database, 2, 1, 1)
	})

	t.Run("link never resolves another provider's identity", func(t *testing.T) {
		const addr = "cross-provider@example.test"
		database := serviceTestDB(t)
		cfg := serviceTestConfig()
		google := &stubProvider{id: "google", info: &UserInfo{ProviderID: "google", ProviderUserID: "shared-sub", Email: addr}}
		facebook := &stubProvider{id: "facebook", info: &UserInfo{ProviderID: "facebook", ProviderUserID: "shared-sub", Email: addr}}
		svc := NewService(database, session.NewService(database, cfg),
			map[string]Provider{"google": google, "facebook": facebook}, cfg)

		owner := db.User{ID: uuid.New(), Email: addr, PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&owner).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		link := db.OAuthAccount{ID: uuid.New(), UserID: owner.ID, ProviderID: "google",
			ProviderUserID: "shared-sub", Email: addr}
		if err := database.Create(&link).Error; err != nil {
			t.Fatalf("seed link: %v", err)
		}

		state, cookie := mustInitiate(t, svc, cfg, "facebook")
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "facebook", "code-1", state, db.SessionTypeCookie)
		if sess != nil {
			t.Fatalf("session minted for %v through the google link", sess.UserID)
		}
		requireCode(t, err, errors.CodeOAuthEmailUnverified, http.StatusBadRequest)
		requireIdentityRows(t, database, 1, 1, 0)
	})

	t.Run("link intent rejects an unverified provider email", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, &UserInfo{
			ProviderID: "google", ProviderUserID: "sub-link-intent", Email: "attacker@example.test",
		})
		owner := db.User{ID: uuid.New(), Email: "signed-in@example.test", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&owner).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		_, rawSession, err := session.NewService(database, cfg).
			CreateSession(context.Background(), owner.ID, owner.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		state, cookie := initiateLinked(t, svc, cfg, "google", rawSession)
		rec, req := callbackRequestWithSession(state, cookie, cfg, rawSession)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if sess != nil {
			t.Fatalf("session minted for %v; want rejection", sess.UserID)
		}
		requireCode(t, err, errors.CodeOAuthEmailUnverified, http.StatusBadRequest)
		requireIdentityRows(t, database, 1, 0, 1)
	})

	t.Run("link intent rejects an unstorable provider email", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, &UserInfo{
			ProviderID: "google", ProviderUserID: "sub-link-invalid", Email: "not-an-address",
			EmailVerified: true,
		})
		owner := db.User{ID: uuid.New(), Email: "signed-in@example.test", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&owner).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		_, rawSession, err := session.NewService(database, cfg).
			CreateSession(context.Background(), owner.ID, owner.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		state, cookie := initiateLinked(t, svc, cfg, "google", rawSession)
		rec, req := callbackRequestWithSession(state, cookie, cfg, rawSession)
		if _, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie); err == nil {
			t.Fatal("expected an unstorable provider email to be rejected")
		}
		requireIdentityRows(t, database, 1, 0, 1)
	})
}
