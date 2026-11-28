package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

// loginMicrosoft drives one callback through the real linking decision tree with
// the given Microsoft identity and returns the minted session.
func loginMicrosoft(t *testing.T, database *gorm.DB, cfg *config.Config, info *UserInfo) *session.Session {
	t.Helper()
	svc := NewService(database, session.NewService(database, cfg),
		map[string]Provider{"microsoft": &stubProvider{id: "microsoft", info: info}}, cfg)
	state, cookie := mustInitiate(t, svc, cfg, "microsoft")
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft/callback", nil)
	req.AddCookie(cookie)

	sess, _, _, err := svc.HandleCallback(context.Background(), httptest.NewRecorder(), req, "microsoft", "code", state, db.SessionTypeCookie)
	if err != nil {
		t.Fatalf("HandleCallback for tenant %q: %v", info.ProviderTenantID, err)
	}
	if sess == nil {
		t.Fatalf("no session for tenant %q", info.ProviderTenantID)
	}
	return sess
}

// TestLinkOrCreateQualifiesIdentityByTenant is the regression test for #72: a
// Microsoft sub is pairwise, so the same sub presented by two tenants must
// resolve to two distinct accounts and never cross over.
func TestLinkOrCreateQualifiesIdentityByTenant(t *testing.T) {
	t.Parallel()
	database := serviceTestDB(t)
	cfg := serviceTestConfig()

	const sharedSub = "pairwise-shared-sub"
	tenants := []struct {
		tenant string
		email  string
	}{
		{tenant: "tenant-a", email: "tenant-a@example.com"},
		{tenant: "tenant-b", email: "tenant-b@example.com"},
	}

	owners := make(map[string]uuid.UUID, len(tenants))
	for _, tt := range tenants {
		sess := loginMicrosoft(t, database, cfg, &UserInfo{
			ProviderID:       "microsoft",
			ProviderTenantID: tt.tenant,
			ProviderUserID:   sharedSub,
			Email:            tt.email,
			EmailVerified:    true,
		})
		owners[tt.tenant] = sess.UserID
	}
	if owners["tenant-a"] == owners["tenant-b"] {
		t.Fatalf("two tenants presenting sub %q resolved the same account %s", sharedSub, owners["tenant-a"])
	}

	var links []db.OAuthAccount
	if err := database.Order("provider_tenant_id").Find(&links).Error; err != nil {
		t.Fatalf("load links: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("oauth links = %d; want one per tenant", len(links))
	}
	for i, tt := range tenants {
		link := links[i]
		if link.ProviderTenantID != tt.tenant || link.ProviderUserID != sharedSub {
			t.Fatalf("link %d keys on (%q, %q); want (%q, %q)", i, link.ProviderTenantID, link.ProviderUserID, tt.tenant, sharedSub)
		}
		if link.UserID != owners[tt.tenant] {
			t.Fatalf("link %d owner = %s; want %s", i, link.UserID, owners[tt.tenant])
		}
	}

	// A repeat login must resolve its own tenant's account, not the neighbour's.
	for _, tt := range tenants {
		sess := loginMicrosoft(t, database, cfg, &UserInfo{
			ProviderID:       "microsoft",
			ProviderTenantID: tt.tenant,
			ProviderUserID:   sharedSub,
			Email:            tt.email,
			EmailVerified:    true,
		})
		if sess.UserID != owners[tt.tenant] {
			t.Fatalf("repeat login in %s resolved %s; want %s", tt.tenant, sess.UserID, owners[tt.tenant])
		}
	}
	if n := countRows(t, database, &db.OAuthAccount{}); n != 2 {
		t.Fatalf("oauth links after repeat logins = %d; want 2", n)
	}
}

// TestOIDFallbackIsTenantScoped pins the legacy fallback: a row keyed by oid in
// one tenant must not be reachable, migrated, or signed in from another.
func TestOIDFallbackIsTenantScoped(t *testing.T) {
	t.Parallel()
	database := serviceTestDB(t)
	cfg := serviceTestConfig()

	const sharedOID = "shared-directory-oid"
	owner := db.User{ID: uuid.New(), Email: "tenant-a@example.com", EmailVerified: true}
	if err := database.Create(&owner).Error; err != nil {
		t.Fatalf("create owner: %v", err)
	}
	legacy := db.OAuthAccount{
		ID:               uuid.New(),
		UserID:           owner.ID,
		ProviderID:       "microsoft",
		ProviderTenantID: "tenant-a",
		ProviderUserID:   sharedOID,
		Email:            owner.Email,
		Verified:         true,
	}
	if err := database.Create(&legacy).Error; err != nil {
		t.Fatalf("create legacy link: %v", err)
	}

	sess := loginMicrosoft(t, database, cfg, &UserInfo{
		ProviderID:       "microsoft",
		ProviderTenantID: "tenant-b",
		ProviderUserID:   "tenant-b-sub",
		Email:            "tenant-b@example.com",
		EmailVerified:    true,
		RawClaims:        map[string]any{"sub": "tenant-b-sub", "oid": sharedOID},
	})
	if sess.UserID == owner.ID {
		t.Fatal("tenant B resolved tenant A's account through the oid fallback")
	}

	var preserved db.OAuthAccount
	if err := database.Where("id = ?", legacy.ID).First(&preserved).Error; err != nil {
		t.Fatalf("load legacy link: %v", err)
	}
	if preserved.ProviderUserID != sharedOID || preserved.UserID != owner.ID {
		t.Fatalf("legacy link mutated to (%q, %s); want (%q, %s)", preserved.ProviderUserID, preserved.UserID, sharedOID, owner.ID)
	}

	var tenantBLinks int64
	if err := database.Model(&db.OAuthAccount{}).
		Where("provider_tenant_id = ? AND provider_user_id = ?", "tenant-b", "tenant-b-sub").
		Count(&tenantBLinks).Error; err != nil {
		t.Fatalf("count tenant B links: %v", err)
	}
	if tenantBLinks != 1 {
		t.Fatalf("tenant B links = %d; want its own identity", tenantBLinks)
	}
}

// TestUntrustedTenantEvictionIsTenantScoped pins the #75 gate under the new key:
// the row deleted for an untrusted tenant is the one that tenant owns, never a
// same-subject row belonging to another tenant.
func TestUntrustedTenantEvictionIsTenantScoped(t *testing.T) {
	t.Parallel()
	database := serviceTestDB(t)
	cfg := serviceTestConfig()

	const sharedSub = "pairwise-shared-sub"
	owner := db.User{ID: uuid.New(), Email: "tenant-a@example.com", EmailVerified: true}
	if err := database.Create(&owner).Error; err != nil {
		t.Fatalf("create owner: %v", err)
	}
	trusted := db.OAuthAccount{
		ID:               uuid.New(),
		UserID:           owner.ID,
		ProviderID:       "microsoft",
		ProviderTenantID: "tenant-a",
		ProviderUserID:   sharedSub,
		Email:            owner.Email,
		Verified:         true,
	}
	if err := database.Create(&trusted).Error; err != nil {
		t.Fatalf("create link: %v", err)
	}
	tenantBOwner := db.User{ID: uuid.New(), Email: "tenant-b@example.com", EmailVerified: true}
	if err := database.Create(&tenantBOwner).Error; err != nil {
		t.Fatalf("create tenant B owner: %v", err)
	}
	untrustedRow := db.OAuthAccount{
		ID:               uuid.New(),
		UserID:           tenantBOwner.ID,
		ProviderID:       "microsoft",
		ProviderTenantID: "tenant-b",
		ProviderUserID:   sharedSub,
		Email:            tenantBOwner.Email,
		Verified:         true,
	}
	if err := database.Create(&untrustedRow).Error; err != nil {
		t.Fatalf("create tenant B link: %v", err)
	}

	svc := NewService(database, session.NewService(database, cfg), map[string]Provider{"microsoft": &stubProvider{
		id: "microsoft",
		info: &UserInfo{
			ProviderID:       "microsoft",
			ProviderTenantID: "tenant-b",
			ProviderUserID:   sharedSub,
			Email:            owner.Email,
			EmailVerified:    true,
			RawClaims:        map[string]any{"untrusted_tenant": true},
		},
	}}, cfg)
	state, cookie := mustInitiate(t, svc, cfg, "microsoft")
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft/callback", nil)
	req.AddCookie(cookie)

	sess, _, _, err := svc.HandleCallback(context.Background(), httptest.NewRecorder(), req, "microsoft", "code", state, db.SessionTypeCookie)
	if sess != nil {
		t.Fatalf("session issued for an untrusted tenant: %+v", sess)
	}
	if !errors.Is(err, errors.ErrOAuthTenantInvalid) {
		t.Fatalf("expected ErrOAuthTenantInvalid, got %v", err)
	}

	var evicted int64
	if err := database.Model(&db.OAuthAccount{}).
		Where("provider_tenant_id = ? AND provider_user_id = ?", "tenant-b", sharedSub).
		Count(&evicted).Error; err != nil {
		t.Fatalf("count tenant B links: %v", err)
	}
	if evicted != 0 {
		t.Fatalf("tenant B links = %d; an untrusted tenant must lose the row it owns", evicted)
	}

	var survived int64
	if err := database.Model(&db.OAuthAccount{}).
		Where("provider_tenant_id = ? AND provider_user_id = ?", "tenant-a", sharedSub).
		Count(&survived).Error; err != nil {
		t.Fatalf("count tenant A links: %v", err)
	}
	if survived != 1 {
		t.Fatalf("tenant A links = %d; an untrusted tenant must not delete another tenant's row", survived)
	}
}
