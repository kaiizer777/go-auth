package db

import (
	"context"
	"strings"
	"testing"

	gormsqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupClaimBackfillDB(t *testing.T) *gorm.DB {
	t.Helper()
	database, err := gorm.Open(gormsqlite.Open("file:claim_backfill_"+uuid.New().String()+"?mode=memory&cache=shared"),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(&User{}, &OAuthAccount{}, &ClaimedEmail{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return database
}

// seedLegacyUser inserts a row without the store, standing in for an address
// written before the claim table existed: its case and padding are whatever the
// caller supplied.
func seedLegacyUser(t *testing.T, database *gorm.DB, email string, verified bool) User {
	t.Helper()
	user := User{ID: uuid.New(), Email: email, EmailVerified: verified}
	if err := database.Create(&user).Error; err != nil {
		t.Fatalf("seed user %q: %v", email, err)
	}
	return user
}

// seedLegacyLink inserts a provider row whose address is not its owner's own.
func seedLegacyLink(t *testing.T, database *gorm.DB, userID uuid.UUID, email string, verified bool) {
	t.Helper()
	link := OAuthAccount{
		ID:             uuid.New(),
		UserID:         userID,
		ProviderID:     "google",
		ProviderUserID: "sub-" + uuid.New().String(),
		Email:          email,
		Verified:       verified,
	}
	if err := database.Create(&link).Error; err != nil {
		t.Fatalf("seed link %q: %v", email, err)
	}
}

// TestBackfillClaimedEmails_WritesTheApplicationKey seeds case- and
// whitespace-variant legacy rows and proves the imported keys are exactly what the
// write paths look up, that the verified flag follows the holders, and that a
// second run changes nothing.
func TestBackfillClaimedEmails_WritesTheApplicationKey(t *testing.T) {
	database := setupClaimBackfillDB(t)
	ctx := context.Background()

	alice := seedLegacyUser(t, database, "  Alice@Example.COM\t", false)
	seedLegacyLink(t, database, alice.ID, "ALICE@example.com", false)
	bob := seedLegacyUser(t, database, "bob@example.com", true)
	seedLegacyLink(t, database, bob.ID, " BOB@Example.com ", true)
	carol := seedLegacyUser(t, database, "carol@example.com", false)
	seedLegacyLink(t, database, carol.ID, "", false)

	if _, err := BackfillClaimedEmails(ctx, database); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	for _, tc := range []struct {
		lookup   string
		owner    uuid.UUID
		verified bool
	}{
		{lookup: " alice@example.com", owner: alice.ID, verified: false},
		{lookup: "Bob@Example.Com", owner: bob.ID, verified: true},
		{lookup: "CAROL@example.com", owner: carol.ID, verified: false},
	} {
		claim, err := readClaim(ctx, database, NormalizeEmail(tc.lookup))
		if err != nil {
			t.Fatalf("claim for %q: %v", tc.lookup, err)
		}
		if claim.OwnerUserID != tc.owner || claim.Verified != tc.verified {
			t.Errorf("claim for %q = (%v, %v); want (%v, %v)",
				tc.lookup, claim.OwnerUserID, claim.Verified, tc.owner, tc.verified)
		}
	}
	// The stored key is the application's key, not the raw column value.
	var rows []ClaimedEmail
	if err := database.Order("email").Find(&rows).Error; err != nil {
		t.Fatalf("load claims: %v", err)
	}
	got := make([]string, 0, len(rows))
	for _, row := range rows {
		got = append(got, row.Email)
	}
	want := []string{"alice@example.com", "bob@example.com", "carol@example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("claim keys = %v; want %v", got, want)
	}

	result, err := BackfillClaimedEmails(ctx, database)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if result.Claims != 0 || result.Promoted != 0 {
		t.Errorf("second run wrote claims=%d promoted=%d; want an idempotent no-op", result.Claims, result.Promoted)
	}
}

// TestBackfillClaimedEmails_AbortsOnCrossAccountConflict pins the policy: two
// accounts parsing to one address block the run and are named, and nothing is
// written, so no account silently loses its attribution.
func TestBackfillClaimedEmails_AbortsOnCrossAccountConflict(t *testing.T) {
	database := setupClaimBackfillDB(t)
	ctx := context.Background()

	dave := seedLegacyUser(t, database, "dave@example.com", true)
	rival := seedLegacyUser(t, database, "rival@example.com", true)
	seedLegacyLink(t, database, rival.ID, " Dave@Example.com", true)

	_, err := BackfillClaimedEmails(ctx, database)
	if err == nil {
		t.Fatal("backfill accepted an address held by two accounts")
	}
	msg := err.Error()
	for _, want := range []string{"backfill aborted", "dave@example.com", dave.ID.String(), rival.ID.String()} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
	var claims int64
	if err := database.Model(&ClaimedEmail{}).Count(&claims).Error; err != nil {
		t.Fatalf("count claims: %v", err)
	}
	if claims != 0 {
		t.Fatalf("claims written despite the conflict = %d; want 0", claims)
	}
}

// TestBackfillClaimedEmails_AbortsOnForeignExistingClaim covers the upgrade where
// a claim row already belongs to a third account: the run must refuse it rather
// than overwrite or ignore it.
func TestBackfillClaimedEmails_AbortsOnForeignExistingClaim(t *testing.T) {
	database := setupClaimBackfillDB(t)
	ctx := context.Background()

	erin := seedLegacyUser(t, database, "erin@example.com", false)
	holder := seedLegacyUser(t, database, "holder@example.com", true)
	if err := ClaimWithin(ctx, database, "erin@example.com", holder.ID, true); err != nil {
		t.Fatalf("seed claim: %v", err)
	}

	_, err := BackfillClaimedEmails(ctx, database)
	if err == nil {
		t.Fatal("backfill ignored a pre-existing claim held by another account")
	}
	if !strings.Contains(err.Error(), erin.ID.String()) || !strings.Contains(err.Error(), holder.ID.String()) {
		t.Errorf("error %q must name both competing accounts", err)
	}
	claim, gerr := readClaim(ctx, database, "erin@example.com")
	if gerr != nil {
		t.Fatalf("load claim: %v", gerr)
	}
	if claim.OwnerUserID != holder.ID {
		t.Fatalf("claim owner = %v; the existing holder must be left untouched", claim.OwnerUserID)
	}
}

// TestImportClaimsAtConnect_SkipsWhenClaimsExist pins the connect gate: a
// non-empty claim table means the import already ran (or this version wrote it),
// so the connect path must not re-scan.
func TestImportClaimsAtConnect_SkipsWhenClaimsExist(t *testing.T) {
	database := setupClaimBackfillDB(t)
	ctx := context.Background()

	owner := seedLegacyUser(t, database, "present@example.com", true)
	if err := ClaimWithin(ctx, database, "present@example.com", owner.ID, true); err != nil {
		t.Fatalf("seed claim: %v", err)
	}
	legacy := seedLegacyUser(t, database, "legacy@example.com", false)

	result, err := importClaimsAtConnect(ctx, database)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.Claims != 0 {
		t.Fatalf("import ran on a non-empty table and wrote %d claims", result.Claims)
	}
	var claims int64
	if err := database.Model(&ClaimedEmail{}).Where("email = ?", legacy.Email).Count(&claims).Error; err != nil {
		t.Fatalf("count claims: %v", err)
	}
	if claims != 0 {
		t.Fatal("connect gate imported a row into a table that was already populated")
	}
}
