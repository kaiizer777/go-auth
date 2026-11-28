package db

import (
	"context"
	"fmt"
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

// claimTestID returns a UUID whose string form sorts in numeric order, so paging
// by primary key visits the fixtures in the order they were seeded.
func claimTestID(i int) uuid.UUID {
	return uuid.MustParse(fmt.Sprintf("00000000-0000-0000-0000-%012d", i))
}

// seedLegacyUser inserts a row without the store, standing in for an address
// written before the claim table existed: its case and padding are whatever the
// caller supplied.
func seedLegacyUser(t *testing.T, database *gorm.DB, id uuid.UUID, email string, verified bool) User {
	t.Helper()
	user := User{ID: id, Email: email, EmailVerified: verified}
	if err := database.Create(&user).Error; err != nil {
		t.Fatalf("seed user %q: %v", email, err)
	}
	return user
}

// seedLegacyLink inserts a provider row whose address is not its owner's own.
func seedLegacyLink(t *testing.T, database *gorm.DB, id, userID uuid.UUID, email string, verified bool) {
	t.Helper()
	link := OAuthAccount{
		ID:             id,
		UserID:         userID,
		ProviderID:     "google",
		ProviderUserID: "sub-" + id.String(),
		Email:          email,
		Verified:       verified,
	}
	if err := database.Create(&link).Error; err != nil {
		t.Fatalf("seed link %q: %v", email, err)
	}
}

func loadClaim(t *testing.T, database *gorm.DB, email string) *ClaimedEmail {
	t.Helper()
	var claim ClaimedEmail
	if err := database.Where("email = ?", NormalizeEmail(email)).First(&claim).Error; err != nil {
		t.Fatalf("load claim %q: %v", email, err)
	}
	return &claim
}

func countClaims(t *testing.T, database *gorm.DB) int64 {
	t.Helper()
	var claims int64
	if err := database.Model(&ClaimedEmail{}).Count(&claims).Error; err != nil {
		t.Fatalf("count claims: %v", err)
	}
	return claims
}

// TestBackfillClaimedEmails_WritesTheApplicationKey seeds case- and
// whitespace-variant legacy rows and proves the imported keys are exactly what the
// write paths look up, that the verified flag follows the holders, and that a
// second run changes nothing.
func TestBackfillClaimedEmails_WritesTheApplicationKey(t *testing.T) {
	database := setupClaimBackfillDB(t)
	ctx := context.Background()

	alice := seedLegacyUser(t, database, uuid.New(), "  Alice@Example.COM\t", false)
	seedLegacyLink(t, database, uuid.New(), alice.ID, "ALICE@example.com", false)
	bob := seedLegacyUser(t, database, uuid.New(), "bob@example.com", true)
	seedLegacyLink(t, database, uuid.New(), bob.ID, " BOB@Example.com ", true)
	carol := seedLegacyUser(t, database, uuid.New(), "carol@example.com", false)
	seedLegacyLink(t, database, uuid.New(), carol.ID, "", false)

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
		claim := loadClaim(t, database, tc.lookup)
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

// TestBackfillClaimedEmails_PagesAcrossBatches seeds more than twice the page size
// in both sources and proves every address is imported, then that a second run
// changes nothing.
func TestBackfillClaimedEmails_PagesAcrossBatches(t *testing.T) {
	database := setupClaimBackfillDB(t)
	ctx := context.Background()

	const rows = 2*claimBackfillBatchSize + 5
	users := make([]User, 0, rows)
	links := make([]OAuthAccount, 0, rows)
	for i := 0; i < rows; i++ {
		users = append(users, User{
			ID:    claimTestID(i),
			Email: fmt.Sprintf("user%04d@example.com", i),
		})
		links = append(links, OAuthAccount{
			ID:             claimTestID(i),
			UserID:         claimTestID(i),
			ProviderID:     "google",
			ProviderUserID: fmt.Sprintf("sub-%04d", i),
			Email:          fmt.Sprintf("alias%04d@example.com", i),
			Verified:       i%2 == 0,
		})
	}
	if err := database.CreateInBatches(&users, 200).Error; err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if err := database.CreateInBatches(&links, 200).Error; err != nil {
		t.Fatalf("seed links: %v", err)
	}

	result, err := BackfillClaimedEmails(ctx, database)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if result.Claims != 2*rows {
		t.Fatalf("claims written = %d; want %d", result.Claims, 2*rows)
	}
	if got := countClaims(t, database); got != int64(2*rows) {
		t.Fatalf("claim rows = %d; want %d", got, 2*rows)
	}
	// A row from the last page of each source is present, so paging reached the end.
	if claim := loadClaim(t, database, fmt.Sprintf("user%04d@example.com", rows-1)); claim.OwnerUserID != claimTestID(rows-1) {
		t.Fatalf("last user page claim owner = %v", claim.OwnerUserID)
	}
	if claim := loadClaim(t, database, fmt.Sprintf("alias%04d@example.com", rows-1)); claim.OwnerUserID != claimTestID(rows-1) {
		t.Fatalf("last link page claim owner = %v", claim.OwnerUserID)
	}

	again, err := BackfillClaimedEmails(ctx, database)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if again.Claims != 0 || again.Promoted != 0 {
		t.Errorf("second run wrote claims=%d promoted=%d; want an idempotent no-op", again.Claims, again.Promoted)
	}
	if got := countClaims(t, database); got != int64(2*rows) {
		t.Fatalf("claim rows after second run = %d; want %d", got, 2*rows)
	}
}

// TestBackfillClaimedEmails_MidRunFailureWritesNothingAtTheBatchBoundary pins the
// per-page transaction: pages committed before the failure stay, the failing page
// commits nothing, and a re-run finishes the import.
func TestBackfillClaimedEmails_MidRunFailureWritesNothingAtTheBatchBoundary(t *testing.T) {
	database := setupClaimBackfillDB(t)
	ctx := context.Background()

	const rows = 2*claimBackfillBatchSize + 5
	users := make([]User, 0, rows)
	for i := 0; i < rows; i++ {
		users = append(users, User{
			ID:    claimTestID(i),
			Email: fmt.Sprintf("user%04d@example.com", i),
		})
	}
	if err := database.CreateInBatches(&users, 200).Error; err != nil {
		t.Fatalf("seed users: %v", err)
	}
	// The rejected key sits in the second page, so the first page is committed
	// before the failure and the second must roll back as a unit.
	const boom = "user0600@example.com"
	if err := database.Exec(`CREATE TRIGGER claim_insert_boom BEFORE INSERT ON claimed_emails
		WHEN NEW.email = '` + boom + `'
		BEGIN
			SELECT RAISE(ABORT, 'injected claim failure');
		END`).Error; err != nil {
		t.Fatalf("install trigger: %v", err)
	}

	if _, err := BackfillClaimedEmails(ctx, database); err == nil {
		t.Fatal("backfill reported success while a claim insert was rejected")
	}
	if got := countClaims(t, database); got != claimBackfillBatchSize {
		t.Fatalf("claim rows after the failed run = %d; want the first page only (%d)", got, claimBackfillBatchSize)
	}
	var boomClaims int64
	if err := database.Model(&ClaimedEmail{}).Where("email = ?", boom).Count(&boomClaims).Error; err != nil {
		t.Fatalf("count boom claim: %v", err)
	}
	if boomClaims != 0 {
		t.Fatal("the failing page left a claim behind")
	}

	if err := database.Exec(`DROP TRIGGER claim_insert_boom`).Error; err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	result, err := BackfillClaimedEmails(ctx, database)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if result.Claims != rows-claimBackfillBatchSize {
		t.Fatalf("retry claimed %d addresses; want %d", result.Claims, rows-claimBackfillBatchSize)
	}
	if got := countClaims(t, database); got != int64(rows) {
		t.Fatalf("claim rows after the retry = %d; want %d", got, rows)
	}
	loadClaim(t, database, boom)
}

// TestBackfillClaimedEmails_AbortsOnCrossAccountConflict pins the policy: a
// cross-account address that already has a claim aborts the page, names both
// accounts, and never overwrites the holder.
func TestBackfillClaimedEmails_AbortsOnCrossAccountConflict(t *testing.T) {
	database := setupClaimBackfillDB(t)
	ctx := context.Background()

	dave := seedLegacyUser(t, database, claimTestID(0), "dave@example.com", true)
	rival := seedLegacyUser(t, database, claimTestID(1), "rival@example.com", true)
	seedLegacyLink(t, database, claimTestID(2), rival.ID, " Dave@Example.com", true)

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
	claim := loadClaim(t, database, "dave@example.com")
	if claim.OwnerUserID != dave.ID {
		t.Fatalf("claim owner = %v; the existing holder %v must not be overwritten", claim.OwnerUserID, dave.ID)
	}
}

// TestBackfillClaimedEmails_ReportsEveryConflictInThePage proves the page is
// validated before it is written: an error lists all conflicting addresses, not
// just the first one hit.
func TestBackfillClaimedEmails_ReportsEveryConflictInThePage(t *testing.T) {
	database := setupClaimBackfillDB(t)
	ctx := context.Background()

	first := seedLegacyUser(t, database, claimTestID(0), "first@example.com", true)
	second := seedLegacyUser(t, database, claimTestID(1), "second@example.com", true)
	holder := seedLegacyUser(t, database, claimTestID(2), "holder@example.com", true)
	if err := ClaimWithin(ctx, database, "first@example.com", holder.ID, true); err != nil {
		t.Fatalf("seed claim: %v", err)
	}
	if err := ClaimWithin(ctx, database, "second@example.com", holder.ID, true); err != nil {
		t.Fatalf("seed claim: %v", err)
	}

	_, err := BackfillClaimedEmails(ctx, database)
	if err == nil {
		t.Fatal("backfill accepted two addresses held by another account")
	}
	for _, want := range []string{"first@example.com", "second@example.com", first.ID.String(), second.ID.String(), holder.ID.String()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
	for _, addr := range []string{"first@example.com", "second@example.com"} {
		if claim := loadClaim(t, database, addr); claim.OwnerUserID != holder.ID {
			t.Errorf("claim %q owner = %v; the existing holder must be left untouched", addr, claim.OwnerUserID)
		}
	}
}

// TestBackfillClaimedEmails_ImportsAddressesAddedAfterASuccessfulRun pins why the
// utility is safe to re-run: a row written after an import completed is picked up
// by the next run instead of staying unclaimed.
func TestBackfillClaimedEmails_ImportsAddressesAddedAfterASuccessfulRun(t *testing.T) {
	database := setupClaimBackfillDB(t)
	ctx := context.Background()

	seedLegacyUser(t, database, claimTestID(0), "early@example.com", false)
	if _, err := BackfillClaimedEmails(ctx, database); err != nil {
		t.Fatalf("first run: %v", err)
	}
	late := seedLegacyUser(t, database, claimTestID(1), "late@example.com", true)

	if _, err := BackfillClaimedEmails(ctx, database); err != nil {
		t.Fatalf("second run: %v", err)
	}
	claim := loadClaim(t, database, late.Email)
	if claim.OwnerUserID != late.ID || !claim.Verified {
		t.Fatalf("claim = %+v; want holder %v, verified", claim, late.ID)
	}
}
