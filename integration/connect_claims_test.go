//go:build integration

package integration

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kaiizer777/go-auth/db"
)

// TestConnect_ImportsLegacyClaimsOnUpgrade pins the connect-time import: 000014
// ships an empty claim table, so a SQL deployment upgrading a database with
// existing accounts must import those addresses when it connects. Skipping the
// call leaves exactly the silent unprotected state #94 is about.
func TestConnect_ImportsLegacyClaimsOnUpgrade(t *testing.T) {
	dbURL := resolveDatabaseURL()

	// First connect brings the schema to head. The claim table is empty, so there
	// is nothing to import yet.
	initial, err := db.Connect(testConfig(dbURL))
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: initial connect failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	_ = initial.Exec("TRUNCATE TABLE sessions, verification_tokens, password_reset_tokens, oauth_accounts, totp_secrets, totp_used_codes, two_factor_tokens, claimed_emails, users CASCADE")
	if rawDB, derr := initial.DB(); derr == nil {
		_ = rawDB.Close()
	}

	// Legacy rows written before the claim table existed: mixed case and a
	// leading tab that only Go's TrimSpace strips.
	ownerID, holderID := uuid.New(), uuid.New()
	seedDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open seed connection: %v", err)
	}
	if _, err := seedDB.Exec(`INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, 'hash', FALSE)`,
		ownerID, "  Legacy.Owner@Example.Test\t"); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if _, err := seedDB.Exec(`INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, 'hash', TRUE)`,
		holderID, "legacy-holder@example.test"); err != nil {
		t.Fatalf("seed holder: %v", err)
	}
	if _, err := seedDB.Exec(`INSERT INTO oauth_accounts (id, user_id, provider_id, provider_tenant_id, provider_user_id, email, verified)
		VALUES ($1, $2, 'google', '', 'sub-legacy-connect', 'LEGACY.HOLDER@example.test', TRUE)`, uuid.New(), holderID); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	_ = seedDB.Close()

	upgraded, err := db.Connect(testConfig(dbURL))
	if err != nil {
		t.Fatalf("upgrade connect failed: %v", err)
	}
	t.Cleanup(func() {
		if rawDB, derr := upgraded.DB(); derr == nil {
			_ = rawDB.Close()
		}
	})

	var claims []db.ClaimedEmail
	if err := upgraded.Order("email").Find(&claims).Error; err != nil {
		t.Fatalf("load claims: %v", err)
	}
	got := make(map[string]db.ClaimedEmail, len(claims))
	for _, claim := range claims {
		got[claim.Email] = claim
	}
	for _, tc := range []struct {
		raw      string
		owner    uuid.UUID
		verified bool
	}{
		{raw: " legacy.owner@example.test", owner: ownerID, verified: false},
		{raw: "legacy-holder@example.test", owner: holderID, verified: true},
	} {
		key := db.NormalizeEmail(tc.raw)
		claim, ok := got[key]
		if !ok {
			t.Fatalf("connect left %q unclaimed; stored keys = %v", key, claims)
		}
		if claim.OwnerUserID != tc.owner || claim.Verified != tc.verified {
			t.Errorf("claim %q = (%v, %v); want (%v, %v)", key, claim.OwnerUserID, claim.Verified, tc.owner, tc.verified)
		}
	}

	if err := upgraded.Exec(`DELETE FROM oauth_accounts WHERE user_id = $1`, holderID).Error; err != nil {
		t.Fatalf("remove seeded link: %v", err)
	}
	if err := upgraded.Exec(`DELETE FROM users WHERE id IN ($1, $2)`, ownerID, holderID).Error; err != nil {
		t.Fatalf("remove seeded users: %v", err)
	}
}

// TestConnect_ImportsRowsAddedAfterTheFirstImport pins the absence of an
// "already imported" gate: an address written after a successful import must be
// picked up on the next connect, or it stays unclaimed with no way to notice.
func TestConnect_ImportsRowsAddedAfterTheFirstImport(t *testing.T) {
	dbURL := resolveDatabaseURL()

	initial, err := db.Connect(testConfig(dbURL))
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: initial connect failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	_ = initial.Exec("TRUNCATE TABLE sessions, verification_tokens, password_reset_tokens, oauth_accounts, totp_secrets, totp_used_codes, two_factor_tokens, claimed_emails, users CASCADE")
	if rawDB, derr := initial.DB(); derr == nil {
		_ = rawDB.Close()
	}

	earlyID, lateID := uuid.New(), uuid.New()
	seedUser := func(id uuid.UUID, email string) {
		t.Helper()
		conn, cerr := sql.Open("pgx", dbURL)
		if cerr != nil {
			t.Fatalf("open seed connection: %v", cerr)
		}
		defer func() { _ = conn.Close() }()
		if _, ierr := conn.Exec(`INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, 'hash', TRUE)`, id, email); ierr != nil {
			t.Fatalf("seed user %q: %v", email, ierr)
		}
	}
	seedUser(earlyID, "early-connect@example.test")

	first, err := db.Connect(testConfig(dbURL))
	if err != nil {
		t.Fatalf("first import connect failed: %v", err)
	}
	if rawDB, derr := first.DB(); derr == nil {
		_ = rawDB.Close()
	}

	seedUser(lateID, " Late.Connect@Example.Test ")

	second, err := db.Connect(testConfig(dbURL))
	if err != nil {
		t.Fatalf("second connect failed: %v", err)
	}
	t.Cleanup(func() {
		if rawDB, derr := second.DB(); derr == nil {
			_ = rawDB.Close()
		}
	})

	var late db.ClaimedEmail
	if err := second.Where("email = ?", db.NormalizeEmail(" Late.Connect@Example.Test ")).First(&late).Error; err != nil {
		t.Fatalf("address written after the first import stayed unclaimed: %v", err)
	}
	if late.OwnerUserID != lateID || !late.Verified {
		t.Errorf("late claim = %+v; want holder %v, verified", late, lateID)
	}

	if err := second.Exec(`DELETE FROM users WHERE id IN ($1, $2)`, earlyID, lateID).Error; err != nil {
		t.Fatalf("remove seeded users: %v", err)
	}
}

// TestConnect_FailsOnConflictingLegacyClaims pins the failure contract: when the
// import cannot resolve who owns an address, the connection fails instead of
// returning a store that silently lost the protection.
func TestConnect_FailsOnConflictingLegacyClaims(t *testing.T) {
	dbURL := resolveDatabaseURL()

	initial, err := db.Connect(testConfig(dbURL))
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: initial connect failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	_ = initial.Exec("TRUNCATE TABLE sessions, verification_tokens, password_reset_tokens, oauth_accounts, totp_secrets, totp_used_codes, two_factor_tokens, claimed_emails, users CASCADE")
	if rawDB, derr := initial.DB(); derr == nil {
		_ = rawDB.Close()
	}

	ownerID, rivalID := uuid.New(), uuid.New()
	seedDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open seed connection: %v", err)
	}
	t.Cleanup(func() {
		cleanupDB, cerr := sql.Open("pgx", dbURL)
		if cerr != nil {
			return
		}
		defer func() { _ = cleanupDB.Close() }()
		_, _ = cleanupDB.Exec(`DELETE FROM oauth_accounts WHERE user_id IN ($1, $2)`, ownerID, rivalID)
		_, _ = cleanupDB.Exec(`DELETE FROM users WHERE id IN ($1, $2)`, ownerID, rivalID)
	})
	if _, err := seedDB.Exec(`INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, 'conflict@example.test', 'hash', TRUE)`, ownerID); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if _, err := seedDB.Exec(`INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, 'conflict-rival@example.test', 'hash', TRUE)`, rivalID); err != nil {
		t.Fatalf("seed rival: %v", err)
	}
	if _, err := seedDB.Exec(`INSERT INTO oauth_accounts (id, user_id, provider_id, provider_tenant_id, provider_user_id, email, verified)
		VALUES ($1, $2, 'google', '', 'sub-conflict-connect', 'CONFLICT@example.test', TRUE)`, uuid.New(), rivalID); err != nil {
		t.Fatalf("seed colliding link: %v", err)
	}
	_ = seedDB.Close()

	_, err = db.Connect(testConfig(dbURL))
	if err == nil {
		t.Fatal("connect succeeded over a cross-account claim conflict; it must fail")
	}
	for _, want := range []string{"backfill aborted", "conflict@example.test", ownerID.String(), rivalID.String()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("connect error %q does not mention %q", err.Error(), want)
		}
	}
}
