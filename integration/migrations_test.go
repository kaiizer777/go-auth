//go:build integration

package integration

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	pgmigrate "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kaiizer777/go-auth/db"
)

// newMigrator creates a golang-migrate instance backed by embedded migrations and pgx driver.
func newMigrator(t *testing.T, dbURL string) (*migrate.Migrate, *sql.DB) {
	t.Helper()

	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("failed to open sql connection: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		_ = sqlDB.Close()
		t.Fatalf("failed to checkout conn: %v", err)
	}

	driver, err := pgmigrate.WithConnection(ctx, conn, &pgmigrate.Config{})
	if err != nil {
		_ = conn.Close()
		_ = sqlDB.Close()
		t.Fatalf("failed to init postgres driver: %v", err)
	}

	srcDriver, err := iofs.New(db.MigrationsFS(), "migrations")
	if err != nil {
		_ = driver.Close()
		_ = sqlDB.Close()
		t.Fatalf("failed to init source driver: %v", err)
	}

	m, err := migrate.NewWithInstance("iofs", srcDriver, "pgx", driver)
	if err != nil {
		_ = srcDriver.Close()
		_ = driver.Close()
		_ = sqlDB.Close()
		t.Fatalf("failed to init migrator: %v", err)
	}

	return m, sqlDB
}

func TestMigrations_Lifecycle(t *testing.T) {
	dbURL := resolveDatabaseURL()

	// 1. Verify connectivity
	testDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: failed to open postgres connection: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := testDB.PingContext(pingCtx); err != nil {
		_ = testDB.Close()
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: PostgreSQL connection failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	_ = testDB.Close()

	// 2. Run initial Up
	m, sqlDB := newMigrator(t, dbURL)
	defer func() {
		_, _ = m.Close()
		_ = sqlDB.Close()
	}()

	// Up may return ErrNoChange if already applied
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("m.Up() failed: %v", err)
	}

	// 3. Up idempotency: running Up again must return ErrNoChange
	if err := m.Up(); err != migrate.ErrNoChange {
		t.Fatalf("expected ErrNoChange on re-running Up, got: %v", err)
	}

	// Clean tables before downing all migrations to ensure no non-zero credential_version rows block 000006 down
	_, _ = sqlDB.Exec("TRUNCATE TABLE sessions, verification_tokens, password_reset_tokens, oauth_accounts, totp_secrets, totp_used_codes, two_factor_tokens, claimed_emails, users CASCADE")

	// 4. Down all migrations cleanly
	if err := m.Down(); err != nil {
		t.Fatalf("m.Down() failed: %v", err)
	}

	// Verify tables dropped
	var tableCount int
	err = sqlDB.QueryRow(`
		SELECT COUNT(*) FROM information_schema.tables 
		WHERE table_schema = 'public' 
		  AND table_name IN ('users', 'sessions', 'verification_tokens', 'password_reset_tokens', 'oauth_accounts', 'totp_secrets', 'totp_used_codes', 'two_factor_tokens', 'claimed_emails')
	`).Scan(&tableCount)
	if err != nil {
		t.Fatalf("querying tables failed: %v", err)
	}
	if tableCount != 0 {
		t.Fatalf("expected 0 application tables after Down, found %d", tableCount)
	}

	// 5. Re-run Up from scratch to verify schema can be reapplied
	if err := m.Up(); err != nil {
		t.Fatalf("re-running m.Up() after Down failed: %v", err)
	}

	err = sqlDB.QueryRow(`
		SELECT COUNT(*) FROM information_schema.tables 
		WHERE table_schema = 'public' 
		  AND table_name IN ('users', 'sessions', 'verification_tokens', 'password_reset_tokens', 'oauth_accounts', 'totp_secrets', 'totp_used_codes', 'two_factor_tokens', 'claimed_emails')
	`).Scan(&tableCount)
	if err != nil {
		t.Fatalf("querying tables failed: %v", err)
	}
	if tableCount != 9 {
		t.Fatalf("expected 9 application tables after re-Up, found %d", tableCount)
	}
}

// TestMigrations_Claim000014BackfillAndDown pins the claim table on the real
// dialect: the down path drops it (so no stale claim can block an address), and a
// re-applied up rebuilds it from users.email and oauth_accounts.email with the
// holder and the proved flag derived from those rows.
func TestMigrations_Claim000014BackfillAndDown(t *testing.T) {
	dbURL := resolveDatabaseURL()
	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: failed to open postgres connection: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	defer func() { _ = sqlDB.Close() }()
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: PostgreSQL connection failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}

	m, migrateDB := newMigrator(t, dbURL)
	defer func() {
		_, _ = m.Close()
		_ = migrateDB.Close()
	}()
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("m.Up() failed: %v", err)
	}
	_, _ = migrateDB.Exec("TRUNCATE TABLE sessions, verification_tokens, password_reset_tokens, oauth_accounts, totp_secrets, totp_used_codes, two_factor_tokens, claimed_emails, users CASCADE")

	ownerID := uuid.New()
	linkerID := uuid.New()
	if _, err := migrateDB.Exec(`INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, 'hash', TRUE)`,
		ownerID, "claim-owner@example.test"); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if _, err := migrateDB.Exec(`INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, 'hash', FALSE)`,
		linkerID, "claim-linker@example.test"); err != nil {
		t.Fatalf("seed linker: %v", err)
	}
	// A link whose address is not its owner's own address, and which the provider
	// attested: the claim it produces is verified.
	if _, err := migrateDB.Exec(`INSERT INTO oauth_accounts (id, user_id, provider_id, provider_tenant_id, provider_user_id, email, verified)
		VALUES ($1, $2, 'google', '', 'sub-claim', $3, TRUE)`, uuid.New(), linkerID, "claim-link@example.test"); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	if err := m.Steps(-1); err != nil {
		t.Fatalf("000014 down failed: %v", err)
	}
	var exists bool
	if err := migrateDB.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'claimed_emails')`).Scan(&exists); err != nil {
		t.Fatalf("query table: %v", err)
	}
	if exists {
		t.Fatal("000014 down left claimed_emails in place")
	}

	if err := m.Up(); err != nil {
		t.Fatalf("re-applying 000014 failed: %v", err)
	}
	for _, tc := range []struct {
		email    string
		owner    uuid.UUID
		verified bool
	}{
		{email: "claim-owner@example.test", owner: ownerID, verified: true},
		{email: "claim-link@example.test", owner: linkerID, verified: true},
	} {
		var gotOwner uuid.UUID
		var gotVerified bool
		if err := migrateDB.QueryRow(`SELECT owner_user_id, verified FROM claimed_emails WHERE email = $1`, tc.email).
			Scan(&gotOwner, &gotVerified); err != nil {
			t.Fatalf("claim for %s: %v", tc.email, err)
		}
		if gotOwner != tc.owner || gotVerified != tc.verified {
			t.Errorf("claim for %s = (%v, %v); want (%v, %v)", tc.email, gotOwner, gotVerified, tc.owner, tc.verified)
		}
	}
	var claimsFromUnverifiedAccount int
	if err := migrateDB.QueryRow(`SELECT COUNT(*) FROM claimed_emails WHERE email = 'claim-linker@example.test'`).Scan(&claimsFromUnverifiedAccount); err != nil {
		t.Fatalf("count claim: %v", err)
	}
	if claimsFromUnverifiedAccount != 1 {
		t.Fatalf("unverified account claims = %d; want 1", claimsFromUnverifiedAccount)
	}
	// Leave the shared database as this test found it: the next migration test
	// only rolls back to 000007 cleanly when oauth_accounts is empty.
	if _, err := migrateDB.Exec(`DELETE FROM oauth_accounts WHERE user_id IN ($1, $2)`, ownerID, linkerID); err != nil {
		t.Fatalf("remove seeded links: %v", err)
	}
	if _, err := migrateDB.Exec(`DELETE FROM users WHERE id IN ($1, $2)`, ownerID, linkerID); err != nil {
		t.Fatalf("remove seeded users: %v", err)
	}
}

func TestMigrations_DownRefusedOnSeededDB(t *testing.T) {
	dbURL := resolveDatabaseURL()

	testDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: failed to open postgres connection: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := testDB.PingContext(pingCtx); err != nil {
		_ = testDB.Close()
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: PostgreSQL connection failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	_ = testDB.Close()

	m, sqlDB := newMigrator(t, dbURL)
	defer func() {
		_, _ = m.Close()
		_ = sqlDB.Close()
	}()

	if err := m.Migrate(7); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("m.Migrate(7) failed: %v", err)
	}

	if _, err := sqlDB.Exec(`INSERT INTO users (email, password_hash, credential_version) VALUES ('down-refusal@example.com', 'hash', 1)`); err != nil {
		t.Fatalf("failed to seed versioned user: %v", err)
	}
	// A linked OAuth identity is the data actually at risk: users rows alone
	// no longer block the rollback.
	if _, err := sqlDB.Exec(`INSERT INTO oauth_accounts (user_id, provider_id, provider_user_id, email) SELECT id, 'google', 'down-refusal-sub', 'down-refusal@example.com' FROM users WHERE email = 'down-refusal@example.com'`); err != nil {
		t.Fatalf("failed to seed linked oauth account: %v", err)
	}

	err = m.Steps(-1)
	if err == nil {
		t.Fatal("expected 000007 down to refuse on linked account, got nil")
	}
	if !strings.Contains(err.Error(), "down refused") {
		t.Fatalf("expected down-refused error, got: %v", err)
	}

	// The refused down records version 6 dirty and leaves the driver's
	// connection unusable for unlock, so recover on a fresh migrator: the
	// script rolled back, the schema is still at 7, and force 7 re-pins it
	// clean. The seed row is removed so the shared DB stays empty.
	_, _ = m.Close()
	_ = sqlDB.Close()

	m2, sqlDB2 := newMigrator(t, dbURL)
	defer func() {
		_, _ = m2.Close()
		_ = sqlDB2.Close()
	}()

	if verr, ddirty, verr2 := m2.Version(); verr2 != nil || verr != 6 || !ddirty {
		t.Fatalf("expected version 6 dirty after refusal, got version=%d dirty=%v err=%v", verr, ddirty, verr2)
	}
	if ferr := m2.Force(7); ferr != nil {
		t.Fatalf("m2.Force(7) failed: %v", ferr)
	}
	if _, err := sqlDB2.Exec(`DELETE FROM oauth_accounts WHERE provider_user_id = 'down-refusal-sub'`); err != nil {
		t.Fatalf("failed to remove seed link row: %v", err)
	}
	if _, err := sqlDB2.Exec(`DELETE FROM users WHERE email = 'down-refusal@example.com'`); err != nil {
		t.Fatalf("failed to remove seed row: %v", err)
	}
	if verr, ddirty, verr2 := m2.Version(); verr2 != nil || verr != 7 || ddirty {
		t.Fatalf("expected version 7 clean after recovery, got version=%d dirty=%v err=%v", verr, ddirty, verr2)
	}

	// Users rows without linked accounts roll back cleanly: the narrowed
	// guard only fires on oauth_accounts contents, and users survive.
	if _, err := sqlDB2.Exec(`INSERT INTO users (email, password_hash, credential_version) VALUES ('down-rollback@example.com', 'hash', 1)`); err != nil {
		t.Fatalf("failed to seed unlinked user: %v", err)
	}
	if err := m2.Steps(-1); err != nil {
		t.Fatalf("users-only 000007 down = %v; want nil", err)
	}
	var oauthAccounts int
	if err := sqlDB2.QueryRow(`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'oauth_accounts'`).Scan(&oauthAccounts); err != nil {
		t.Fatalf("querying oauth_accounts table: %v", err)
	}
	if oauthAccounts != 0 {
		t.Fatal("users-only down left oauth_accounts behind")
	}
	var users int
	if err := sqlDB2.QueryRow(`SELECT COUNT(*) FROM users WHERE email = 'down-rollback@example.com'`).Scan(&users); err != nil {
		t.Fatalf("querying users: %v", err)
	}
	if users != 1 {
		t.Fatalf("users = %d after down; want 1 (down drops only oauth_accounts)", users)
	}
	if err := m2.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("re-applying m2.Up() failed: %v", err)
	}
	if _, err := sqlDB2.Exec(`DELETE FROM users WHERE email = 'down-rollback@example.com'`); err != nil {
		t.Fatalf("failed to remove seed row: %v", err)
	}
	if verr, ddirty, verr2 := m2.Version(); verr2 != nil || verr != 14 || ddirty {
		t.Fatalf("expected version 14 clean after re-up, got version=%d dirty=%v err=%v", verr, ddirty, verr2)
	}
}

func TestMigration000008_UpAndDown(t *testing.T) {
	dbURL := resolveDatabaseURL()
	testDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: failed to open postgres connection: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := testDB.PingContext(pingCtx); err != nil {
		_ = testDB.Close()
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: PostgreSQL connection failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	_ = testDB.Close()

	m, sqlDB := newMigrator(t, dbURL)
	defer func() {
		_, _ = m.Close()
		_ = sqlDB.Close()
	}()

	// Pin to 000008: head is 000009, so a bare Up() would leave the totp-down
	// assertion stepping down the wrong migration.
	if err := m.Migrate(8); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("m.Migrate(8) failed: %v", err)
	}

	// 1. Verify tables exist
	for _, table := range []string{"totp_secrets", "totp_used_codes", "two_factor_tokens"} {
		var exists bool
		err := sqlDB.QueryRow(`
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables 
				WHERE table_schema = 'public' AND table_name = $1
			)
		`, table).Scan(&exists)
		if err != nil || !exists {
			t.Fatalf("table %s does not exist after 000008 up: %v", table, err)
		}
	}

	// 2. Verify unique constraints
	for _, constraint := range []string{"uq_totp_secrets_user_id", "uq_totp_used_codes_user_code", "uq_two_factor_tokens_token_hash"} {
		var exists bool
		err := sqlDB.QueryRow(`
			SELECT EXISTS (
				SELECT 1 FROM information_schema.table_constraints 
				WHERE constraint_name = $1
			)
		`, constraint).Scan(&exists)
		if err != nil || !exists {
			t.Fatalf("unique constraint %s missing: %v", constraint, err)
		}
	}

	// 3. Verify two_factor_tokens schema invariants (attempts exists, deleted_at absent)
	var hasAttempts, hasDeletedAt bool
	err = sqlDB.QueryRow(`
		SELECT 
			EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'two_factor_tokens' AND column_name = 'attempts'),
			EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'two_factor_tokens' AND column_name = 'deleted_at')
	`).Scan(&hasAttempts, &hasDeletedAt)
	if err != nil {
		t.Fatalf("failed to query two_factor_tokens columns: %v", err)
	}
	if !hasAttempts {
		t.Fatal("two_factor_tokens missing attempts column")
	}
	if hasDeletedAt {
		t.Fatal("two_factor_tokens must NOT have deleted_at column (hard-delete invariant)")
	}

	// 4. Test Step Down (-1)
	if err := m.Steps(-1); err != nil {
		t.Fatalf("000008 down migration failed: %v", err)
	}

	// Verify all 3 tables dropped
	var tableCount int
	err = sqlDB.QueryRow(`
		SELECT COUNT(*) FROM information_schema.tables 
		WHERE table_schema = 'public' 
		  AND table_name IN ('totp_secrets', 'totp_used_codes', 'two_factor_tokens')
	`).Scan(&tableCount)
	if err != nil {
		t.Fatalf("failed to query dropped totp tables: %v", err)
	}
	if tableCount != 0 {
		t.Fatalf("expected 0 totp tables after 000008 down, found %d", tableCount)
	}

	// 5. Restore Up
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("restoring 000008 up failed: %v", err)
	}
}

func TestMigration000008_DownRefusedOnSeededDB(t *testing.T) {
	dbURL := resolveDatabaseURL()

	testDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: failed to open postgres connection: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := testDB.PingContext(pingCtx); err != nil {
		_ = testDB.Close()
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: PostgreSQL connection failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	_ = testDB.Close()

	m, sqlDB := newMigrator(t, dbURL)
	defer func() {
		_, _ = m.Close()
		_ = sqlDB.Close()
	}()

	if err := m.Migrate(8); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("m.Migrate(8) failed: %v", err)
	}

	if _, err := sqlDB.Exec(`INSERT INTO users (email, password_hash, credential_version) VALUES ('totp-down-refusal@example.com', 'hash', 1)`); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}
	if _, err := sqlDB.Exec(`INSERT INTO totp_secrets (user_id, encrypted_secret, backup_codes, enabled) SELECT id, '\x010203', '[]', true FROM users WHERE email = 'totp-down-refusal@example.com'`); err != nil {
		t.Fatalf("failed to seed totp secret: %v", err)
	}

	err = m.Steps(-1)
	if err == nil {
		t.Fatal("expected 000008 down to refuse on seeded totp_secrets, got nil")
	}
	if !strings.Contains(err.Error(), "down refused") {
		t.Fatalf("expected down-refused error, got: %v", err)
	}

	// Recovery
	_, _ = m.Close()
	_ = sqlDB.Close()

	m2, sqlDB2 := newMigrator(t, dbURL)
	defer func() {
		_, _ = m2.Close()
		_ = sqlDB2.Close()
	}()

	if ferr := m2.Force(8); ferr != nil {
		t.Fatalf("m2.Force(8) failed: %v", ferr)
	}
	if _, err := sqlDB2.Exec(`DELETE FROM totp_secrets WHERE user_id IN (SELECT id FROM users WHERE email = 'totp-down-refusal@example.com')`); err != nil {
		t.Fatalf("failed to remove seed totp row: %v", err)
	}
	if _, err := sqlDB2.Exec(`DELETE FROM users WHERE email = 'totp-down-refusal@example.com'`); err != nil {
		t.Fatalf("failed to remove seed user row: %v", err)
	}
}

// TestMigration000009_UpAndDown pins the trust flag's migration contract: the
// column backfills from the owning account's local verification so legacy users
// keep signing in, while links whose owner was never locally verified stay
// unverified. The down removes only the column, leaving every link row intact.
func TestMigration000009_UpAndDown(t *testing.T) {
	dbURL := resolveDatabaseURL()

	testDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: failed to open postgres connection: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := testDB.PingContext(pingCtx); err != nil {
		_ = testDB.Close()
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: PostgreSQL connection failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	_ = testDB.Close()

	m, sqlDB := newMigrator(t, dbURL)
	t.Cleanup(func() {
		_, _ = m.Close()
		_ = sqlDB.Close()
	})

	if err := m.Migrate(8); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("m.Migrate(8) failed: %v", err)
	}

	// A link created before 000009 carries no value for the flag. Three owners:
	// a locally verified address, an unclaimed address, and a password-claimed
	// address with no local verification.
	if _, err := sqlDB.Exec(`INSERT INTO users (email, password_hash, credential_version, email_verified) VALUES
		('legacy-trusted@example.com', 'hash', 1, true),
		('legacy-untrusted@example.com', '', 1, false),
		('legacy-password-only@example.com', 'hash', 1, false)`); err != nil {
		t.Fatalf("failed to seed users: %v", err)
	}
	for sub, addr := range map[string]string{
		"legacy-trusted-sub":       "legacy-trusted@example.com",
		"legacy-untrusted-sub":     "legacy-untrusted@example.com",
		"legacy-password-only-sub": "legacy-password-only@example.com",
	} {
		if _, err := sqlDB.Exec(`INSERT INTO oauth_accounts (user_id, provider_id, provider_user_id, email) SELECT id, 'google', $1, email FROM users WHERE email = $2`, sub, addr); err != nil {
			t.Fatalf("failed to seed link %s: %v", sub, err)
		}
	}
	t.Cleanup(func() {
		_, _ = sqlDB.Exec(`DELETE FROM oauth_accounts WHERE provider_user_id IN ('legacy-trusted-sub', 'legacy-untrusted-sub', 'legacy-password-only-sub')`)
		_, _ = sqlDB.Exec(`DELETE FROM users WHERE email IN ('legacy-trusted@example.com', 'legacy-untrusted@example.com', 'legacy-password-only@example.com')`)
	})

	if err := m.Steps(1); err != nil {
		t.Fatalf("000009 up migration failed: %v", err)
	}

	var nullable bool
	if err := sqlDB.QueryRow(`
		SELECT is_nullable = 'YES'
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'oauth_accounts' AND column_name = 'verified'
	`).Scan(&nullable); err != nil {
		t.Fatalf("failed to inspect verified column: %v", err)
	}
	if nullable {
		t.Fatal("oauth_accounts.verified must be NOT NULL")
	}

	requireLinkVerified := func(t *testing.T, sub string, want bool) {
		t.Helper()
		var verified bool
		if err := sqlDB.QueryRow(`SELECT verified FROM oauth_accounts WHERE provider_user_id = $1`, sub).Scan(&verified); err != nil {
			t.Fatalf("failed to read %s.verified: %v", sub, err)
		}
		if verified != want {
			t.Fatalf("%s verified = %v; want %v", sub, verified, want)
		}
	}
	// Trust survives only where the owner's address was verified locally.
	requireLinkVerified(t, "legacy-trusted-sub", true)
	requireLinkVerified(t, "legacy-untrusted-sub", false)
	requireLinkVerified(t, "legacy-password-only-sub", false)

	// A link the provider attested after 000009 on a password-claimed account is
	// the data a down/up cycle cannot restore: the flag is re-derived from
	// users.email_verified, which is false here.
	if _, err := sqlDB.Exec(`UPDATE oauth_accounts SET verified = TRUE WHERE provider_user_id = 'legacy-password-only-sub'`); err != nil {
		t.Fatalf("failed to attest link: %v", err)
	}

	if err := m.Steps(-1); err != nil {
		t.Fatalf("000009 down migration failed: %v", err)
	}
	var hasColumn bool
	if err := sqlDB.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'oauth_accounts' AND column_name = 'verified')
	`).Scan(&hasColumn); err != nil {
		t.Fatalf("failed to inspect dropped column: %v", err)
	}
	if hasColumn {
		t.Fatal("000009 down must drop the verified column")
	}
	var links int
	if err := sqlDB.QueryRow(`SELECT COUNT(*) FROM oauth_accounts WHERE provider_user_id LIKE 'legacy-%-sub'`).Scan(&links); err != nil {
		t.Fatalf("failed to count links after down: %v", err)
	}
	if links != 3 {
		t.Fatalf("links after 000009 down = %d; want 3 (down drops the flag, not the links)", links)
	}

	if err := m.Steps(1); err != nil {
		t.Fatalf("re-applying 000009 failed: %v", err)
	}
	requireLinkVerified(t, "legacy-trusted-sub", true)
	requireLinkVerified(t, "legacy-password-only-sub", false)

	if _, err := sqlDB.Exec(`DELETE FROM oauth_accounts WHERE provider_user_id LIKE 'legacy-%-sub'`); err != nil {
		t.Fatalf("failed to remove seed links: %v", err)
	}
	if _, err := sqlDB.Exec(`DELETE FROM users WHERE email LIKE 'legacy-%@example.com'`); err != nil {
		t.Fatalf("failed to remove seed users: %v", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("restoring head failed: %v", err)
	}
}

// TestMigration000010_UpAndDown pins the Microsoft duplicate link deduplication contract.
func TestMigration000010_UpAndDown(t *testing.T) {
	dbURL := resolveDatabaseURL()
	testDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: failed to open postgres connection: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := testDB.PingContext(pingCtx); err != nil {
		_ = testDB.Close()
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: PostgreSQL connection failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	_ = testDB.Close()

	m, sqlDB := newMigrator(t, dbURL)
	t.Cleanup(func() {
		_, _ = m.Close()
		_ = sqlDB.Close()
	})

	if err := m.Migrate(9); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("m.Migrate(9) failed: %v", err)
	}

	var userID string
	if err := sqlDB.QueryRow(`INSERT INTO users (email, password_hash, credential_version, email_verified) VALUES
		('ms-dedup@example.com', 'hash', 1, true) RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sqlDB.Exec(`DELETE FROM oauth_accounts WHERE user_id = $1`, userID)
		_, _ = sqlDB.Exec(`DELETE FROM users WHERE id = $1`, userID)
	})

	// Seed duplicate Microsoft links for the same user with matching email (e.g. legacy oid vs new sub)
	// One verified and one unverified (survivor rule: verified wins)
	// Plus distinct identities on the same user with different emails to prove dedup never collapses across distinct emails
	if _, err := sqlDB.Exec(`INSERT INTO oauth_accounts (user_id, provider_id, provider_user_id, email, verified, created_at) VALUES
		($1, 'microsoft', 'ms-old-oid', 'ms-dedup@example.com', false, '2026-01-01 00:00:00Z'),
		($1, 'microsoft', 'ms-new-sub', 'ms-dedup@example.com', true, '2026-02-01 00:00:00Z'),
		($1, 'microsoft', 'ms-work-sub', 'ms-work@example.com', true, '2026-01-01 00:00:00Z'),
		($1, 'microsoft', 'ms-personal-sub', 'ms-personal@example.com', true, '2026-01-01 00:00:00Z')`, userID); err != nil {
		t.Fatalf("failed to seed microsoft duplicate links: %v", err)
	}

	if err := m.Steps(1); err != nil {
		t.Fatalf("000010 up migration failed: %v", err)
	}

	var remainingLinks int
	if err := sqlDB.QueryRow(`SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1 AND provider_id = 'microsoft'`, userID).Scan(&remainingLinks); err != nil {
		t.Fatalf("failed to count remaining links: %v", err)
	}
	if remainingLinks != 3 {
		t.Fatalf("expected 3 remaining links (1 deduped + 2 distinct identities), got %d", remainingLinks)
	}

	var keptVerified bool
	var keptSub string
	if err := sqlDB.QueryRow(`SELECT verified, provider_user_id FROM oauth_accounts WHERE user_id = $1 AND provider_id = 'microsoft' AND email = 'ms-dedup@example.com'`, userID).Scan(&keptVerified, &keptSub); err != nil {
		t.Fatalf("failed to read retained link: %v", err)
	}
	if !keptVerified || keptSub != "ms-new-sub" {
		t.Fatalf("expected verified link with sub 'ms-new-sub' retained, got verified=%v sub=%s", keptVerified, keptSub)
	}

	// 000010 down is a no-op
	if err := m.Steps(-1); err != nil {
		t.Fatalf("000010 down migration failed: %v", err)
	}

	if _, err := sqlDB.Exec(`DELETE FROM oauth_accounts WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("failed to cleanup links: %v", err)
	}
	if _, err := sqlDB.Exec(`DELETE FROM users WHERE id = $1`, userID); err != nil {
		t.Fatalf("failed to cleanup user: %v", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("restoring head failed: %v", err)
	}
}

// TestMigration000011_TenantQualifiesIdentityKey pins the schema rollover for
// #72 against a live database: the tenant joins the unique key, the tenant-blind
// constraint is removed, and the down migration restores it.
func TestMigration000011_TenantQualifiesIdentityKey(t *testing.T) {
	dbURL := resolveDatabaseURL()
	testDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: failed to open postgres connection: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := testDB.PingContext(pingCtx); err != nil {
		_ = testDB.Close()
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: PostgreSQL connection failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	_ = testDB.Close()

	m, sqlDB := newMigrator(t, dbURL)
	t.Cleanup(func() {
		_, _ = m.Close()
		_ = sqlDB.Close()
	})

	if err := m.Migrate(10); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("m.Migrate(10) failed: %v", err)
	}
	if !postgresIndexExists(t, sqlDB, "uq_oauth_accounts_provider_uid") {
		t.Fatal("precondition: the tenant-blind unique index must exist before 000011")
	}

	if err := m.Steps(1); err != nil {
		t.Fatalf("000011 up migration failed: %v", err)
	}

	var tenantNullable string
	if err := sqlDB.QueryRow(`SELECT is_nullable FROM information_schema.columns WHERE table_name = 'oauth_accounts' AND column_name = 'provider_tenant_id'`).Scan(&tenantNullable); err != nil {
		t.Fatalf("provider_tenant_id column missing after 000011: %v", err)
	}
	if tenantNullable != "NO" {
		t.Fatalf("provider_tenant_id is_nullable = %q; want NO", tenantNullable)
	}
	if !postgresIndexExists(t, sqlDB, "uq_oauth_accounts_provider_tenant_uid") {
		t.Fatal("000011 must create the tenant-qualified unique index")
	}
	if postgresIndexExists(t, sqlDB, "uq_oauth_accounts_provider_uid") {
		t.Fatal("000011 must drop the tenant-blind unique index")
	}

	var userID string
	if err := sqlDB.QueryRow(`INSERT INTO users (email, password_hash, credential_version, email_verified) VALUES
		('ms-tenant-key@example.com', 'hash', 1, true) RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sqlDB.Exec(`DELETE FROM oauth_accounts WHERE user_id = $1`, userID)
		_, _ = sqlDB.Exec(`DELETE FROM users WHERE id = $1`, userID)
	})

	// The same pairwise subject in two tenants is two identities.
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if _, err := sqlDB.Exec(`INSERT INTO oauth_accounts (user_id, provider_id, provider_tenant_id, provider_user_id, email)
			VALUES ($1, 'microsoft', $2, 'shared-sub', $3)`, userID, tenant, tenant+"@example.com"); err != nil {
			t.Fatalf("insert link for %s: %v", tenant, err)
		}
	}
	// Within one tenant the subject stays unique.
	if _, err := sqlDB.Exec(`INSERT INTO oauth_accounts (user_id, provider_id, provider_tenant_id, provider_user_id, email)
		VALUES ($1, 'microsoft', 'tenant-a', 'shared-sub', 'duplicate@example.com')`, userID); err == nil {
		t.Fatal("duplicate subject in one tenant was accepted")
	}

	if _, err := sqlDB.Exec(`DELETE FROM oauth_accounts WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("failed to cleanup links: %v", err)
	}
	if err := m.Steps(-1); err != nil {
		t.Fatalf("000011 down migration failed: %v", err)
	}
	if postgresIndexExists(t, sqlDB, "uq_oauth_accounts_provider_tenant_uid") {
		t.Fatal("000011 down must drop the tenant-qualified unique index")
	}
	if !postgresConstraintExists(t, sqlDB, "uq_oauth_accounts_provider_uid") {
		t.Fatal("000011 down must restore the tenant-blind unique constraint, not a plain index")
	}

	_, _ = sqlDB.Exec(`DELETE FROM users WHERE id = $1`, userID)
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("restoring head failed: %v", err)
	}
}

// TestMigration000012_UpAndDown runs the token-envelope migration against a
// live database: the up adds the five columns, a populated grant round-trips,
// the down drops only the columns, and re-applying the up restores them empty.
func TestMigration000012_UpAndDown(t *testing.T) {
	dbURL := resolveDatabaseURL()
	testDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: failed to open postgres connection: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := testDB.PingContext(pingCtx); err != nil {
		_ = testDB.Close()
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: PostgreSQL connection failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	_ = testDB.Close()

	m, sqlDB := newMigrator(t, dbURL)
	t.Cleanup(func() {
		_, _ = m.Close()
		_ = sqlDB.Close()
	})

	if err := m.Migrate(11); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("m.Migrate(11) failed: %v", err)
	}
	requireNoOAuthTokenColumns(t, sqlDB)

	if err := m.Steps(1); err != nil {
		t.Fatalf("000012 up migration failed: %v", err)
	}
	requireOAuthTokenColumns(t, sqlDB)

	var userID string
	if err := sqlDB.QueryRow(`INSERT INTO users (email, password_hash, credential_version, email_verified) VALUES
		('tokens-migration@example.com', 'hash', 1, true) RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sqlDB.Exec(`DELETE FROM oauth_accounts WHERE user_id = $1`, userID)
		_, _ = sqlDB.Exec(`DELETE FROM users WHERE id = $1`, userID)
	})

	fingerprint := strings.Repeat("a", 64)
	expiresAt := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Microsecond)
	if _, err := sqlDB.Exec(`INSERT INTO oauth_accounts
		(user_id, provider_id, provider_tenant_id, provider_user_id, email,
		 access_token_ciphertext, refresh_token_ciphertext, refresh_token_fingerprint, token_expires_at, token_scope)
		VALUES ($1, 'x', '', 'token-sub', 'tokens-migration@example.com', '{"v":1}', '{"v":1}', $2, $3, 'users.read offline.access')`,
		userID, fingerprint, expiresAt); err != nil {
		t.Fatalf("failed to seed token link: %v", err)
	}

	var (
		access, refresh, storedFingerprint, scope string
		storedExpiry                              time.Time
	)
	if err := sqlDB.QueryRow(`SELECT access_token_ciphertext, refresh_token_ciphertext,
		refresh_token_fingerprint, token_expires_at, token_scope
		FROM oauth_accounts WHERE user_id = $1`, userID).
		Scan(&access, &refresh, &storedFingerprint, &storedExpiry, &scope); err != nil {
		t.Fatalf("failed to read the seeded grant: %v", err)
	}
	if access != `{"v":1}` || refresh != `{"v":1}` || storedFingerprint != fingerprint || scope != "users.read offline.access" {
		t.Fatalf("stored grant = (%q, %q, %q, %q); want the seeded values", access, refresh, storedFingerprint, scope)
	}
	if !storedExpiry.Equal(expiresAt) {
		t.Fatalf("stored expiry = %v; want %v", storedExpiry, expiresAt)
	}

	if err := m.Steps(-1); err != nil {
		t.Fatalf("000012 down migration failed: %v", err)
	}
	requireNoOAuthTokenColumns(t, sqlDB)
	var surviving int
	if err := sqlDB.QueryRow(`SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1`, userID).Scan(&surviving); err != nil {
		t.Fatalf("failed to count surviving links: %v", err)
	}
	if surviving != 1 {
		t.Fatalf("links after the 000012 down = %d; want the populated row to survive", surviving)
	}

	if err := m.Steps(1); err != nil {
		t.Fatalf("000012 re-up migration failed: %v", err)
	}
	requireOAuthTokenColumns(t, sqlDB)
	// Scan each re-added column on its own: concatenating in SQL would cast a
	// CHAR column through text(bpchar), which trims the padding and hides the
	// very thing this asserts: that an empty fingerprint reads back as "".
	var reUpAccess, reUpFingerprint, reUpScope string
	if err := sqlDB.QueryRow(`SELECT access_token_ciphertext, refresh_token_fingerprint, token_scope
		FROM oauth_accounts WHERE user_id = $1`, userID).
		Scan(&reUpAccess, &reUpFingerprint, &reUpScope); err != nil {
		t.Fatalf("failed to read the re-added columns: %v", err)
	}
	if reUpAccess != "" || reUpFingerprint != "" || reUpScope != "" {
		t.Fatalf("re-added columns = (%q, %q, %q); want the empty backfill", reUpAccess, reUpFingerprint, reUpScope)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("restoring head failed: %v", err)
	}
}

// requireOAuthTokenColumns asserts the five columns 000012 adds, with their
// types and nullability: the fingerprint is a VARCHAR(64) and only the expiry
// may be NULL.
func requireOAuthTokenColumns(t *testing.T, sqlDB *sql.DB) {
	t.Helper()

	want := map[string]string{
		"access_token_ciphertext":   "text/NO/0",
		"refresh_token_ciphertext":  "text/NO/0",
		"refresh_token_fingerprint": "character varying/NO/64",
		"token_expires_at":          "timestamp with time zone/YES/0",
		"token_scope":               "text/NO/0",
	}
	got := map[string]string{}
	rows, err := sqlDB.Query(`SELECT column_name, data_type, is_nullable, COALESCE(character_maximum_length, 0)
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'oauth_accounts'
		  AND column_name IN ('access_token_ciphertext', 'refresh_token_ciphertext',
			'refresh_token_fingerprint', 'token_expires_at', 'token_scope')`)
	if err != nil {
		t.Fatalf("query oauth_accounts columns: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name, dataType, nullable string
		var maxLength int
		if err := rows.Scan(&name, &dataType, &nullable, &maxLength); err != nil {
			t.Fatalf("scan oauth_accounts column: %v", err)
		}
		got[name] = fmt.Sprintf("%s/%s/%d", dataType, nullable, maxLength)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate oauth_accounts columns: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("oauth token columns = %v; want %v", got, want)
	}
}

// requireNoOAuthTokenColumns asserts none of 000012's columns exist.
func requireNoOAuthTokenColumns(t *testing.T, sqlDB *sql.DB) {
	t.Helper()

	var count int
	if err := sqlDB.QueryRow(`SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'oauth_accounts'
		  AND column_name IN ('access_token_ciphertext', 'refresh_token_ciphertext',
			'refresh_token_fingerprint', 'token_expires_at', 'token_scope')`).Scan(&count); err != nil {
		t.Fatalf("count oauth token columns: %v", err)
	}
	if count != 0 {
		t.Fatalf("oauth token columns present = %d; want none", count)
	}
}

// postgresIndexExists reports whether the named index exists on oauth_accounts.
func postgresIndexExists(t *testing.T, sqlDB *sql.DB, name string) bool {
	t.Helper()
	var exists bool
	err := sqlDB.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM pg_indexes
		WHERE schemaname = 'public' AND tablename = 'oauth_accounts' AND indexname = $1
	)`, name).Scan(&exists)
	if err != nil {
		t.Fatalf("query index %s: %v", name, err)
	}
	return exists
}

// postgresConstraintExists reports whether the named unique constraint exists on
// oauth_accounts. A constraint-owned index is also listed by pg_indexes, so only
// pg_constraint distinguishes the restored form from a plain index.
func postgresConstraintExists(t *testing.T, sqlDB *sql.DB, name string) bool {
	t.Helper()
	var exists bool
	err := sqlDB.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid
		JOIN pg_namespace n ON n.oid = t.relnamespace
		WHERE n.nspname = 'public' AND t.relname = 'oauth_accounts'
		  AND c.contype = 'u' AND c.conname = $1
	)`, name).Scan(&exists)
	if err != nil {
		t.Fatalf("query constraint %s: %v", name, err)
	}
	return exists
}

// TestMigration000013_UpAndDown proves the key-id hint is bookkeeping the ciphertext
// survives: up adds one NOT NULL empty-default column, down drops exactly that
// column without touching stored secrets, and re-applying up backfills the hint
// to unknown for rows that predate it.
func TestMigration000013_UpAndDown(t *testing.T) {
	dbURL := resolveDatabaseURL()
	testDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: failed to open postgres connection: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := testDB.PingContext(pingCtx); err != nil {
		_ = testDB.Close()
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: PostgreSQL connection failed: %v", err)
		}
		t.Skipf("Postgres not available, skipping: %v", err)
	}
	_ = testDB.Close()

	m, sqlDB := newMigrator(t, dbURL)
	t.Cleanup(func() {
		_, _ = m.Close()
		_ = sqlDB.Close()
	})

	if err := m.Migrate(12); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("m.Migrate(12) failed: %v", err)
	}

	var userID string
	if err := sqlDB.QueryRow(`INSERT INTO users (email, password_hash, credential_version, email_verified) VALUES
		('totp-kid-013@example.com', 'hash', 1, true) RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sqlDB.Exec(`DELETE FROM totp_secrets WHERE user_id = $1`, userID)
		_, _ = sqlDB.Exec(`DELETE FROM users WHERE id = $1`, userID)
	})

	// A pre-envelope row: 12-byte nonce || ciphertext || 16-byte tag.
	ciphertext := []byte("013-nonce||ciphertext||tag-payload")
	if _, err := sqlDB.Exec(`INSERT INTO totp_secrets (user_id, encrypted_secret, backup_codes, enabled) VALUES ($1, $2, '[]', true)`, userID, ciphertext); err != nil {
		t.Fatalf("failed to seed totp secret: %v", err)
	}

	if err := m.Steps(1); err != nil {
		t.Fatalf("000013 up migration failed: %v", err)
	}

	requireHint := func(t *testing.T, want string) {
		t.Helper()
		var (
			nullable   bool
			columnType string
			columnLen  int
			hint       string
			stored     []byte
		)
		if err := sqlDB.QueryRow(`
			SELECT is_nullable = 'YES', data_type, character_maximum_length
			FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'totp_secrets' AND column_name = 'secret_kid'
		`).Scan(&nullable, &columnType, &columnLen); err != nil {
			t.Fatalf("failed to inspect secret_kid column: %v", err)
		}
		if nullable || columnType != "character varying" || columnLen != 32 {
			t.Fatalf("secret_kid = (%s(%d), nullable %v); want varchar(32) NOT NULL", columnType, columnLen, nullable)
		}
		if err := sqlDB.QueryRow(`SELECT secret_kid, encrypted_secret FROM totp_secrets WHERE user_id = $1`, userID).Scan(&hint, &stored); err != nil {
			t.Fatalf("failed to read totp row: %v", err)
		}
		if hint != want {
			t.Fatalf("secret_kid = %q; want %q", hint, want)
		}
		if !bytes.Equal(stored, ciphertext) {
			t.Fatalf("000013 changed the stored ciphertext")
		}
	}
	requireHint(t, "")

	if err := m.Steps(-1); err != nil {
		t.Fatalf("000013 down migration failed: %v", err)
	}
	// Probing the column directly is the property under test: an information_schema
	// lookup can pass on a schema mismatch, a read of a dropped column cannot.
	var (
		probeHint string
		pgErr     *pgconn.PgError
	)
	err = sqlDB.QueryRow(`SELECT secret_kid FROM totp_secrets LIMIT 0`).Scan(&probeHint)
	if !errors.As(err, &pgErr) || pgErr.Code != "42703" {
		t.Fatalf("reading secret_kid after down = %v; want undefined_column (42703)", err)
	}
	var storedAfterDown []byte
	if err := sqlDB.QueryRow(`SELECT encrypted_secret FROM totp_secrets WHERE user_id = $1`, userID).Scan(&storedAfterDown); err != nil {
		t.Fatalf("failed to read totp row after down: %v", err)
	}
	if !bytes.Equal(storedAfterDown, ciphertext) {
		t.Fatal("000013 down changed the stored ciphertext")
	}

	if err := m.Steps(1); err != nil {
		t.Fatalf("re-applying 000013 failed: %v", err)
	}
	requireHint(t, "")

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("restoring head failed: %v", err)
	}
}

