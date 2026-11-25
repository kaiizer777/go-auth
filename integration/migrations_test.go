//go:build integration

package integration

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	pgmigrate "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
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
	_, _ = sqlDB.Exec("TRUNCATE TABLE sessions, verification_tokens, password_reset_tokens, oauth_accounts, totp_secrets, totp_used_codes, two_factor_tokens, users CASCADE")

	// 4. Down all migrations cleanly
	if err := m.Down(); err != nil {
		t.Fatalf("m.Down() failed: %v", err)
	}

	// Verify tables dropped
	var tableCount int
	err = sqlDB.QueryRow(`
		SELECT COUNT(*) FROM information_schema.tables 
		WHERE table_schema = 'public' 
		  AND table_name IN ('users', 'sessions', 'verification_tokens', 'password_reset_tokens', 'oauth_accounts', 'totp_secrets', 'totp_used_codes', 'two_factor_tokens')
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
		  AND table_name IN ('users', 'sessions', 'verification_tokens', 'password_reset_tokens', 'oauth_accounts', 'totp_secrets', 'totp_used_codes', 'two_factor_tokens')
	`).Scan(&tableCount)
	if err != nil {
		t.Fatalf("querying tables failed: %v", err)
	}
	if tableCount != 8 {
		t.Fatalf("expected 8 application tables after re-Up, found %d", tableCount)
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
	if verr, ddirty, verr2 := m2.Version(); verr2 != nil || verr != 10 || ddirty {
		t.Fatalf("expected version 10 clean after re-up, got version=%d dirty=%v err=%v", verr, ddirty, verr2)
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
	defer func() {
		_, _ = m.Close()
		_ = sqlDB.Close()
	}()

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
	defer func() {
		_, _ = m.Close()
		_ = sqlDB.Close()
	}()

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

	// Seed duplicate (provider_id, provider_user_id) with distinct emails and verified vs unverified
	// Plus distinct identities on the same user to prove dedup never collapses on user_id
	if _, err := sqlDB.Exec(`INSERT INTO oauth_accounts (user_id, provider_id, provider_user_id, email, verified, created_at) VALUES
		($1, 'microsoft', 'ms-dup-sub', 'ms-verified@example.com', true, '2026-01-01 00:00:00Z'),
		($1, 'microsoft', 'ms-dup-sub', 'ms-unverified-diff@example.com', false, '2026-02-01 00:00:00Z'),
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
	var keptEmail string
	if err := sqlDB.QueryRow(`SELECT verified, email FROM oauth_accounts WHERE user_id = $1 AND provider_id = 'microsoft' AND provider_user_id = 'ms-dup-sub'`, userID).Scan(&keptVerified, &keptEmail); err != nil {
		t.Fatalf("failed to read retained link: %v", err)
	}
	if !keptVerified || keptEmail != "ms-verified@example.com" {
		t.Fatalf("expected verified link with email 'ms-verified@example.com' retained, got verified=%v email=%s", keptVerified, keptEmail)
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
