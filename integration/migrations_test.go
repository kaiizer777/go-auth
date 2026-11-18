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
	_, _ = sqlDB.Exec("TRUNCATE TABLE sessions, verification_tokens, password_reset_tokens, users CASCADE")

	// 4. Down all migrations cleanly
	if err := m.Down(); err != nil {
		t.Fatalf("m.Down() failed: %v", err)
	}

	// Verify tables dropped
	var tableCount int
	err = sqlDB.QueryRow(`
		SELECT COUNT(*) FROM information_schema.tables 
		WHERE table_schema = 'public' 
		  AND table_name IN ('users', 'sessions', 'verification_tokens', 'password_reset_tokens')
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
		  AND table_name IN ('users', 'sessions', 'verification_tokens', 'password_reset_tokens')
	`).Scan(&tableCount)
	if err != nil {
		t.Fatalf("querying tables failed: %v", err)
	}
	if tableCount != 4 {
		t.Fatalf("expected 4 application tables after re-Up, found %d", tableCount)
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

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("m.Up() failed: %v", err)
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
	if verr, ddirty, verr2 := m2.Version(); verr2 != nil || verr != 7 || ddirty {
		t.Fatalf("expected version 7 clean after re-up, got version=%d dirty=%v err=%v", verr, ddirty, verr2)
	}
}
