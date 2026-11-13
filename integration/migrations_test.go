//go:build integration

package integration

import (
	"context"
	"database/sql"
	"os"
	"testing"

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

	conn, err := sqlDB.Conn(context.Background())
	if err != nil {
		_ = sqlDB.Close()
		t.Fatalf("failed to checkout conn: %v", err)
	}

	driver, err := pgmigrate.WithConnection(context.Background(), conn, &pgmigrate.Config{})
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
	if err := testDB.Ping(); err != nil {
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

