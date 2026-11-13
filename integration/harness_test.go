//go:build integration

package integration

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
)

const defaultTestDBURL = "postgres://postgres:postgres@localhost:5432/goauth_test?sslmode=disable"

// resolveDatabaseURL resolves the PostgreSQL connection URL from environment variables,
// falling back to local PostgreSQL on default port.
func resolveDatabaseURL() string {
	if u := os.Getenv("TEST_DATABASE_URL"); u != "" {
		return u
	}
	if u := os.Getenv("DATABASE_URL"); u != "" {
		return u
	}
	return defaultTestDBURL
}

// testConfig returns a standard configuration tuned for integration testing:
// fast Argon2 parameters to prevent timeouts under -race, and a test BaseURL.
func testConfig(databaseURL string) config.Config {
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = databaseURL
	cfg.BaseURL = "http://localhost:8080"
	cfg.Argon2 = config.Argon2Config{
		Memory:      19456,
		Time:        2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	return cfg
}

// setupDB initializes a real PostgreSQL database connection via db.Connect (which runs migrations)
// and returns the GORM handle and resolved config. If PostgreSQL is not reachable, the test is skipped.
func setupDB(t *testing.T) (*gorm.DB, config.Config) {
	t.Helper()

	dbURL := resolveDatabaseURL()

	// Probe connectivity first before failing tests
	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Skipf("Postgres not available, skipping integration tests: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		t.Skipf("Postgres not available at %s, skipping integration tests: %v", sanitizeURL(dbURL), err)
	}
	_ = sqlDB.Close()

	cfg := testConfig(dbURL)
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	t.Cleanup(func() {
		if rawDB, err := database.DB(); err == nil {
			_ = rawDB.Close()
		}
	})

	truncateTables(t, database)
	return database, cfg
}

// truncateTables clears all test tables with CASCADE between tests.
func truncateTables(t *testing.T, database *gorm.DB) {
	t.Helper()
	err := database.Exec("TRUNCATE TABLE users, sessions, verification_tokens, password_reset_tokens CASCADE").Error
	if err != nil {
		t.Fatalf("failed to truncate test tables: %v", err)
	}
}

// sanitizeURL removes user credentials from connection strings for safe logging.
func sanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "REDACTED")
	}
	return strings.ReplaceAll(u.String(), "%3A", ":")
}
