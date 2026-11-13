package db

import (
	"database/sql"
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4/source/iofs"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

func TestCustomMigrationsFS(t *testing.T) {
	tmpDir := t.TempDir()
	upFile := filepath.Join(tmpDir, "000001_init.up.sql")
	if err := os.WriteFile(upFile, []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatalf("failed to write test migration file: %v", err)
	}

	driver, err := iofs.New(os.DirFS(tmpDir), ".")
	if err != nil {
		t.Fatalf("iofs.New(os.DirFS) err = %v", err)
	}
	defer func() { _ = driver.Close() }()

	first, err := driver.First()
	if err != nil {
		t.Fatalf("driver.First() err = %v", err)
	}
	if first != 1 {
		t.Fatalf("driver.First() = %d, want 1", first)
	}
}

func TestDefaultMigrationsEmbedded(t *testing.T) {
	driver, err := iofs.New(defaultMigrationsFS, "migrations")
	if err != nil {
		t.Fatalf("failed to init iofs driver: %v", err)
	}
	defer func() {
		_ = driver.Close()
	}()

	first, err := driver.First()
	if err != nil {
		t.Fatalf("failed to read first migration version: %v", err)
	}
	if first != 1 {
		t.Fatalf("first migration = %d; want 1", first)
	}

	// Verify all up and down migrations can be read
	current := first
	for {
		rcUp, _, err := driver.ReadUp(current)
		if err != nil {
			t.Fatalf("failed to read up migration for version %d: %v", current, err)
		}
		_ = rcUp.Close()

		rcDown, _, err := driver.ReadDown(current)
		if err != nil {
			t.Fatalf("failed to read down migration for version %d: %v", current, err)
		}
		_ = rcDown.Close()

		next, err := driver.Next(current)
		if err != nil {
			break
		}
		current = next
	}
}

func TestIsDefaultMigrationsPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"", true},
		{"db/migrations", true},
		{"./db/migrations", true},
		{"custom/migrations", false},
		{"/var/migrations", false},
	}

	for _, tt := range tests {
		got := isDefaultMigrationsPath(tt.path)
		if got != tt.want {
			t.Errorf("isDefaultMigrationsPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestConnectInvalidURL(t *testing.T) {
	cfg := config.Config{
		DatabaseURL: "postgres://invalid:invalid@127.0.0.1:54329/nonexistent?sslmode=disable&connect_timeout=1",
	}
	gormDB, err := Connect(cfg)
	if err == nil {
		if gormDB != nil {
			if sqlDB, errDB := gormDB.DB(); errDB == nil {
				_ = sqlDB.Close()
			}
		}
		t.Fatal("Connect with invalid database URL expected error, got nil")
	}
}

func TestRunMigrationsInvalidURL(t *testing.T) {
	err := runMigrations("postgres://invalid:invalid@127.0.0.1:54329/nonexistent?sslmode=disable&connect_timeout=1", "")
	if err == nil {
		t.Fatal("runMigrations with invalid database URL expected error, got nil")
	}
}

func TestConnect_PingFailureAndPoolSettings(t *testing.T) {
	oldRunMigrations := runMigrationsFn
	oldSQLDBPing := sqlDBPingFn
	t.Cleanup(func() {
		runMigrationsFn = oldRunMigrations
		sqlDBPingFn = oldSQLDBPing
	})

	runMigrationsFn = func(databaseURL, migrationsPath string) error {
		return nil
	}

	var capturedStats sql.DBStats
	var capturedDB *sql.DB
	sqlDBPingFn = func(db *sql.DB) error {
		capturedDB = db
		capturedStats = db.Stats()
		return stderrors.New("ping connection refused")
	}

	cfg := config.Config{
		DatabaseURL:     "postgres://user:pass@127.0.0.1:54329/testdb?sslmode=disable&connect_timeout=1",
		MaxOpenConns:    42,
		MaxIdleConns:    12,
		ConnMaxLifetime: 15 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
	}

	gormDB, err := Connect(cfg)
	if err == nil {
		if gormDB != nil {
			if sqlDB, errDB := gormDB.DB(); errDB == nil {
				_ = sqlDB.Close()
			}
		}
		t.Fatal("Connect expected ping failure error, got nil")
	}

	var appErr *errors.Error
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseUnavailable {
		t.Fatalf("Connect error code = %v; want %v", appErr.Code(), errors.CodeDatabaseUnavailable)
	}
	if !strings.Contains(err.Error(), "db ping failed") {
		t.Fatalf("Connect error message = %q; want containing 'db ping failed'", err.Error())
	}

	// Verify pool settings were applied before Ping was called
	if capturedStats.MaxOpenConnections != 42 {
		t.Fatalf("capturedStats.MaxOpenConnections = %d; want 42", capturedStats.MaxOpenConnections)
	}

	// Verify deferred cleanup closed the *sql.DB on ping failure
	if capturedDB != nil {
		if pingErr := capturedDB.Ping(); pingErr == nil || !strings.Contains(pingErr.Error(), "sql: database is closed") {
			t.Fatalf("expected sql.DB to be closed on ping failure, got ping err = %v", pingErr)
		}
	}
}

func TestConnect_GetSQLDBFailure(t *testing.T) {
	oldRunMigrations := runMigrationsFn
	oldGetSQLDB := getSQLDBFn
	t.Cleanup(func() {
		runMigrationsFn = oldRunMigrations
		getSQLDBFn = oldGetSQLDB
	})

	runMigrationsFn = func(databaseURL, migrationsPath string) error {
		return nil
	}
	getSQLDBFn = func(db *gorm.DB) (*sql.DB, error) {
		return nil, stderrors.New("mock get sql.DB failed")
	}

	cfg := config.Config{
		DatabaseURL: "postgres://user:pass@127.0.0.1:54329/testdb?sslmode=disable&connect_timeout=1",
	}

	gormDB, err := Connect(cfg)
	if err == nil {
		if gormDB != nil {
			if sqlDB, errDB := gormDB.DB(); errDB == nil {
				_ = sqlDB.Close()
			}
		}
		t.Fatal("Connect expected get sql.DB error, got nil")
	}

	var appErr *errors.Error
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
		t.Fatalf("Connect error code = %v; want %v", appErr.Code(), errors.CodeDatabaseError)
	}
	if !strings.Contains(err.Error(), "get sql.DB failed") {
		t.Fatalf("Connect error message = %q; want containing 'get sql.DB failed'", err.Error())
	}
}

func TestConnect_MigrationFailure(t *testing.T) {
	oldRunMigrations := runMigrationsFn
	t.Cleanup(func() {
		runMigrationsFn = oldRunMigrations
	})

	expectedErr := errors.New(errors.CodeMigrationFailed, "custom migration failed", stderrors.New("bad sql"))
	runMigrationsFn = func(databaseURL, migrationsPath string) error {
		return expectedErr
	}

	cfg := config.Config{
		DatabaseURL: "postgres://user:pass@127.0.0.1:54329/testdb?sslmode=disable&connect_timeout=1",
	}

	gormDB, err := Connect(cfg)
	if err == nil {
		if gormDB != nil {
			if sqlDB, errDB := gormDB.DB(); errDB == nil {
				_ = sqlDB.Close()
			}
		}
		t.Fatal("Connect expected migration error, got nil")
	}

	var appErr *errors.Error
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeMigrationFailed {
		t.Fatalf("Connect error code = %v; want %v", appErr.Code(), errors.CodeMigrationFailed)
	}
}

func TestCustomMigrationsFS_InvalidDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistent := filepath.Join(tmpDir, "does-not-exist")

	_, err := iofs.New(os.DirFS(nonExistent), ".")
	if err == nil {
		t.Fatal("expected error opening non-existent directory with iofs.New, got nil")
	}
}

func TestCustomMigrationsFS_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	driver, err := iofs.New(os.DirFS(tmpDir), ".")
	if err != nil {
		t.Fatalf("iofs.New on empty dir unexpected err: %v", err)
	}
	defer func() { _ = driver.Close() }()

	_, err = driver.First()
	if err == nil {
		t.Fatal("expected error calling First() on empty migrations directory, got nil")
	}
}

func TestCustomMigrationsFS_DuplicateVersion(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "000001_first.up.sql")
	f2 := filepath.Join(tmpDir, "000001_duplicate.up.sql")
	if err := os.WriteFile(f1, []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatalf("failed to write f1: %v", err)
	}
	if err := os.WriteFile(f2, []byte("SELECT 2;"), 0o600); err != nil {
		t.Fatalf("failed to write f2: %v", err)
	}

	driver, err := iofs.New(os.DirFS(tmpDir), ".")
	if err == nil {
		if driver != nil {
			_ = driver.Close()
		}
		t.Fatal("expected error for duplicate migration version, got nil")
	}
}
