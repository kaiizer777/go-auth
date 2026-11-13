package db

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/kaiizer777/go-auth/config"
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
