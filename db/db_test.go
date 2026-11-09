package db

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4/source/iofs"
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

	// Verify all up migrations can be read
	current := first
	for {
		rc, _, err := driver.ReadUp(current)
		if err != nil {
			t.Fatalf("failed to read up migration for version %d: %v", current, err)
		}
		_ = rc.Close()

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
