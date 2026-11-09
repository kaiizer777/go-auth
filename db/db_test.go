package db

import (
	"testing"

	"github.com/golang-migrate/migrate/v4/source/iofs"
)

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
