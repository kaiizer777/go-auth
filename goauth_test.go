package goauth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
)

var registerMockOnce sync.Once

type mockAuthDriver struct{}

func (d *mockAuthDriver) Open(name string) (driver.Conn, error) {
	return &mockAuthConn{}, nil
}

type mockAuthConn struct {
	closed bool
}

func (c *mockAuthConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}

func (c *mockAuthConn) Close() error {
	c.closed = true
	return nil
}

func (c *mockAuthConn) Begin() (driver.Tx, error) {
	return nil, errors.New("not implemented")
}

func (c *mockAuthConn) Ping(ctx context.Context) error {
	return nil
}

func TestNew_InvalidConfig(t *testing.T) {
	cfg := config.Config{} // Missing DatabaseURL
	auth, err := New(cfg)
	if err == nil {
		t.Fatal("expected error with invalid config, got nil")
	}
	if auth != nil {
		t.Fatalf("expected nil Auth on error, got %+v", auth)
	}
}

func TestAuth_Close_NilDB(t *testing.T) {
	auth := &Auth{}
	if err := auth.Close(); err != nil {
		t.Fatalf("Close() on nil DB returned err = %v, want nil", err)
	}
}

func TestAuth_Close_WithDB(t *testing.T) {
	registerMockOnce.Do(func() {
		sql.Register("auth_mock_driver", &mockAuthDriver{})
	})

	sqlDB, err := sql.Open("auth_mock_driver", "mock")
	if err != nil {
		t.Fatalf("failed to open mock db: %v", err)
	}

	gormDB, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{
		DisableAutomaticPing: true,
	})
	if err != nil {
		t.Fatalf("failed to open gorm db: %v", err)
	}

	auth := &Auth{
		DB: gormDB,
	}

	if err := auth.Close(); err != nil {
		t.Fatalf("auth.Close() failed: %v", err)
	}
}
