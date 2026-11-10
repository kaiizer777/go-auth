package goauth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	stderrors "errors"
	"strings"
	"sync"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
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
	return nil, stderrors.New("not implemented")
}

func (c *mockAuthConn) Close() error {
	c.closed = true
	return nil
}

func (c *mockAuthConn) Begin() (driver.Tx, error) {
	return nil, stderrors.New("not implemented")
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
	if !strings.Contains(err.Error(), "goauth: invalid configuration") {
		t.Fatalf("expected error containing 'goauth: invalid configuration', got: %v", err)
	}
	if !errors.Is(err, errors.ErrDatabaseURLRequired) {
		t.Fatalf("expected errors.Is(err, ErrDatabaseURLRequired), got: %v", err)
	}
	var appErr *errors.Error
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *errors.Error, got %T", err)
	}
	if appErr.Code() != errors.CodeInvalidConfig {
		t.Errorf("expected CodeInvalidConfig, got %s", appErr.Code())
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
		db: gormDB,
	}

	if err := auth.Close(); err != nil {
		t.Fatalf("auth.Close() failed: %v", err)
	}
}

func TestAuth_EmailDispatcher(t *testing.T) {
	dispatcher := email.NewAsyncDispatcher(email.DispatcherConfig{
		BaseURL:                   "https://example.com",
		DisableAsyncEmailDispatch: true,
	}, nil)
	auth := &Auth{
		emailDispatcher: dispatcher,
	}

	d := auth.EmailDispatcher()
	if d == nil {
		t.Fatal("expected non-nil email dispatcher, got nil")
	}
	if d != dispatcher {
		t.Fatalf("got dispatcher %v, want %v", d, dispatcher)
	}

	d.DispatchVerification(context.Background(), email.VerificationEmailPayload{
		UserID: "usr_test",
		To:     "test@example.com",
		Token:  "token_abc",
	})
}

func TestAuth_EmailDispatcher_Nil(t *testing.T) {
	var nilAuth *Auth
	if nilAuth.EmailDispatcher() != nil {
		t.Fatal("expected nil dispatcher for nil Auth")
	}

	emptyAuth := &Auth{}
	if emptyAuth.EmailDispatcher() != nil {
		t.Fatal("expected nil dispatcher for uninitialized Auth")
	}
}
