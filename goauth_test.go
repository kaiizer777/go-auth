package goauth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	stderrors "errors"
	"strings"
	"sync"
	"testing"

	"github.com/glebarez/sqlite"
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

func TestNew_DatabaseConnectionError(t *testing.T) {
	cfg := config.Config{
		DatabaseURL: "postgres://invalid:invalid@127.0.0.1:54329/nonexistent?sslmode=disable&connect_timeout=1",
		BaseURL:     "https://example.com",
	}

	auth, err := New(cfg)
	if err == nil {
		if auth != nil {
			_ = auth.Close()
		}
		t.Fatal("expected error with unreachable database, got nil")
	}

	if !strings.Contains(err.Error(), "goauth: failed to connect to database") {
		t.Fatalf("expected error containing 'goauth: failed to connect to database', got %v", err)
	}

	var appErr *errors.Error
	if !errors.As(err, &appErr) || (appErr.Code() != errors.CodeDatabaseUnavailable && appErr.Code() != errors.CodeDatabaseError) {
		t.Fatalf("expected CodeDatabaseUnavailable or CodeDatabaseError, got %v", appErr.Code())
	}
	if auth != nil {
		t.Fatalf("expected nil Auth on error, got %+v", auth)
	}

	// Also verify that a generic (non-appErr) DB connection error wraps with CodeDatabaseError
	oldDBConnect := dbConnectFn
	t.Cleanup(func() {
		dbConnectFn = oldDBConnect
	})
	dbConnectFn = func(cfg config.Config) (*gorm.DB, error) {
		return nil, stderrors.New("raw connection failure")
	}

	_, err = New(cfg)
	if err == nil {
		t.Fatal("expected error with raw connection failure, got nil")
	}
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
		t.Fatalf("expected CodeDatabaseError for raw error, got %v", appErr.Code())
	}
}

func TestNew_SuccessAndWiring(t *testing.T) {
	oldDBConnect := dbConnectFn
	t.Cleanup(func() {
		dbConnectFn = oldDBConnect
	})

	sqliteDB, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		DisableAutomaticPing: true,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, errDB := sqliteDB.DB(); errDB == nil {
			_ = sqlDB.Close()
		}
	})

	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		email_verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS verification_tokens (
		token_hash BLOB PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		token_hash BLOB PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	`
	if err := sqliteDB.Exec(ddl).Error; err != nil {
		t.Fatalf("failed to execute sqlite ddl: %v", err)
	}

	dbConnectFn = func(cfg config.Config) (*gorm.DB, error) {
		return sqliteDB, nil
	}

	var verificationPayload email.VerificationEmailPayload
	var resetPayload email.PasswordResetEmailPayload

	cfg := config.Config{
		DatabaseURL:               "postgres://user:pass@localhost:5432/testdb",
		BaseURL:                   "https://auth.example.com",
		DisableAsyncEmailDispatch: true,
		SendVerificationEmail: func(ctx context.Context, payload email.VerificationEmailPayload) error {
			verificationPayload = payload
			return nil
		},
		SendPasswordResetEmail: func(ctx context.Context, payload email.PasswordResetEmailPayload) error {
			resetPayload = payload
			return nil
		},
	}

	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New(cfg) unexpected err = %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil Auth, got nil")
	}
	if a.Handler == nil {
		t.Fatal("expected non-nil Handler, got nil")
	}
	if a.Auth == nil {
		t.Fatal("expected non-nil Auth service, got nil")
	}
	if a.EmailDispatcher() == nil {
		t.Fatal("expected non-nil EmailDispatcher, got nil")
	}

	// Trigger email dispatcher verification and reset to verify hook wiring
	a.EmailDispatcher().DispatchVerification(context.Background(), email.VerificationEmailPayload{
		UserID: "usr_123",
		To:     "user@example.com",
		Token:  "test-token",
	})
	if verificationPayload.To != "user@example.com" {
		t.Fatalf("verificationPayload.To = %q; want 'user@example.com'", verificationPayload.To)
	}

	a.EmailDispatcher().DispatchPasswordReset(context.Background(), email.PasswordResetEmailPayload{
		UserID: "usr_123",
		To:     "user@example.com",
		Token:  "test-token",
	})
	if resetPayload.To != "user@example.com" {
		t.Fatalf("resetPayload.To = %q; want 'user@example.com'", resetPayload.To)
	}

	// Verify Close cleans up cleanly
	if err := a.Close(); err != nil {
		t.Fatalf("a.Close() unexpected err = %v", err)
	}
}
