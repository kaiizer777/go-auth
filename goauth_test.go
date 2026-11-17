package goauth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	stderrors "errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
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

	// Repeated calls must be idempotent and safe
	if err := auth.Close(); err != nil {
		t.Fatalf("second auth.Close() failed: %v", err)
	}
}

func TestAuth_Close_ConcurrentIdempotent(t *testing.T) {
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
		db:          gormDB,
		limiterDone: make(chan struct{}),
	}

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = auth.Close()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d close error: %v", i, err)
		}
	}
}

func TestAuth_Close_ShutsDownEmailDispatcher(t *testing.T) {
	var inFlight atomic.Int32
	var completed atomic.Int32
	unblock := make(chan struct{})

	dispatcher := email.NewAsyncDispatcher(email.DispatcherConfig{
		BaseURL: "https://example.com",
		SendVerificationEmail: func(ctx context.Context, payload email.VerificationEmailPayload) error {
			inFlight.Add(1)
			<-unblock
			completed.Add(1)
			return nil
		},
		EmailDispatchTimeout: 5 * time.Second,
	}, nil)

	auth := &Auth{
		emailDispatcher: dispatcher,
	}

	for i := 0; i < 3; i++ {
		auth.EmailDispatcher().DispatchVerification(context.Background(), email.VerificationEmailPayload{To: "user@example.com"})
	}

	for i := 0; i < 50; i++ {
		if inFlight.Load() == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- auth.Close()
	}()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Auth.Close() failed: %v", err)
		}
		t.Fatal("Auth.Close() returned before in-flight email dispatches completed")
	case <-time.After(50 * time.Millisecond):
	}

	close(unblock)

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("unexpected error from Auth.Close(): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Auth.Close() timed out waiting for email dispatcher shutdown")
	}

	if got := completed.Load(); got != 3 {
		t.Fatalf("completed dispatches = %d, want 3", got)
	}
}

func TestAuth_Close_EmailDispatcherShutdownTimeoutBounded(t *testing.T) {
	var inFlight atomic.Int32
	hang := make(chan struct{})
	defer close(hang)

	dispatcher := email.NewAsyncDispatcher(email.DispatcherConfig{
		BaseURL: "https://example.com",
		SendVerificationEmail: func(ctx context.Context, payload email.VerificationEmailPayload) error {
			inFlight.Add(1)
			<-hang
			return nil
		},
		EmailDispatchTimeout: 5 * time.Second,
	}, nil)

	auth := &Auth{
		cfg: config.Config{
			EmailDispatchTimeout: 100 * time.Millisecond,
		},
		emailDispatcher: dispatcher,
	}

	auth.EmailDispatcher().DispatchVerification(context.Background(), email.VerificationEmailPayload{To: "user@example.com"})

	for i := 0; i < 50; i++ {
		if inFlight.Load() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	start := time.Now()
	err := auth.Close()
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded from bounded shutdown, got: %v", err)
	}
	if elapsed > 1*time.Second {
		t.Fatalf("auth.Close() took %v, expected bounded shutdown under 1s", elapsed)
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
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://invalid:invalid@127.0.0.1:54329/nonexistent?sslmode=disable&connect_timeout=1"
	cfg.BaseURL = "https://example.com"

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
		credential_version INTEGER NOT NULL DEFAULT 0,
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
		id_hash CHAR(64) UNIQUE NOT NULL,
		session_type VARCHAR(10) NOT NULL DEFAULT 'cookie',
		ip_address VARCHAR(45) NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '',
		credential_version INTEGER NOT NULL DEFAULT 0,
		last_active_at DATETIME NOT NULL,
		absolute_expires_at DATETIME NOT NULL,
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

	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://auth.example.com"
	cfg.DisableAsyncEmailDispatch = true
	cfg.SendVerificationEmail = func(ctx context.Context, payload email.VerificationEmailPayload) error {
		verificationPayload = payload
		return nil
	}
	cfg.SendPasswordResetEmail = func(ctx context.Context, payload email.PasswordResetEmailPayload) error {
		resetPayload = payload
		return nil
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

	if a.SessionService() == nil {
		t.Fatal("expected a.SessionService() to not be nil")
	}
	if a.RequireAuth(http.NotFoundHandler()) == nil {
		t.Fatal("expected a.RequireAuth middleware to not be nil")
	}
	if a.CSRF(http.NotFoundHandler()) == nil {
		t.Fatal("expected a.CSRF middleware to not be nil")
	}

	// Verify Close cleans up cleanly
	if err := a.Close(); err != nil {
		t.Fatalf("a.Close() unexpected err = %v", err)
	}
}

func TestNewWithDB_ZeroCleanupTick(t *testing.T) {
	sqliteDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableAutomaticPing: true,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		credential_version INTEGER NOT NULL DEFAULT 0,
		email_verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		id_hash CHAR(64) UNIQUE NOT NULL,
		session_type VARCHAR(10) NOT NULL DEFAULT 'cookie',
		ip_address VARCHAR(45) NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '',
		credential_version INTEGER NOT NULL DEFAULT 0,
		last_active_at DATETIME NOT NULL,
		absolute_expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	`
	if err := sqliteDB.Exec(ddl).Error; err != nil {
		t.Fatalf("failed to execute sqlite ddl: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://auth.example.com"
	cfg.RateLimitCleanupTick = 0

	a, err := NewWithDB(sqliteDB, cfg)
	if err != nil {
		t.Fatalf("NewWithDB unexpected err = %v", err)
	}
	defer func() { _ = a.Close() }()
	if a == nil {
		t.Fatal("expected non-nil Auth")
	}
}

func TestNewWithDB_InvalidConfig(t *testing.T) {
	sqliteDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableAutomaticPing: true,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	// Empty config missing DatabaseURL and BaseURL
	_, err = NewWithDB(sqliteDB, config.Config{})
	if err == nil {
		t.Fatal("expected NewWithDB to fail validation on empty config, got nil")
	}
	var appErr *errors.Error
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidConfig {
		t.Fatalf("expected CodeInvalidConfig, got %v", err)
	}
}

func TestNewWithDB_AppliesDefaults(t *testing.T) {
	sqliteDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableAutomaticPing: true,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		credential_version INTEGER NOT NULL DEFAULT 0,
		email_verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		id_hash CHAR(64) UNIQUE NOT NULL,
		session_type VARCHAR(10) NOT NULL DEFAULT 'cookie',
		ip_address VARCHAR(45) NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '',
		credential_version INTEGER NOT NULL DEFAULT 0,
		last_active_at DATETIME NOT NULL,
		absolute_expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	`
	if err := sqliteDB.Exec(ddl).Error; err != nil {
		t.Fatalf("failed to execute sqlite ddl: %v", err)
	}

	cfg := config.Config{
		DatabaseURL: "postgres://user:pass@localhost:5432/testdb",
		BaseURL:     "https://auth.example.com",
	}

	a, err := NewWithDB(sqliteDB, cfg)
	if err != nil {
		t.Fatalf("NewWithDB unexpected err = %v", err)
	}
	defer func() { _ = a.Close() }()

	if a.cfg.CSRFCookieName != "csrf_token" {
		t.Errorf("CSRFCookieName = %q; want %q", a.cfg.CSRFCookieName, "csrf_token")
	}
	if a.cfg.SessionIdleTimeout != 30*time.Minute {
		t.Errorf("SessionIdleTimeout = %v; want 30m", a.cfg.SessionIdleTimeout)
	}
}

func TestAuth_PurgeExpiredSessions(t *testing.T) {
	sqliteDB, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:purge_test_%d?mode=memory&cache=shared", time.Now().UnixNano())), &gorm.Config{
		DisableAutomaticPing: true,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	defer func() {
		if sqlDB, errDB := sqliteDB.DB(); errDB == nil {
			_ = sqlDB.Close()
		}
	}()

	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		credential_version INTEGER NOT NULL DEFAULT 0,
		email_verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		id_hash CHAR(64) UNIQUE NOT NULL,
		session_type VARCHAR(10) NOT NULL DEFAULT 'cookie',
		ip_address VARCHAR(45) NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '',
		credential_version INTEGER NOT NULL DEFAULT 0,
		last_active_at DATETIME NOT NULL,
		absolute_expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	`
	if err := sqliteDB.Exec(ddl).Error; err != nil {
		t.Fatalf("failed to execute sqlite ddl: %v", err)
	}

	cfg := config.Config{
		DatabaseURL: "postgres://user:pass@localhost:5432/testdb",
		BaseURL:     "https://auth.example.com",
	}

	a, err := NewWithDB(sqliteDB, cfg)
	if err != nil {
		t.Fatalf("NewWithDB failed: %v", err)
	}
	defer func() { _ = a.Close() }()

	now := time.Now().UTC()
	// Insert an expired session
	sqliteDB.Exec("INSERT INTO sessions (id, user_id, id_hash, session_type, last_active_at, absolute_expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		uuid.New().String(), uuid.New().String(), "hash1", "cookie", now.Add(-1*time.Hour), now.Add(-1*time.Hour), now.Add(-2*time.Hour))

	purged, err := a.PurgeExpiredSessions(context.Background())
	if err != nil {
		t.Fatalf("PurgeExpiredSessions failed: %v", err)
	}
	if purged != 1 {
		t.Fatalf("expected 1 purged session, got %d", purged)
	}
}
