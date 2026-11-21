package matrix_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
	mongostore "github.com/kaiizer777/go-auth/db/mongo"
)

const matrixTestEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestAdapter encapsulates a database engine and its go-auth application instance.
type TestAdapter struct {
	Name                 string
	Store                db.Store
	DB                   *gorm.DB
	App                  *goauth.Auth
	Config               config.Config
	SupportsTransactions bool
	Cleanup              func()
}

func baseConfig() config.Config {
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://postgres:postgres@localhost:5432/testdb"
	cfg.BaseURL = "http://localhost:8080"
	cfg.DisableAsyncEmailDispatch = true
	cfg.SessionIdleTimeout = 30 * time.Minute
	cfg.SessionAbsoluteMaxAge = 24 * time.Hour
	cfg.SessionCookieSecure = false
	cfg.RateLimitLoginMax = 100
	cfg.RateLimitLoginIPMax = 100
	cfg.RateLimitSignupMax = 100
	cfg.RateLimitSignupIPMax = 100
	cfg.TOTP.EncryptionKey = matrixTestEncryptionKey
	cfg.TOTP.Issuer = "GoAuthMatrixTest"
	cfg.TOTP.ChallengeTokenTTL = 5 * time.Minute
	cfg.TOTP.MaxAttemptsPerWindow = 20
	cfg.TOTP.AttemptWindow = 5 * time.Minute
	return cfg
}

func setupSQLiteAdapter(t *testing.T) TestAdapter {
	t.Helper()
	dbName := fmt.Sprintf("file:matrix_%d_%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)", time.Now().UnixNano(), uuid.New().String())
	database, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	sqlDB, err := database.DB()
	if err != nil {
		t.Fatalf("failed to get sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	// Enforce foreign key constraints and busy timeout in SQLite
	if err := database.Exec("PRAGMA foreign_keys = ON;").Error; err != nil {
		t.Fatalf("failed to enable foreign keys: %v", err)
	}
	if err := database.Exec("PRAGMA busy_timeout = 10000;").Error; err != nil {
		t.Fatalf("failed to set busy timeout: %v", err)
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
	CREATE TABLE IF NOT EXISTS verification_tokens (
		token_hash BLOB PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		token_hash BLOB PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		id_hash CHAR(64) UNIQUE NOT NULL,
		session_type VARCHAR(10) NOT NULL DEFAULT 'cookie',
		ip_address VARCHAR(45) NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '',
		credential_version INTEGER NOT NULL DEFAULT 0,
		last_active_at DATETIME NOT NULL,
		absolute_expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS oauth_accounts (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		provider_id VARCHAR(32) NOT NULL,
		provider_user_id VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL,
		created_at DATETIME,
		updated_at DATETIME,
		CONSTRAINT uq_oauth_accounts_provider_uid UNIQUE (provider_id, provider_user_id)
	);
	CREATE TABLE IF NOT EXISTS totp_secrets (
		id TEXT PRIMARY KEY,
		user_id TEXT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		encrypted_secret BLOB NOT NULL,
		backup_codes TEXT NOT NULL DEFAULT '[]',
		enabled INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS totp_used_codes (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		code_hash BLOB NOT NULL,
		used_at DATETIME NOT NULL,
		CONSTRAINT uq_totp_used_codes_user_code UNIQUE (user_id, code_hash)
	);
	CREATE TABLE IF NOT EXISTS two_factor_tokens (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash BLOB UNIQUE NOT NULL,
		expires_at DATETIME NOT NULL,
		attempts INTEGER NOT NULL DEFAULT 0
	);`
	if err := database.Exec(ddl).Error; err != nil {
		t.Fatalf("failed to execute sqlite ddl: %v", err)
	}

	cfg := baseConfig()
	app, err := goauth.NewWithDB(database, cfg)
	if err != nil {
		t.Fatalf("goauth.NewWithDB failed for sqlite: %v", err)
	}

	store := gormstore.New(database)

	return TestAdapter{
		Name:                 "SQLite",
		Store:                store,
		DB:                   database,
		App:                  app,
		Config:               cfg,
		SupportsTransactions: true,
		Cleanup: func() {
			truncateSQLTables(database)
			_ = app.Close()
		},
	}
}

func truncateSQLTables(database *gorm.DB) {
	if database == nil {
		return
	}
	tables := []string{
		"two_factor_tokens",
		"totp_used_codes",
		"totp_secrets",
		"oauth_accounts",
		"sessions",
		"password_reset_tokens",
		"verification_tokens",
		"users",
	}
	for _, tbl := range tables {
		_ = database.Exec(fmt.Sprintf("DELETE FROM %s;", tbl)).Error
	}
}

func setupPostgresAdapter(t *testing.T, pgURL string) (TestAdapter, error) {
	t.Helper()
	cfg := baseConfig()
	cfg.DatabaseType = config.DatabaseTypePostgres
	cfg.DatabaseURL = pgURL

	database, err := db.Connect(cfg)
	if err != nil {
		return TestAdapter{}, err
	}

	app, err := goauth.NewWithDB(database, cfg)
	if err != nil {
		if sqlDB, dbErr := database.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
		return TestAdapter{}, err
	}

	store := gormstore.New(database)

	return TestAdapter{
		Name:                 "PostgreSQL",
		Store:                store,
		DB:                   database,
		App:                  app,
		Config:               cfg,
		SupportsTransactions: true,
		Cleanup: func() {
			truncateSQLTables(database)
			_ = app.Close()
		},
	}, nil
}

func setupMySQLAdapter(t *testing.T, dsn string) (TestAdapter, error) {
	t.Helper()
	cfg := baseConfig()
	cfg.DatabaseType = config.DatabaseTypeMySQL
	cfg.DatabaseURL = dsn

	database, err := db.Connect(cfg)
	if err != nil {
		return TestAdapter{}, err
	}

	app, err := goauth.NewWithDB(database, cfg)
	if err != nil {
		if sqlDB, dbErr := database.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
		return TestAdapter{}, err
	}

	store := gormstore.New(database)

	return TestAdapter{
		Name:                 "MySQL",
		Store:                store,
		DB:                   database,
		App:                  app,
		Config:               cfg,
		SupportsTransactions: true,
		Cleanup: func() {
			truncateSQLTables(database)
			_ = app.Close()
		},
	}, nil
}

func setupMongoAdapter(t *testing.T, uri string) (TestAdapter, error) {
	t.Helper()
	cfg := baseConfig()
	cfg.DatabaseType = config.DatabaseTypeMongo
	cfg.DatabaseURL = uri
	dbName := fmt.Sprintf("goauth_test_%s", strings.ReplaceAll(uuid.New().String(), "-", ""))
	cfg.MongoDB.Database = dbName
	cfg.MongoDB.AllowNonTransactionalMongo = true

	store, err := mongostore.Connect(cfg)
	if err != nil {
		return TestAdapter{}, err
	}

	app, err := goauth.NewWithStore(store, cfg)
	if err != nil {
		_ = store.Close()
		return TestAdapter{}, err
	}

	// Dynamically test transaction capability
	var supportsTx bool
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if txErr := store.Transaction(ctx, func(txStore db.Store) error {
		return nil
	}); txErr == nil {
		supportsTx = true
	}

	return TestAdapter{
		Name:                 "MongoDB",
		Store:                store,
		App:                  app,
		Config:               cfg,
		SupportsTransactions: supportsTx,
		Cleanup: func() {
			_ = store.Database().Drop(context.Background())
			_ = app.Close()
		},
	}, nil
}

func getAvailableAdapters(t *testing.T) []TestAdapter {
	t.Helper()
	var adapters []TestAdapter

	// 1. SQLite (Always present, in-memory)
	adapters = append(adapters, setupSQLiteAdapter(t))

	// 2. PostgreSQL
	pgURL := os.Getenv("TEST_POSTGRES_URL")
	if pgURL == "" {
		pgURL = os.Getenv("TEST_DATABASE_URL")
	}
	if pgURL != "" {
		adapter, err := setupPostgresAdapter(t, pgURL)
		if err != nil {
			t.Fatalf("configured %s test backend failed to initialize: %v", "postgres", err)
		} else {
			adapters = append(adapters, adapter)
		}
	} else {
		t.Log("Skipping PostgreSQL matrix: TEST_POSTGRES_URL unset")
	}

	// 3. MySQL
	mysqlDSN := os.Getenv("TEST_MYSQL_DSN")
	if mysqlDSN != "" {
		adapter, err := setupMySQLAdapter(t, mysqlDSN)
		if err != nil {
			t.Fatalf("configured %s test backend failed to initialize: %v", "mysql", err)
		} else {
			adapters = append(adapters, adapter)
		}
	} else {
		t.Log("Skipping MySQL matrix: TEST_MYSQL_DSN unset")
	}

	// 4. MongoDB
	mongoURI := os.Getenv("TEST_MONGO_URI")
	if mongoURI != "" {
		adapter, err := setupMongoAdapter(t, mongoURI)
		if err != nil {
			t.Fatalf("configured %s test backend failed to initialize: %v", "mongodb", err)
		} else {
			adapters = append(adapters, adapter)
		}
	} else {
		t.Log("Skipping MongoDB matrix: TEST_MONGO_URI unset")
	}

	return adapters
}

func testMatrix(t *testing.T, fn func(t *testing.T, auth *goauth.Auth, store db.Store)) {
	t.Helper()
	adapters := getAvailableAdapters(t)
	for _, a := range adapters {
		a := a
		t.Run(a.Name, func(t *testing.T) {
			defer a.Cleanup()
			fn(t, a.App, a.Store)
		})
	}
}

func TestMatrixHarness(t *testing.T) {
	testMatrix(t, func(t *testing.T, auth *goauth.Auth, store db.Store) {
		if auth == nil || store == nil {
			t.Fatal("expected non-nil auth and store from testMatrix")
		}
	})
}

func runMatrix(t *testing.T, fn func(t *testing.T, adapter TestAdapter)) {
	t.Helper()
	adapters := getAvailableAdapters(t)
	for _, a := range adapters {
		a := a
		t.Run(a.Name, func(t *testing.T) {
			defer a.Cleanup()
			fn(t, a)
		})
	}
}

func createTestUser(t *testing.T, store db.Store, email, rawPassword string, verified bool) *db.User {
	t.Helper()
	hash, err := crypto.HashPassword(rawPassword, crypto.DefaultHashParams())
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user := &db.User{
		ID:                uuid.New(),
		Email:             email,
		PasswordHash:      hash,
		CredentialVersion: 0,
		EmailVerified:     verified,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
	if err := store.Users().Create(context.Background(), user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	return user
}

func init() {
	suppressLogs()
}

func suppressLogs() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
}
