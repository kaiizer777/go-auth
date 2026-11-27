package db

import (
	"context"
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
	fs := MigrationsFS()
	driver, err := iofs.New(fs, "migrations")
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

func TestDefaultMigrations_NoExplicitTransactions(t *testing.T) {
	entries, err := defaultMigrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("failed to read migrations dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		content, err := defaultMigrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			t.Fatalf("failed to read migration file %s: %v", entry.Name(), err)
		}
		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			trimmed := strings.TrimSpace(line)
			upper := strings.ToUpper(trimmed)
			if upper == "BEGIN;" || upper == "BEGIN" || upper == "COMMIT;" || upper == "COMMIT" {
				t.Errorf("%s:%d contains explicit transaction control: %q", entry.Name(), lineNum+1, trimmed)
			}
		}
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
	var capturedCtx context.Context
	sqlDBPingFn = func(ctx context.Context, db *sql.DB) error {
		capturedCtx = ctx
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

	if capturedCtx == nil {
		t.Fatal("expected non-nil context passed to sqlDBPingFn")
	}
	if _, ok := capturedCtx.Deadline(); !ok {
		t.Fatal("expected bounded context deadline on sqlDBPingFn")
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

func TestMigration000005_TimestampBackfillAndDialectParity(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/000005_add_session_phase4_columns.up.sql")
	if err != nil {
		t.Fatalf("failed to read migration 5 up: %v", err)
	}
	content := string(data)

	if strings.Contains(content, "CREATE TYPE session_type AS ENUM") {
		t.Error("migration 5 must not create custom enum session_type")
	}

	if strings.Contains(content, "csrf_token") {
		t.Error("migration 5 must not reference dead csrf_token column")
	}

	backfillIdx := strings.Index(content, "UPDATE sessions SET absolute_expires_at = COALESCE(expires_at")
	dropIdx := strings.Index(content, "DROP COLUMN IF EXISTS expires_at")
	if backfillIdx == -1 {
		t.Fatal("migration 5 missing backfill for absolute_expires_at from expires_at")
	}
	if dropIdx == -1 {
		t.Fatal("migration 5 missing DROP COLUMN IF EXISTS expires_at")
	}
	if backfillIdx > dropIdx {
		t.Errorf("migration 5 backfill (idx %d) must occur before drop (idx %d)", backfillIdx, dropIdx)
	}
}

func TestMigration000006_UpAddsCredentialVersionColumns(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/000006_add_credential_version.up.sql")
	if err != nil {
		t.Fatalf("failed to read migration 6 up: %v", err)
	}
	content := string(data)

	if got := strings.Count(content, "BEGIN;"); got != 0 {
		t.Errorf("migration 6 up BEGIN count = %d; want 0", got)
	}
	if got := strings.Count(content, "COMMIT;"); got != 0 {
		t.Errorf("migration 6 up COMMIT count = %d; want 0", got)
	}

	for _, table := range []string{"users", "sessions"} {
		alterIdx := strings.Index(content, "ALTER TABLE "+table)
		if alterIdx == -1 {
			t.Errorf("migration 6 up missing ALTER TABLE %s", table)
			continue
		}
		colIdx := strings.Index(content[alterIdx:], "credential_version")
		if colIdx == -1 {
			t.Errorf("migration 6 up ALTER TABLE %s missing credential_version", table)
			continue
		}
		stmt := content[alterIdx:]
		if semi := strings.Index(stmt, ";"); semi != -1 {
			stmt = stmt[:semi]
		}
		if !strings.Contains(stmt, "NOT NULL") || !strings.Contains(stmt, "DEFAULT 0") {
			t.Errorf("migration 6 up %s.credential_version must be NOT NULL DEFAULT 0", table)
		}
	}

	usersIdx := strings.Index(content, "ALTER TABLE users")
	sessionsIdx := strings.Index(content, "ALTER TABLE sessions")
	if usersIdx == -1 || sessionsIdx == -1 {
		t.Fatal("migration 6 up must ALTER both users and sessions")
	}
	if usersIdx > sessionsIdx {
		t.Errorf("migration 6 up users ALTER (idx %d) must precede sessions ALTER (idx %d)", usersIdx, sessionsIdx)
	}
}

func TestMigration000006_DownRefusesVersionedDB(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/000006_add_credential_version.down.sql")
	if err != nil {
		t.Fatalf("failed to read migration 6 down: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "down refused") {
		t.Error("migration 6 down must carry the refusal text")
	}
	guardIdx := strings.Index(content, "credential_version <> 0")
	raiseIdx := strings.Index(content, "RAISE EXCEPTION")
	if guardIdx == -1 {
		t.Fatal("migration 6 down must gate refusal on non-zero credential_version rows")
	}
	if raiseIdx == -1 {
		t.Fatal("migration 6 down missing RAISE EXCEPTION refusal")
	}
	if guardIdx > raiseIdx {
		t.Errorf("migration 6 version guard (idx %d) must precede refusal (idx %d)", guardIdx, raiseIdx)
	}
	for _, table := range []string{"users", "sessions"} {
		if !strings.Contains(content, table) {
			t.Errorf("migration 6 down must guard %s", table)
		}
	}
}

func TestMigration000007_DownRefusesOnLinkedAccounts(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/000007_create_oauth_accounts.down.sql")
	if err != nil {
		t.Fatalf("failed to read migration 7 down: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "down refused") {
		t.Error("migration 7 down must carry the refusal text")
	}
	guardIdx := strings.Index(content, "SELECT 1 FROM oauth_accounts")
	raiseIdx := strings.Index(content, "RAISE EXCEPTION")
	if guardIdx == -1 {
		t.Fatal("migration 7 down must gate refusal on oauth_accounts contents")
	}
	if raiseIdx == -1 {
		t.Fatal("migration 7 down missing RAISE EXCEPTION refusal")
	}
	if guardIdx > raiseIdx {
		t.Errorf("migration 7 data guard (idx %d) must precede refusal (idx %d)", guardIdx, raiseIdx)
	}
	// Users rows alone must not block rollback: the down drops only
	// oauth_accounts, so users survive it untouched.
	if strings.Contains(content, "SELECT 1 FROM users") {
		t.Error("migration 7 down must not gate refusal on users-row existence")
	}
}

func TestMigration000009_BackfillTrustsVerifiedOwners(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/000009_add_oauth_account_verified.up.sql")
	if err != nil {
		t.Fatalf("failed to read migration 9 up: %v", err)
	}
	content := string(data)

	alterIdx := strings.Index(content, "ALTER TABLE oauth_accounts ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT FALSE")
	if alterIdx == -1 {
		t.Fatal("migration 9 up must add oauth_accounts.verified as NOT NULL DEFAULT FALSE")
	}
	backfillIdx := strings.Index(content, "UPDATE oauth_accounts SET verified = TRUE")
	if backfillIdx == -1 {
		t.Fatal("migration 9 up must backfill verified from the owning account")
	}
	if alterIdx > backfillIdx {
		t.Errorf("migration 9 column add (idx %d) must precede the backfill (idx %d)", alterIdx, backfillIdx)
	}

	backfill := content[backfillIdx:]
	if semi := strings.Index(backfill, ";"); semi != -1 {
		backfill = backfill[:semi]
	}
	if !strings.Contains(backfill, "users.email_verified") {
		t.Errorf("migration 9 backfill must gate trust on users.email_verified: %q", backfill)
	}
	if !strings.Contains(backfill, "users.id = oauth_accounts.user_id") {
		t.Errorf("migration 9 backfill must correlate the link to its owning user: %q", backfill)
	}
}

func TestMigrations_NoExplicitTransactionWrappers(t *testing.T) {
	files := []string{
		"migrations/000001_create_users.up.sql",
		"migrations/000001_create_users.down.sql",
		"migrations/000002_create_sessions.up.sql",
		"migrations/000002_create_sessions.down.sql",
		"migrations/000003_create_verification_tokens.up.sql",
		"migrations/000003_create_verification_tokens.down.sql",
		"migrations/000004_create_password_reset_tokens.up.sql",
		"migrations/000004_create_password_reset_tokens.down.sql",
		"migrations/000005_add_session_phase4_columns.up.sql",
		"migrations/000005_add_session_phase4_columns.down.sql",
		"migrations/000006_add_credential_version.up.sql",
		"migrations/000006_add_credential_version.down.sql",
		"migrations/000007_create_oauth_accounts.up.sql",
		"migrations/000007_create_oauth_accounts.down.sql",
		"migrations/000008_create_totp.up.sql",
		"migrations/000008_create_totp.down.sql",
		"migrations/000009_add_oauth_account_verified.up.sql",
		"migrations/000009_add_oauth_account_verified.down.sql",
		"migrations/000010_resolve_microsoft_oid_links.up.sql",
		"migrations/000010_resolve_microsoft_oid_links.down.sql",
		"migrations/000011_add_oauth_account_tenant.up.sql",
		"migrations/000011_add_oauth_account_tenant.down.sql",
		"migrations/000012_add_oauth_account_tokens.up.sql",
		"migrations/000012_add_oauth_account_tokens.down.sql",
		"migrations/mysql/000012_add_oauth_account_tokens.up.sql",
		"migrations/mysql/000012_add_oauth_account_tokens.down.sql",
	}

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			data, err := defaultMigrationsFS.ReadFile(file)
			if err != nil {
				t.Fatalf("failed to read migration file %s: %v", file, err)
			}
			content := strings.TrimSpace(string(data))
			if strings.HasPrefix(content, "BEGIN;") {
				t.Errorf("migration file %s must not begin with 'BEGIN;'", file)
			}
			if strings.HasSuffix(content, "COMMIT;") {
				t.Errorf("migration file %s must not end with 'COMMIT;'", file)
			}
		})
	}
}

func TestRunMigrations_ConfiguresStatementTimeout(t *testing.T) {
	data, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatalf("failed to read db.go: %v", err)
	}
	src := string(data)
	if !strings.Contains(src, "StatementTimeout: defaultMigrationTimeout") {
		t.Fatal("runMigrations must configure StatementTimeout: defaultMigrationTimeout in pgmigrate.Config")
	}
}

func TestMigration000010_DeduplicatesMicrosoftOIDLinks(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/000010_resolve_microsoft_oid_links.up.sql")
	if err != nil {
		t.Fatalf("failed to read migration 10 up: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "DELETE FROM oauth_accounts") {
		t.Fatal("migration 10 up must delete duplicate oauth_accounts")
	}
	if !strings.Contains(content, "provider_id = 'microsoft'") {
		t.Fatal("migration 10 up must be scoped to microsoft provider")
	}

	downData, err := defaultMigrationsFS.ReadFile("migrations/000010_resolve_microsoft_oid_links.down.sql")
	if err != nil {
		t.Fatalf("failed to read migration 10 down: %v", err)
	}
	if len(downData) == 0 {
		t.Fatal("migration 10 down file must exist")
	}
}

// TestMigration000011_TenantQualifiesIdentityKey pins the schema half of the fix
// for #72: the tenant joins the unique key, is required, and the tenant-blind
// constraint is gone.
func TestMigration000011_TenantQualifiesIdentityKey(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/000011_add_oauth_account_tenant.up.sql")
	if err != nil {
		t.Fatalf("failed to read migration 11 up: %v", err)
	}
	content := string(data)

	column := "ADD COLUMN IF NOT EXISTS provider_tenant_id VARCHAR(64) NOT NULL"
	columnIdx := strings.Index(content, column)
	if columnIdx == -1 {
		t.Fatalf("migration 11 up must add a required provider_tenant_id column: %q", content)
	}
	if columnStmt := upToSemicolon(content[columnIdx:]); strings.Contains(columnStmt, "DEFAULT") {
		t.Fatalf("migration 11 up must not default the tenant: %q", columnStmt)
	}

	newKey := "CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_accounts_provider_tenant_uid"
	newKeyIdx := strings.Index(content, newKey)
	if newKeyIdx == -1 {
		t.Fatal("migration 11 up must create the tenant-qualified unique index")
	}
	if !strings.Contains(content[newKeyIdx:], "provider_id, provider_tenant_id, provider_user_id") {
		t.Fatal("migration 11 up must key uniqueness on provider, tenant and provider user id")
	}

	dropOldIdx := strings.Index(content, "DROP CONSTRAINT IF EXISTS uq_oauth_accounts_provider_uid")
	if dropOldIdx == -1 {
		t.Fatal("migration 11 up must drop the tenant-blind unique constraint")
	}
	// The down migration restores the old key as a unique constraint, so the
	// re-applied up must drop that form too (and the plain index form an older
	// down left behind) or it keeps enforcing the old key.
	dropOldIndex := strings.Index(content, "DROP INDEX IF EXISTS uq_oauth_accounts_provider_uid")
	if dropOldIndex == -1 || dropOldIndex < dropOldIdx {
		t.Fatal("migration 11 up must drop the tenant-blind unique index after the constraint")
	}
	if columnIdx > newKeyIdx || newKeyIdx > dropOldIdx {
		t.Errorf("migration 11 ordering must be column, new index, drop old constraint: column=%d new=%d drop=%d", columnIdx, newKeyIdx, dropOldIdx)
	}

	downData, err := defaultMigrationsFS.ReadFile("migrations/000011_add_oauth_account_tenant.down.sql")
	if err != nil {
		t.Fatalf("failed to read migration 11 down: %v", err)
	}
	if !strings.Contains(string(downData), "DROP COLUMN IF EXISTS provider_tenant_id") {
		t.Fatal("migration 11 down must drop the tenant column it added")
	}
}

// TestMigration000012_AddsOAuthAccountTokens pins the token schema for #54: the
// four non-expiry columns are NOT NULL with an empty-string default so a legacy
// row reads as "no token stored", the expiry stays nullable, and the down
// migration drops exactly the columns the up added.
func TestMigration000012_AddsOAuthAccountTokens(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/000012_add_oauth_account_tokens.up.sql")
	if err != nil {
		t.Fatalf("failed to read migration 12 up: %v", err)
	}
	content := string(data)

	columns := []struct{ name, definition string }{
		{"access_token_ciphertext", "TEXT NOT NULL DEFAULT ''"},
		{"refresh_token_ciphertext", "TEXT NOT NULL DEFAULT ''"},
		{"refresh_token_fingerprint", "VARCHAR(64) NOT NULL DEFAULT ''"},
		{"token_expires_at", "TIMESTAMPTZ"},
		{"token_scope", "TEXT NOT NULL DEFAULT ''"},
	}

	lastIdx := -1
	for _, column := range columns {
		statement := "ADD COLUMN IF NOT EXISTS " + column.name + " " + column.definition
		idx := strings.Index(content, statement)
		if idx == -1 {
			t.Fatalf("migration 12 up must contain %q", statement)
		}
		if idx < lastIdx {
			t.Errorf("migration 12 up adds %s out of model order", column.name)
		}
		lastIdx = idx
		if stmt := upToSemicolon(content[idx:]); strings.Contains(stmt, "DEFAULT") && !strings.Contains(stmt, "DEFAULT ''") {
			t.Errorf("migration 12 up must not give %s a non-empty default: %q", column.name, stmt)
		}
	}

	downData, err := defaultMigrationsFS.ReadFile("migrations/000012_add_oauth_account_tokens.down.sql")
	if err != nil {
		t.Fatalf("failed to read migration 12 down: %v", err)
	}
	down := string(downData)
	if drops := strings.Count(down, "DROP COLUMN IF EXISTS"); drops != len(columns) {
		t.Fatalf("migration 12 down must drop exactly %d columns, got %d: %q", len(columns), drops, down)
	}
	for _, column := range columns {
		if !strings.Contains(down, "DROP COLUMN IF EXISTS "+column.name+";") {
			t.Errorf("migration 12 down must drop %s", column.name)
		}
	}
	if strings.Contains(down, "DROP TABLE") {
		t.Error("migration 12 down must drop only the token columns, never the links table")
	}
}

// upToSemicolon returns the statement starting at raw, without its terminator.
func upToSemicolon(raw string) string {
	if semi := strings.Index(raw, ";"); semi != -1 {
		return raw[:semi]
	}
	return raw
}
