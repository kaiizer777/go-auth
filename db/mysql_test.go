package db

import (
	"context"
	"database/sql"
	stderrors "errors"
	"strings"
	"testing"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

func TestMySQLDefaultMigrationsEmbedded(t *testing.T) {
	driver, err := iofs.New(defaultMigrationsFS, "migrations/mysql")
	if err != nil {
		t.Fatalf("failed to init iofs driver for mysql migrations: %v", err)
	}
	defer func() {
		_ = driver.Close()
	}()

	first, err := driver.First()
	if err != nil {
		t.Fatalf("failed to read first mysql migration version: %v", err)
	}
	if first != 1 {
		t.Fatalf("first mysql migration = %d; want 1", first)
	}

	current := first
	count := 0
	for {
		count++
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

	if count != 11 {
		t.Fatalf("expected 11 mysql migration versions, found %d", count)
	}
}

func TestMySQLMigrations_NoExplicitTransactions(t *testing.T) {
	entries, err := defaultMigrationsFS.ReadDir("migrations/mysql")
	if err != nil {
		t.Fatalf("failed to read migrations/mysql dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		content, err := defaultMigrationsFS.ReadFile("migrations/mysql/" + entry.Name())
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

func TestMySQLMigrations_TableOptionsAndReverseDownOrder(t *testing.T) {
	entries, err := defaultMigrationsFS.ReadDir("migrations/mysql")
	if err != nil {
		t.Fatalf("failed to read migrations/mysql dir: %v", err)
	}

	const expectedOptions = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		content, err := defaultMigrationsFS.ReadFile("migrations/mysql/" + entry.Name())
		if err != nil {
			t.Fatalf("failed to read file %s: %v", entry.Name(), err)
		}
		text := string(content)
		if strings.Contains(strings.ToUpper(text), "CREATE TABLE") {
			if !strings.Contains(text, expectedOptions) {
				t.Errorf("file %s contains CREATE TABLE but lacks expected table options %q", entry.Name(), expectedOptions)
			}
		}
	}

	// Verify reverse drop order in 000008 down migration
	downContent, err := defaultMigrationsFS.ReadFile("migrations/mysql/000008_create_totp.down.sql")
	if err != nil {
		t.Fatalf("failed to read 000008 down migration: %v", err)
	}
	downText := string(downContent)

	idxTwoFactor := strings.Index(downText, "DROP TABLE IF EXISTS two_factor_tokens")
	idxTotpUsed := strings.Index(downText, "DROP TABLE IF EXISTS totp_used_codes")
	idxTotpSecrets := strings.Index(downText, "DROP TABLE IF EXISTS totp_secrets")

	if idxTwoFactor == -1 || idxTotpUsed == -1 || idxTotpSecrets == -1 {
		t.Fatalf("000008 down migration missing one or more required drop tables: %s", downText)
	}
	if idxTwoFactor > idxTotpUsed || idxTotpUsed > idxTotpSecrets {
		t.Errorf("000008 down drop order must be two_factor_tokens -> totp_used_codes -> totp_secrets, got indices %d, %d, %d",
			idxTwoFactor, idxTotpUsed, idxTotpSecrets)
	}
}

func TestMySQLMigration000007_DownRefusesOnLinkedAccounts(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/mysql/000007_create_oauth_accounts.down.sql")
	if err != nil {
		t.Fatalf("failed to read mysql migration 7 down: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "down refused") {
		t.Error("mysql migration 7 down must carry the refusal text")
	}
	guardIdx := strings.Index(content, "SELECT 1 FROM oauth_accounts")
	signalIdx := strings.Index(content, "SIGNAL SQLSTATE '45000'")
	if guardIdx == -1 {
		t.Fatal("mysql migration 7 down must gate refusal on oauth_accounts contents")
	}
	if signalIdx == -1 {
		t.Fatal("mysql migration 7 down missing SIGNAL SQLSTATE refusal")
	}
	if guardIdx > signalIdx {
		t.Errorf("mysql migration 7 data guard (idx %d) must precede refusal (idx %d)", guardIdx, signalIdx)
	}
	if strings.Contains(content, "SELECT 1 FROM users") {
		t.Error("mysql migration 7 down must not gate refusal on users-row existence")
	}
}

func TestMySQLMigration000008_DownRefusesOnTotpSecrets(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/mysql/000008_create_totp.down.sql")
	if err != nil {
		t.Fatalf("failed to read mysql migration 8 down: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "down refused") {
		t.Error("mysql migration 8 down must carry the refusal text")
	}
	guardIdx := strings.Index(content, "SELECT 1 FROM totp_secrets")
	signalIdx := strings.Index(content, "SIGNAL SQLSTATE '45000'")
	if guardIdx == -1 {
		t.Fatal("mysql migration 8 down must gate refusal on totp_secrets contents")
	}
	if signalIdx == -1 {
		t.Fatal("mysql migration 8 down missing SIGNAL SQLSTATE refusal")
	}
	if guardIdx > signalIdx {
		t.Errorf("mysql migration 8 data guard (idx %d) must precede refusal (idx %d)", guardIdx, signalIdx)
	}

	idxTwoFactor := strings.Index(content, "DROP TABLE IF EXISTS two_factor_tokens")
	idxTotpUsed := strings.Index(content, "DROP TABLE IF EXISTS totp_used_codes")
	idxTotpSecrets := strings.Index(content, "DROP TABLE IF EXISTS totp_secrets")
	if idxTwoFactor == -1 || idxTotpUsed == -1 || idxTotpSecrets == -1 {
		t.Fatal("mysql migration 8 down missing drop table statements")
	}
	if idxTwoFactor > idxTotpUsed || idxTotpUsed > idxTotpSecrets {
		t.Errorf("mysql migration 8 down drop order must be two_factor_tokens -> totp_used_codes -> totp_secrets, got indices %d, %d, %d",
			idxTwoFactor, idxTotpUsed, idxTotpSecrets)
	}
}

func TestMySQLMigration000009_AddsVerifiedFlag(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/mysql/000009_add_oauth_account_verified.up.sql")
	if err != nil {
		t.Fatalf("failed to read mysql migration 9 up: %v", err)
	}
	content := string(data)

	alterIdx := strings.Index(content, "ALTER TABLE oauth_accounts ADD COLUMN")
	if alterIdx == -1 || !strings.Contains(content, "verified TINYINT(1) NOT NULL DEFAULT 0") {
		t.Fatal("mysql migration 9 up must add oauth_accounts.verified as TINYINT(1) NOT NULL DEFAULT 0")
	}
	backfillIdx := strings.Index(content, "UPDATE oauth_accounts SET verified = 1")
	if backfillIdx == -1 {
		t.Fatal("mysql migration 9 up must backfill verified from the owning account")
	}
	if alterIdx > backfillIdx {
		t.Errorf("mysql migration 9 column add (idx %d) must precede the backfill (idx %d)", alterIdx, backfillIdx)
	}
	backfill := content[backfillIdx:]
	if semi := strings.Index(backfill, ";"); semi != -1 {
		backfill = backfill[:semi]
	}
	if !strings.Contains(backfill, "users.email_verified = 1") {
		t.Errorf("mysql migration 9 backfill must gate trust on users.email_verified: %q", backfill)
	}
	if !strings.Contains(backfill, "users.id = oauth_accounts.user_id") {
		t.Errorf("mysql migration 9 backfill must correlate the link to its owning user: %q", backfill)
	}

	downData, err := defaultMigrationsFS.ReadFile("migrations/mysql/000009_add_oauth_account_verified.down.sql")
	if err != nil {
		t.Fatalf("failed to read mysql migration 9 down: %v", err)
	}
	downContent := string(downData)
	if !strings.Contains(downContent, "ALTER TABLE oauth_accounts DROP COLUMN") || !strings.Contains(downContent, "verified") {
		t.Error("mysql migration 9 down must drop the verified column")
	}
	if strings.Contains(strings.ToUpper(downContent), "DROP TABLE") {
		t.Error("mysql migration 9 down must drop only the column, never the links table")
	}
	if strings.Contains(downContent, "loses no identity data") {
		t.Error("mysql migration 9 down must not claim the rollback is lossless")
	}
}

func TestMySQLMigration000002_SessionTimestampIndexes(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/mysql/000002_create_sessions.up.sql")
	if err != nil {
		t.Fatalf("failed to read mysql migration 2 up: %v", err)
	}
	content := string(data)

	requiredIndexes := []string{
		"CREATE INDEX idx_sessions_user_id ON sessions(user_id);",
		"CREATE INDEX idx_sessions_last_active_at ON sessions(last_active_at);",
		"CREATE INDEX idx_sessions_absolute_expires_at ON sessions(absolute_expires_at);",
	}

	for _, idx := range requiredIndexes {
		if !strings.Contains(content, idx) {
			t.Errorf("mysql migration 2 up missing expected index statement: %s", idx)
		}
	}
}

func TestNormalizeMySQLError(t *testing.T) {
	if got := NormalizeMySQLError(nil); got != nil {
		t.Errorf("NormalizeMySQLError(nil) = %v; want nil", got)
	}

	tests := []struct {
		name    string
		err     error
		wantErr error
	}{
		{
			name:    "foreign key violation via mysql 1452 error",
			err:     &mysqlDriver.MySQLError{Number: 1452, Message: "Cannot add or update a child row: a foreign key constraint fails"},
			wantErr: errors.ErrUserNotFound,
		},
		{
			name:    "foreign key violation via mysql string",
			err:     stderrors.New("Error 1452 (23000): Cannot add or update a child row: a foreign key constraint fails"),
			wantErr: errors.ErrUserNotFound,
		},
		{
			name:    "foreign key violation via postgres pgconn error",
			err:     &pgconn.PgError{Code: "23503", Message: "insert or update on table \"oauth_accounts\" violates foreign key constraint \"fk_oauth_accounts_user_id\""},
			wantErr: errors.ErrUserNotFound,
		},
		{
			name:    "foreign key violation via postgres string",
			err:     stderrors.New("ERROR: insert or update on table \"oauth_accounts\" violates foreign key constraint \"fk_oauth_accounts_user_id\" (SQLSTATE 23503)"),
			wantErr: errors.ErrUserNotFound,
		},
		{
			name:    "foreign key violation via gorm sentinel",
			err:     gorm.ErrForeignKeyViolated,
			wantErr: errors.ErrUserNotFound,
		},
		{
			name:    "email duplicate via MySQLError",
			err:     &mysqlDriver.MySQLError{Number: 1062, Message: "Duplicate entry 'test@example.com' for key 'users.idx_users_email_lower'"},
			wantErr: errors.ErrEmailAlreadyExists,
		},
		{
			name:    "totp used code duplicate via MySQLError",
			err:     &mysqlDriver.MySQLError{Number: 1062, Message: "Duplicate entry '...' for key 'totp_used_codes.uq_totp_used_codes_user_code'"},
			wantErr: errors.ErrTOTPCodeReplayed,
		},
		{
			name:    "totp secret duplicate via MySQLError",
			err:     &mysqlDriver.MySQLError{Number: 1062, Message: "Duplicate entry '...' for key 'totp_secrets.uq_totp_secrets_user_id'"},
			wantErr: errors.ErrTOTPAlreadyEnabled,
		},
		{
			name:    "oauth account duplicate via MySQLError",
			err:     &mysqlDriver.MySQLError{Number: 1062, Message: "Duplicate entry 'github-123' for key 'oauth_accounts.uq_oauth_accounts_provider_uid'"},
			wantErr: errors.ErrOAuthAccountAlreadyLinked,
		},
		{
			name:    "email duplicate via string",
			err:     stderrors.New("Error 1062 (23000): Duplicate entry 'test@example.com' for key 'idx_users_email_lower'"),
			wantErr: errors.ErrEmailAlreadyExists,
		},
		{
			name:    "totp used code duplicate via string",
			err:     stderrors.New("Error 1062 (23000): Duplicate entry 'code' for key 'uq_totp_used_codes_user_code'"),
			wantErr: errors.ErrTOTPCodeReplayed,
		},
		{
			name:    "totp secret duplicate via string",
			err:     stderrors.New("Error 1062 (23000): Duplicate entry 'uid' for key 'uq_totp_secrets_user_id'"),
			wantErr: errors.ErrTOTPAlreadyEnabled,
		},
		{
			name:    "oauth account duplicate via string",
			err:     stderrors.New("Error 1062 (23000): Duplicate entry 'p-uid' for key 'uq_oauth_accounts_provider_uid'"),
			wantErr: errors.ErrOAuthAccountAlreadyLinked,
		},
		{
			name:    "unmapped 1062 key returns original error",
			err:     stderrors.New("Error 1062 (23000): Duplicate entry 'foo' for key 'other_table.idx_foo'"),
			wantErr: stderrors.New("Error 1062 (23000): Duplicate entry 'foo' for key 'other_table.idx_foo'"),
		},
		{
			name:    "non-1062 error returns original error",
			err:     stderrors.New("Error 1146 (42S02): Table 'test.unknown' doesn't exist"),
			wantErr: stderrors.New("Error 1146 (42S02): Table 'test.unknown' doesn't exist"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeMySQLError(tt.err)
			if !errors.Is(got, tt.wantErr) && got.Error() != tt.wantErr.Error() {
				t.Errorf("NormalizeMySQLError() = %v; want %v", got, tt.wantErr)
			}
		})
	}
}

func TestConnect_MySQLPingFailureAndPoolSettings(t *testing.T) {
	oldRunMySQLMigrations := runMySQLMigrationsFn
	oldSQLDBPing := sqlDBPingFn
	t.Cleanup(func() {
		runMySQLMigrationsFn = oldRunMySQLMigrations
		sqlDBPingFn = oldSQLDBPing
	})

	runMySQLMigrationsFn = func(databaseURL, migrationsPath string) error {
		return nil
	}

	var capturedStats sql.DBStats
	var capturedDB *sql.DB
	var capturedCtx context.Context
	sqlDBPingFn = func(ctx context.Context, db *sql.DB) error {
		capturedCtx = ctx
		capturedDB = db
		capturedStats = db.Stats()
		return stderrors.New("mysql ping connection refused")
	}

	cfg := config.Config{
		DatabaseType:    config.DatabaseTypeMySQL,
		DatabaseURL:     "testuser:testpass@tcp(127.0.0.1:33069)/testdb?parseTime=true&timeout=1s",
		MaxOpenConns:    35,
		MaxIdleConns:    7,
		ConnMaxLifetime: 20 * time.Minute,
		ConnMaxIdleTime: 10 * time.Minute,
	}

	gormDB, err := Connect(cfg)
	if err == nil {
		if gormDB != nil {
			if sqlDB, errDB := gormDB.DB(); errDB == nil {
				_ = sqlDB.Close()
			}
		}
		t.Fatal("Connect expected mysql ping failure error, got nil")
	}

	var appErr *errors.Error
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseUnavailable {
		t.Fatalf("Connect error code = %v; want %v", appErr.Code(), errors.CodeDatabaseUnavailable)
	}
	if !strings.Contains(err.Error(), "db ping failed") {
		t.Fatalf("Connect error message = %q; want containing 'db ping failed'", err.Error())
	}

	if capturedStats.MaxOpenConnections != 35 {
		t.Fatalf("capturedStats.MaxOpenConnections = %d; want 35", capturedStats.MaxOpenConnections)
	}

	if capturedCtx == nil {
		t.Fatal("expected non-nil context passed to sqlDBPingFn")
	}
	if _, ok := capturedCtx.Deadline(); !ok {
		t.Fatal("expected bounded context deadline on sqlDBPingFn")
	}

	if capturedDB != nil {
		if pingErr := capturedDB.Ping(); pingErr == nil || !strings.Contains(pingErr.Error(), "sql: database is closed") {
			t.Fatalf("expected sql.DB to be closed on ping failure, got ping err = %v", pingErr)
		}
	}
}

func TestConnect_MySQLMigrationFailure(t *testing.T) {
	oldRunMySQLMigrations := runMySQLMigrationsFn
	t.Cleanup(func() {
		runMySQLMigrationsFn = oldRunMySQLMigrations
	})

	expectedErr := errors.New(errors.CodeMigrationFailed, "mysql migration syntax error", stderrors.New("table exists"))
	runMySQLMigrationsFn = func(databaseURL, migrationsPath string) error {
		return expectedErr
	}

	cfg := config.Config{
		DatabaseType: config.DatabaseTypeMySQL,
		DatabaseURL:  "user:pass@tcp(127.0.0.1:3306)/testdb?parseTime=true",
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

	if !errors.Is(err, expectedErr) {
		t.Fatalf("Connect error = %v; want %v", err, expectedErr)
	}
}

func TestRunMySQLMigrations_InvalidURL(t *testing.T) {
	err := runMySQLMigrations("invalid-dsn", "")
	if err == nil {
		t.Fatal("runMySQLMigrations with invalid database URL expected error, got nil")
	}
}

func TestIsDefaultMigrationsPath_MySQL(t *testing.T) {
	paths := []string{
		"db/migrations/mysql",
		"./db/migrations/mysql",
		"migrations/mysql",
	}
	for _, p := range paths {
		if !isDefaultMigrationsPath(p) {
			t.Errorf("isDefaultMigrationsPath(%q) = false; want true", p)
		}
	}
}

func TestPrepareMySQLMigrationDSN_MultiStatements(t *testing.T) {
	rawDSN := "testuser:secretpassword@tcp(127.0.0.1:3306)/authdb?parseTime=true"

	// 1. Initial raw DSN must have MultiStatements == false
	initialCfg, err := mysqlDriver.ParseDSN(rawDSN)
	if err != nil {
		t.Fatalf("failed to parse initial DSN: %v", err)
	}
	if initialCfg.MultiStatements {
		t.Fatalf("expected initial DSN MultiStatements to be false, got true")
	}

	// 2. Migration DSN prepared via PrepareMySQLMigrationDSN must have MultiStatements == true
	migrationDSN, err := PrepareMySQLMigrationDSN(rawDSN)
	if err != nil {
		t.Fatalf("PrepareMySQLMigrationDSN failed: %v", err)
	}

	parsedMigrationCfg, err := mysqlDriver.ParseDSN(migrationDSN)
	if err != nil {
		t.Fatalf("failed to parse prepared migration DSN: %v", err)
	}
	if !parsedMigrationCfg.MultiStatements {
		t.Fatalf("expected migration DSN MultiStatements to be true, got false")
	}

	// 3. Invalid DSN must return a wrapped error
	_, err = PrepareMySQLMigrationDSN("invalid://dsn/format")
	if err == nil {
		t.Fatal("expected error when preparing invalid DSN, got nil")
	}
	var appErr *errors.Error
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
		t.Fatalf("expected CodeDatabaseError, got: %v", err)
	}
}

func TestMySQLMigration000010_DeduplicatesMicrosoftOIDLinks(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/mysql/000010_resolve_microsoft_oid_links.up.sql")
	if err != nil {
		t.Fatalf("failed to read mysql migration 10 up: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "DELETE a FROM oauth_accounts a") {
		t.Fatal("mysql migration 10 up must delete duplicate oauth_accounts")
	}
	if !strings.Contains(content, "a.provider_id = 'microsoft'") {
		t.Fatal("mysql migration 10 up must be scoped to microsoft provider")
	}

	downData, err := defaultMigrationsFS.ReadFile("migrations/mysql/000010_resolve_microsoft_oid_links.down.sql")
	if err != nil {
		t.Fatalf("failed to read mysql migration 10 down: %v", err)
	}
	if len(downData) == 0 {
		t.Fatal("mysql migration 10 down file must exist")
	}
}

// TestMySQLMigration000011_TenantQualifiesIdentityKey mirrors the Postgres
// assertions on MySQL's non-transactional DDL.
func TestMySQLMigration000011_TenantQualifiesIdentityKey(t *testing.T) {
	data, err := defaultMigrationsFS.ReadFile("migrations/mysql/000011_add_oauth_account_tenant.up.sql")
	if err != nil {
		t.Fatalf("failed to read mysql migration 11 up: %v", err)
	}
	content := string(data)

	columnIdx := strings.Index(content, "ADD COLUMN provider_tenant_id VARCHAR(64)")
	if columnIdx == -1 {
		t.Fatalf("mysql migration 11 up must add provider_tenant_id: %q", content)
	}
	columnStmt := upToSemicolon(content[columnIdx:])
	if !strings.Contains(columnStmt, "NOT NULL") {
		t.Fatal("mysql migration 11 up must require the tenant")
	}
	if strings.Contains(columnStmt, "DEFAULT") {
		t.Fatalf("mysql migration 11 up must not default the tenant: %q", columnStmt)
	}

	guardIdx := strings.Index(content, "INSERT INTO oauth_accounts")
	if guardIdx == -1 {
		t.Fatal("mysql migration 11 up must refuse a non-empty oauth_accounts table")
	}
	if guardIdx > columnIdx {
		t.Errorf("mysql migration 11 empty-table guard must run before the column add: guard=%d column=%d", guardIdx, columnIdx)
	}
	if !strings.Contains(content[guardIdx:columnIdx], "FROM oauth_accounts LIMIT 1") {
		t.Fatal("mysql migration 11 guard must copy at most one existing row back into the table")
	}
	for _, privileged := range []string{"PROCEDURE", "TEMPORARY TABLE"} {
		if strings.Contains(content, privileged) {
			t.Fatalf("mysql migration 11 guard must not need %s privileges", privileged)
		}
	}

	newKeyIdx := strings.Index(content, "CREATE UNIQUE INDEX uq_oauth_accounts_provider_tenant_uid")
	if newKeyIdx == -1 {
		t.Fatal("mysql migration 11 up must create the tenant-qualified unique index")
	}
	if !strings.Contains(content[newKeyIdx:], "(provider_id, provider_tenant_id, provider_user_id)") {
		t.Fatal("mysql migration 11 up must key uniqueness on provider, tenant and provider user id")
	}

	dropOldIdx := strings.Index(content, "DROP INDEX uq_oauth_accounts_provider_uid")
	if dropOldIdx == -1 {
		t.Fatal("mysql migration 11 up must drop the tenant-blind unique constraint")
	}
	if columnIdx > newKeyIdx || newKeyIdx > dropOldIdx {
		t.Errorf("mysql migration 11 ordering must be column, new index, drop old constraint: column=%d new=%d drop=%d", columnIdx, newKeyIdx, dropOldIdx)
	}

	downData, err := defaultMigrationsFS.ReadFile("migrations/mysql/000011_add_oauth_account_tenant.down.sql")
	if err != nil {
		t.Fatalf("failed to read mysql migration 11 down: %v", err)
	}
	if !strings.Contains(string(downData), "DROP COLUMN provider_tenant_id") {
		t.Fatal("mysql migration 11 down must drop the tenant column it added")
	}
}
