package db

import (
	"context"
	"database/sql"
	"embed"
	stderrors "errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	mysqlmigrate "github.com/golang-migrate/migrate/v4/database/mysql"
	pgmigrate "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

//go:embed migrations/*.sql migrations/mysql/*.sql
var defaultMigrationsFS embed.FS

const (
	defaultPingTimeout      = 5 * time.Second
	defaultMigrationTimeout = 30 * time.Second
)

var (
	runMigrationsFn      = runMigrations
	runMySQLMigrationsFn = runMySQLMigrations
	getSQLDBFn           = func(db *gorm.DB) (*sql.DB, error) { return db.DB() }
	sqlDBPingFn          = func(ctx context.Context, db *sql.DB) error { return db.PingContext(ctx) }
)

// Connect runs pending migrations, initializes the GORM database connection,
// and applies connection pooling limits.
func Connect(cfg config.Config) (*gorm.DB, error) {
	var dialector gorm.Dialector
	switch cfg.DatabaseType {
	case config.DatabaseTypeMySQL:
		if err := runMySQLMigrationsFn(cfg.DatabaseURL, cfg.MigrationsPath); err != nil {
			return nil, err
		}
		dialector = gormmysql.New(gormmysql.Config{
			DSN:                       cfg.DatabaseURL,
			SkipInitializeWithVersion: true,
		})
	default:
		if err := runMigrationsFn(cfg.DatabaseURL, cfg.MigrationsPath); err != nil {
			return nil, err
		}
		dialector = postgres.Open(cfg.DatabaseURL)
	}

	// 2. Open GORM
	gormLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true,
			Colorful:                  false,
		},
	)

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger:                                   gormLogger,
		DisableForeignKeyConstraintWhenMigrating: true,
		DisableAutomaticPing:                     true,
		PrepareStmt:                              true,
	})
	if err != nil {
		return nil, errors.New(errors.CodeDatabaseError, "gorm open failed", err)
	}

	// 3. Pool config
	sqlDB, err := getSQLDBFn(db)
	if err != nil {
		if closer, ok := db.ConnPool.(io.Closer); ok {
			_ = closer.Close()
		}
		return nil, errors.New(errors.CodeDatabaseError, "get sql.DB failed", err)
	}

	var success bool
	defer func() {
		if !success {
			_ = sqlDB.Close()
		}
	}()

	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	pingCtx, pingCancel := context.WithTimeout(context.Background(), defaultPingTimeout)
	defer pingCancel()

	if err := sqlDBPingFn(pingCtx, sqlDB); err != nil {
		return nil, errors.New(errors.CodeDatabaseUnavailable, "db ping failed", err)
	}

	success = true
	return db, nil
}

// runMigrations executes database migrations using either embedded migration files
// or a custom filesystem directory for PostgreSQL.
func runMigrations(databaseURL, migrationsPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultMigrationTimeout)
	defer cancel()

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return errors.New(errors.CodeDatabaseError, "open database connection failed", err)
	}

	// validate connection before passing to migrate
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return errors.New(errors.CodeDatabaseUnavailable, "ping database failed", err)
	}

	// Check out a dedicated connection explicitly: pgmigrate.WithInstance leaks
	// the checked-out *sql.Conn when its internal WithConnection call fails, so
	// the conn lifecycle is owned here instead. WithConnection leaves the driver
	// without a pool reference, so the pool is closed explicitly below.
	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return errors.New(errors.CodeDatabaseError, "checkout migration connection failed", err)
	}

	driver, err := pgmigrate.WithConnection(ctx, conn, &pgmigrate.Config{
		StatementTimeout: defaultMigrationTimeout,
	})
	if err != nil {
		_ = conn.Close()
		_ = db.Close()
		return errors.New(errors.CodeMigrationFailed, "initialize postgres migration driver failed", err)
	}

	var sourceDriver source.Driver
	if isDefaultMigrationsPath(migrationsPath) {
		sourceDriver, err = iofs.New(defaultMigrationsFS, "migrations")
		if err != nil {
			_ = driver.Close()
			_ = db.Close()
			return errors.New(errors.CodeMigrationFailed, "init embedded migrations source failed", err)
		}
	} else {
		sourceDriver, err = iofs.New(os.DirFS(migrationsPath), ".")
		if err != nil {
			_ = driver.Close()
			_ = db.Close()
			return errors.New(errors.CodeMigrationFailed, "init custom migrations source failed", err)
		}
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "pgx", driver)
	if err != nil {
		_ = sourceDriver.Close()
		_ = driver.Close()
		_ = db.Close()
		return errors.New(errors.CodeMigrationFailed, "init migrate instance failed", err)
	}

	defer func() {
		_, _ = m.Close()
		_ = db.Close()
	}()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return errors.New(errors.CodeMigrationFailed, "execute migrations failed", err)
	}
	return nil
}

// PrepareMySQLMigrationDSN parses the MySQL DSN and ensures multiStatements=true
// is enabled for migration scripts, while runtime connections keep multiStatements=false.
func PrepareMySQLMigrationDSN(databaseURL string) (string, error) {
	cfg, err := mysqlDriver.ParseDSN(databaseURL)
	if err != nil {
		return "", errors.New(errors.CodeDatabaseError, "parse mysql migration dsn failed", err)
	}
	cfg.MultiStatements = true
	return cfg.FormatDSN(), nil
}

// runMySQLMigrations executes database migrations using either embedded migration files
// or a custom filesystem directory for MySQL.
func runMySQLMigrations(databaseURL, migrationsPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultMigrationTimeout)
	defer cancel()

	migrationDSN, err := PrepareMySQLMigrationDSN(databaseURL)
	if err != nil {
		return err
	}

	db, err := sql.Open("mysql", migrationDSN)
	if err != nil {
		return errors.New(errors.CodeDatabaseError, "open database connection failed", err)
	}

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return errors.New(errors.CodeDatabaseUnavailable, "ping database failed", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return errors.New(errors.CodeDatabaseError, "checkout migration connection failed", err)
	}

	driver, err := mysqlmigrate.WithConnection(ctx, conn, &mysqlmigrate.Config{
		MigrationsTable:  "schema_migrations",
		StatementTimeout: defaultMigrationTimeout,
	})
	if err != nil {
		_ = conn.Close()
		_ = db.Close()
		return errors.New(errors.CodeMigrationFailed, "initialize mysql migration driver failed", err)
	}

	var sourceDriver source.Driver
	if isDefaultMigrationsPath(migrationsPath) {
		sourceDriver, err = iofs.New(defaultMigrationsFS, "migrations/mysql")
		if err != nil {
			_ = driver.Close()
			_ = db.Close()
			return errors.New(errors.CodeMigrationFailed, "init embedded migrations source failed", err)
		}
	} else {
		sourceDriver, err = iofs.New(os.DirFS(migrationsPath), ".")
		if err != nil {
			_ = driver.Close()
			_ = db.Close()
			return errors.New(errors.CodeMigrationFailed, "init custom migrations source failed", err)
		}
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "mysql", driver)
	if err != nil {
		_ = sourceDriver.Close()
		_ = driver.Close()
		_ = db.Close()
		return errors.New(errors.CodeMigrationFailed, "init migrate instance failed", err)
	}

	defer func() {
		_, _ = m.Close()
		_ = db.Close()
	}()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return errors.New(errors.CodeMigrationFailed, "execute migrations failed", err)
	}
	return nil
}

// NormalizeMySQLError maps database driver constraint violations (MySQL and PostgreSQL)
// to domain error sentinels, or returns the original error if unmapped.
func NormalizeMySQLError(err error) error {
	if err == nil {
		return nil
	}
	if stderrors.Is(err, gorm.ErrForeignKeyViolated) {
		return errors.ErrUserNotFound
	}
	var myErr *mysqlDriver.MySQLError
	if stderrors.As(err, &myErr) && myErr.Number == 1452 {
		return errors.ErrUserNotFound
	}
	var pgErr *pgconn.PgError
	if stderrors.As(err, &pgErr) && pgErr.Code == "23503" {
		return errors.ErrUserNotFound
	}

	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "1452") || strings.Contains(msg, "23503") ||
		strings.Contains(msg, "foreign key constraint fails") ||
		strings.Contains(msg, "violates foreign key constraint") ||
		strings.Contains(msg, "foreign key constraint") {
		return errors.ErrUserNotFound
	}

	is1062 := errors.Is(err, gorm.ErrDuplicatedKey) || (stderrors.As(err, &myErr) && myErr.Number == 1062)
	isDup := is1062 || (stderrors.As(err, &pgErr) && pgErr.Code == "23505") ||
		strings.Contains(msg, "1062") || strings.Contains(msg, "duplicate entry") ||
		strings.Contains(msg, "duplicate key") || strings.Contains(msg, "23505") ||
		strings.Contains(msg, "unique constraint")
	if !isDup {
		return err
	}

	switch {
	case strings.Contains(msg, "idx_users_email") || strings.Contains(msg, "users"):
		return errors.ErrEmailAlreadyExists
	case strings.Contains(msg, "totp_used_codes") || strings.Contains(msg, "uq_totp_used_codes"):
		return errors.ErrTOTPCodeReplayed
	case strings.Contains(msg, "totp_secrets") || strings.Contains(msg, "uq_totp_secrets"):
		return errors.ErrTOTPAlreadyEnabled
	case strings.Contains(msg, "oauth_accounts") || strings.Contains(msg, "uq_oauth_accounts"):
		return errors.ErrOAuthAccountAlreadyLinked
	default:
		return err
	}
}

// MigrationsFS returns the embedded migration filesystem.
func MigrationsFS() embed.FS {
	return defaultMigrationsFS
}

func isDefaultMigrationsPath(p string) bool {
	clean := filepath.ToSlash(filepath.Clean(p))
	return p == "" || clean == "db/migrations" || clean == "db/migrations/mysql" || clean == "migrations" || clean == "migrations/mysql"
}
