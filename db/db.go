package db

import (
	"context"
	"database/sql"
	"embed"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-migrate/migrate/v4"
	pgmigrate "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

//go:embed migrations/*.sql
var defaultMigrationsFS embed.FS

const (
	defaultPingTimeout      = 5 * time.Second
	defaultMigrationTimeout = 30 * time.Second
)

var (
	runMigrationsFn = runMigrations
	getSQLDBFn      = func(db *gorm.DB) (*sql.DB, error) { return db.DB() }
	sqlDBPingFn     = func(ctx context.Context, db *sql.DB) error { return db.PingContext(ctx) }
)

// Connect runs pending migrations, initializes the GORM PostgreSQL connection,
// and applies connection pooling limits.
func Connect(cfg config.Config) (*gorm.DB, error) {
	// 1. Run migrations first
	if err := runMigrationsFn(cfg.DatabaseURL, cfg.MigrationsPath); err != nil {
		return nil, err
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

	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{
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
// or a custom filesystem directory.
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

	driver, err := pgmigrate.WithConnection(ctx, conn, &pgmigrate.Config{})
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

// MigrationsFS returns the embedded migration filesystem.
func MigrationsFS() embed.FS {
	return defaultMigrationsFS
}

func isDefaultMigrationsPath(p string) bool {
	clean := filepath.ToSlash(filepath.Clean(p))
	return p == "" || clean == "db/migrations"
}
