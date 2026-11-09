package db

import (
	"database/sql"
	"embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-migrate/migrate/v4"
	pgmigrate "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth/config"
)

//go:embed migrations/*.sql
var defaultMigrationsFS embed.FS

// Connect runs pending migrations, initializes the GORM PostgreSQL connection,
// and applies connection pooling limits.
func Connect(cfg config.Config) (*gorm.DB, error) {
	// 1. Run migrations first
	if err := runMigrations(cfg.DatabaseURL, cfg.MigrationsPath); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
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
		PrepareStmt:                              true,
	})
	if err != nil {
		return nil, fmt.Errorf("gorm open: %w", err)
	}

	// 3. Pool config
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("db ping failed: %w", err)
	}

	return db, nil
}

// runMigrations executes database migrations using either embedded migration files
// or a custom filesystem directory.
func runMigrations(databaseURL, migrationsPath string) error {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() {
		_ = db.Close()
	}()

	// validate connection before passing to migrate
	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping: %w", err)
	}

	driver, err := pgmigrate.WithInstance(db, &pgmigrate.Config{})
	if err != nil {
		return err
	}

	var m *migrate.Migrate
	if isDefaultMigrationsPath(migrationsPath) {
		sourceDriver, err := iofs.New(defaultMigrationsFS, "migrations")
		if err != nil {
			_ = driver.Close()
			return fmt.Errorf("init embedded migrations source: %w", err)
		}
		m, err = migrate.NewWithInstance("iofs", sourceDriver, "pgx", driver)
		if err != nil {
			_ = sourceDriver.Close()
			_ = driver.Close()
			return fmt.Errorf("init migrate instance: %w", err)
		}
	} else {
		sourceURL := fmt.Sprintf("file://%s", filepath.ToSlash(migrationsPath))
		m, err = migrate.NewWithDatabaseInstance(sourceURL, "pgx", driver)
		if err != nil {
			_ = driver.Close()
			return fmt.Errorf("init migrate instance: %w", err)
		}
	}

	defer func() {
		_, _ = m.Close()
	}()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	return nil
}

// isDefaultMigrationsPath reports whether the provided path represents the default embedded migrations directory.
func isDefaultMigrationsPath(p string) bool {
	clean := filepath.ToSlash(filepath.Clean(p))
	return p == "" || clean == "db/migrations"
}
