package totp

import (
	"log/slog"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/kaiizer777/go-auth/config"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite db: %v", err)
	}
	return db
}

func TestNewService_NilDBPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("expected panic on nil DB, got none")
		}
	}()

	cfg := config.DefaultTOTPConfig()
	_ = NewService(nil, cfg, nil, nil)
}

func TestNewService_Defaults(t *testing.T) {
	t.Parallel()

	db := setupTestDB(t)
	cfg := config.TOTPConfig{
		EncryptionKey: validTestHexKey(),
	}

	svc := NewService(db, cfg, nil, nil)
	concrete, ok := svc.(*totpService)
	if !ok {
		t.Fatalf("expected *totpService, got %T", svc)
	}

	if concrete.cfg.Issuer != "go-auth" {
		t.Errorf("expected default issuer go-auth, got %s", concrete.cfg.Issuer)
	}
	if concrete.cfg.ChallengeTokenTTL != 10*time.Minute {
		t.Errorf("expected default challenge ttl 10m, got %v", concrete.cfg.ChallengeTokenTTL)
	}
	if concrete.cfg.MaxAttemptsPerWindow != 5 {
		t.Errorf("expected default max attempts 5, got %d", concrete.cfg.MaxAttemptsPerWindow)
	}
	if concrete.logger == nil || concrete.logger != slog.Default() {
		t.Errorf("expected default logger slog.Default()")
	}
}
