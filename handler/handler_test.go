package handler

import (
	"context"
	"database/sql"
	"database/sql/driver"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
)

var registerMockOnce sync.Once

type mockDriver struct{}

func (d *mockDriver) Open(name string) (driver.Conn, error) {
	return &mockConn{healthy: name == "healthy"}, nil
}

type mockConn struct {
	healthy bool
}

func (c *mockConn) Prepare(query string) (driver.Stmt, error) {
	return nil, stderrors.New("not implemented")
}

func (c *mockConn) Close() error {
	return nil
}

func (c *mockConn) Begin() (driver.Tx, error) {
	return nil, stderrors.New("not implemented")
}

func (c *mockConn) Ping(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if !c.healthy {
		return stderrors.New("database ping error")
	}
	return nil
}

func newMockGormDB(t *testing.T, healthy bool) *gorm.DB {
	t.Helper()
	registerMockOnce.Do(func() {
		sql.Register("handler_mock_driver", &mockDriver{})
	})
	dsn := "unhealthy"
	if healthy {
		dsn = "healthy"
	}
	sqlDB, err := sql.Open("handler_mock_driver", dsn)
	if err != nil {
		t.Fatalf("failed to open mock db: %v", err)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})
	gormDB, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{
		DisableAutomaticPing: true,
	})
	if err != nil {
		t.Fatalf("failed to open gorm db: %v", err)
	}
	return gormDB
}

func TestNewHandler_HealthEndpoint_Healthy(t *testing.T) {
	cfg := config.DefaultConfig()
	db := newMockGormDB(t, true)
	h := New(db, cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", got)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"status":"ok"}` {
		t.Errorf("expected body %q, got %q", `{"status":"ok"}`, body)
	}
}

func TestNewHandler_HealthEndpoint_UnhealthyDB(t *testing.T) {
	cfg := config.DefaultConfig()
	db := newMockGormDB(t, false)
	h := New(db, cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", got)
	}
	wantBody := `{"code":"DATABASE_UNAVAILABLE","message":"database unavailable"}`
	if body := strings.TrimSpace(rec.Body.String()); body != wantBody {
		t.Errorf("expected body %q, got %q", wantBody, body)
	}
}

func TestNewHandler_HealthEndpoint_NilDB(t *testing.T) {
	cfg := config.DefaultConfig()
	h := New(nil, cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", got)
	}
	wantBody := `{"code":"DATABASE_UNAVAILABLE","message":"database unavailable"}`
	if body := strings.TrimSpace(rec.Body.String()); body != wantBody {
		t.Errorf("expected body %q, got %q", wantBody, body)
	}
}

func TestNewHandler_HealthEndpoint_MethodNotAllowed(t *testing.T) {
	cfg := config.DefaultConfig()
	db := newMockGormDB(t, true)
	h := New(db, cfg, nil)

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", got)
	}
	wantBody := `{"code":"METHOD_NOT_ALLOWED","message":"method not allowed"}`
	if body := strings.TrimSpace(rec.Body.String()); body != wantBody {
		t.Errorf("expected body %q, got %q", wantBody, body)
	}
}

func TestNewHandler_NotFound(t *testing.T) {
	cfg := config.DefaultConfig()
	h := New(nil, cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/non-existent-endpoint", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", got)
	}
	wantBody := `{"code":"NOT_FOUND","message":"not found"}`
	if body := strings.TrimSpace(rec.Body.String()); body != wantBody {
		t.Errorf("expected body %q, got %q", wantBody, body)
	}
}

func TestStandaloneHandlers(t *testing.T) {
	t.Run("NotFoundHandler", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
		NotFoundHandler().ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected status %d, got %d", http.StatusNotFound, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", got)
		}
		wantBody := `{"code":"NOT_FOUND","message":"not found"}`
		if body := strings.TrimSpace(rec.Body.String()); body != wantBody {
			t.Errorf("expected body %q, got %q", wantBody, body)
		}
	})

	t.Run("MethodNotAllowedHandler", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		MethodNotAllowedHandler().ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", got)
		}
		wantBody := `{"code":"METHOD_NOT_ALLOWED","message":"method not allowed"}`
		if body := strings.TrimSpace(rec.Body.String()); body != wantBody {
			t.Errorf("expected body %q, got %q", wantBody, body)
		}
	})
}

func TestNewHandler_WrapsCORSMiddleware(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AllowedOrigins = []string{"https://dashboard.example.com"}
	db := newMockGormDB(t, true)

	h := New(db, cfg, nil)

	// Test GET with Origin
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://dashboard.example.com")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q; want https://dashboard.example.com", got)
	}

	// Test OPTIONS preflight short-circuit
	optReq := httptest.NewRequest(http.MethodOptions, "/health", nil)
	optReq.Header.Set("Origin", "https://dashboard.example.com")
	optReq.Header.Set("Access-Control-Request-Method", "GET")
	optRec := httptest.NewRecorder()

	h.ServeHTTP(optRec, optReq)

	if optRec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, optRec.Code)
	}
	if got := optRec.Header().Get("Access-Control-Max-Age"); got != "86400" {
		t.Fatalf("Access-Control-Max-Age = %q; want 86400", got)
	}
}

func TestResponseInterceptor_HonorsFirstWriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	ri := &responseInterceptor{ResponseWriter: rec}

	ri.WriteHeader(http.StatusNotFound)
	ri.WriteHeader(http.StatusInternalServerError)

	if ri.statusCode != http.StatusNotFound {
		t.Errorf("expected statusCode %d, got %d", http.StatusNotFound, ri.statusCode)
	}
}

func TestResponseInterceptor_JSONContentTypeWithParameters(t *testing.T) {
	rec := httptest.NewRecorder()
	ri := &responseInterceptor{ResponseWriter: rec}

	ri.Header().Set("Content-Type", "application/json; charset=utf-8")
	ri.WriteHeader(http.StatusNotFound)
	customBody := `{"custom":"not found"}`
	n, err := ri.Write([]byte(customBody))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(customBody) {
		t.Fatalf("Write wrote %d bytes, want %d", n, len(customBody))
	}

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected recorder status %d, got %d", http.StatusNotFound, rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != customBody {
		t.Errorf("expected body %q, got %q", customBody, rec.Body.String())
	}
}

func TestNewHandler_HealthEndpoint_CanceledContext(t *testing.T) {
	cfg := config.DefaultConfig()
	db := newMockGormDB(t, true)
	h := New(db, cfg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := httptest.NewRequest(http.MethodGet, "/health", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d on canceled context, got %d", http.StatusServiceUnavailable, rec.Code)
	}
}
