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

func TestResponseInterceptor_BufferingAndDoubleWrite(t *testing.T) {
	t.Run("non-JSON 404 body is buffered and suppresses raw output", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ri := &responseInterceptor{ResponseWriter: rec}

		ri.Header().Set("Content-Type", "text/plain; charset=utf-8")
		ri.WriteHeader(http.StatusNotFound)

		n1, err1 := ri.Write([]byte("404 page not found\n"))
		n2, err2 := ri.Write([]byte("second line"))

		if err1 != nil || err2 != nil {
			t.Fatalf("expected nil write errors, got err1=%v, err2=%v", err1, err2)
		}
		if n1 != 19 || n2 != 11 {
			t.Errorf("unexpected byte counts written: n1=%d, n2=%d", n1, n2)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("expected recorder body to be empty (buffered), got %q", rec.Body.String())
		}
		if ri.body.String() != "404 page not found\nsecond line" {
			t.Errorf("expected buffered body %q, got %q", "404 page not found\nsecond line", ri.body.String())
		}
	})

	t.Run("non-JSON 405 body is buffered", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ri := &responseInterceptor{ResponseWriter: rec}

		ri.WriteHeader(http.StatusMethodNotAllowed)
		_, err := ri.Write([]byte("Method Not Allowed\n"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		if rec.Body.Len() != 0 {
			t.Errorf("expected recorder body to be empty, got %q", rec.Body.String())
		}
		if ri.body.String() != "Method Not Allowed\n" {
			t.Errorf("expected buffered body %q, got %q", "Method Not Allowed\n", ri.body.String())
		}
	})

	t.Run("write without writeHeader defaults to 200 OK", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ri := &responseInterceptor{ResponseWriter: rec}

		_, err := ri.Write([]byte("implicit ok"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		if ri.statusCode != http.StatusOK {
			t.Errorf("expected statusCode 200, got %d", ri.statusCode)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected recorder code 200, got %d", rec.Code)
		}
		if rec.Body.String() != "implicit ok" {
			t.Errorf("expected body 'implicit ok', got %q", rec.Body.String())
		}
	})

	t.Run("multiple writes with 200 OK succeed sequentially", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ri := &responseInterceptor{ResponseWriter: rec}

		ri.WriteHeader(http.StatusOK)
		ri.WriteHeader(http.StatusBadRequest) // Ignored: first WriteHeader wins

		_, _ = ri.Write([]byte("first "))
		_, _ = ri.Write([]byte("second"))

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if rec.Body.String() != "first second" {
			t.Errorf("expected body 'first second', got %q", rec.Body.String())
		}
	})

	t.Run("malformed json content-type fallback", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ri := &responseInterceptor{ResponseWriter: rec}

		ri.Header().Set("Content-Type", "application/json; invalid;; syntax")
		ri.WriteHeader(http.StatusNotFound)
		customJSON := `{"error":"custom"}`
		_, err := ri.Write([]byte(customJSON))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", rec.Code)
		}
		if rec.Body.String() != customJSON {
			t.Errorf("expected body %q, got %q", customJSON, rec.Body.String())
		}
	})

	t.Run("plus json media-type suffix pass-through", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ri := &responseInterceptor{ResponseWriter: rec}

		ri.Header().Set("Content-Type", "application/problem+json")
		ri.WriteHeader(http.StatusNotFound)
		problemJSON := `{"type":"about:blank","title":"Not Found"}`
		_, err := ri.Write([]byte(problemJSON))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", rec.Code)
		}
		if rec.Body.String() != problemJSON {
			t.Errorf("expected body %q, got %q", problemJSON, rec.Body.String())
		}
	})
}

func TestNewHandler_NilAuthService_RoutesIsolated(t *testing.T) {
	cfg := config.DefaultConfig()
	db := newMockGormDB(t, true)
	h := New(db, cfg, nil) // authSvc is nil

	// Verify health route works
	healthReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthRec := httptest.NewRecorder()
	h.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("expected /health to return 200, got %d", healthRec.Code)
	}

	authRoutes := []string{
		"/auth/signup",
		"/auth/login",
		"/auth/logout",
		"/auth/verify",
		"/auth/password/reset-request",
		"/auth/password/reset",
		"/api/auth/signup",
		"/api/auth/login",
		"/api/auth/logout",
		"/api/auth/verify-email",
		"/api/auth/request-password-reset",
		"/api/auth/reset-password",
	}

	for _, route := range authRoutes {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("expected route %s to return 404 when authSvc is nil, got %d", route, rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("expected Content-Type application/json, got %q", got)
			}
			wantBody := `{"code":"NOT_FOUND","message":"not found"}`
			if body := strings.TrimSpace(rec.Body.String()); body != wantBody {
				t.Errorf("expected body %q, got %q", wantBody, body)
			}
		})
	}
}
