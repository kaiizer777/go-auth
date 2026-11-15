package session

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/config"
	apperrors "github.com/kaiizer777/go-auth/errors"
)

func TestSetSessionCookie_Flags(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SessionCookieName = "sid"
	cfg.SessionCookieSecure = true
	cfg.SessionCookieSameSite = http.SameSiteLaxMode
	cfg.SessionCookiePath = "/"
	cfg.SessionCookieDomain = "example.com"

	rec := httptest.NewRecorder()
	rawID := "0123456789abcdef0123456789abcdef"

	SetSessionCookie(rec, rawID, &cfg)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "sid" {
		t.Fatalf("expected cookie name 'sid', got %q", cookie.Name)
	}
	if cookie.Value != rawID {
		t.Fatalf("expected cookie value %q, got %q", rawID, cookie.Value)
	}
	if !cookie.HttpOnly {
		t.Fatal("expected HttpOnly to be true")
	}
	if !cookie.Secure {
		t.Fatal("expected Secure to be true")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite Lax, got %v", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Fatalf("expected Path '/', got %q", cookie.Path)
	}
	if cookie.Domain != "example.com" {
		t.Fatalf("expected Domain 'example.com', got %q", cookie.Domain)
	}
}

func TestSetSessionCookie_MaxAge(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SessionAbsoluteMaxAge = 12 * time.Hour

	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "token", &cfg)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	expectedMaxAge := int((12 * time.Hour) / time.Second)
	if cookies[0].MaxAge != expectedMaxAge {
		t.Fatalf("expected MaxAge %d, got %d", expectedMaxAge, cookies[0].MaxAge)
	}
}

func TestClearSessionCookie_MaxAge(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SessionCookieName = "sid"

	rec := httptest.NewRecorder()
	ClearSessionCookie(rec, &cfg)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "sid" {
		t.Fatalf("expected cookie name 'sid', got %q", cookie.Name)
	}
	if cookie.Value != "" {
		t.Fatalf("expected empty cookie value, got %q", cookie.Value)
	}
	if cookie.MaxAge != -1 {
		t.Fatalf("expected MaxAge -1, got %d", cookie.MaxAge)
	}
	if !cookie.HttpOnly {
		t.Fatal("expected HttpOnly to be preserved as true")
	}
}

func TestReadSessionCookie_Present(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SessionCookieName = "sid"

	rawID := "0123456789abcdef0123456789abcdef"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "sid",
		Value: rawID,
	})

	extracted, err := ReadSessionCookie(req, &cfg)
	if err != nil {
		t.Fatalf("ReadSessionCookie failed: %v", err)
	}
	if extracted != rawID {
		t.Fatalf("expected %q, got %q", rawID, extracted)
	}
}

func TestReadSessionCookie_Absent(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SessionCookieName = "sid"

	t.Run("cookie missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		val, err := ReadSessionCookie(req, &cfg)
		if val != "" {
			t.Fatalf("expected empty value, got %q", val)
		}
		if !errors.Is(err, http.ErrNoCookie) {
			t.Fatalf("expected http.ErrNoCookie, got %v", err)
		}
		if !errors.Is(err, apperrors.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("cookie empty value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "sid",
			Value: "",
		})
		val, err := ReadSessionCookie(req, &cfg)
		if val != "" {
			t.Fatalf("expected empty value, got %q", val)
		}
		if !errors.Is(err, http.ErrNoCookie) {
			t.Fatalf("expected http.ErrNoCookie, got %v", err)
		}
		if !errors.Is(err, apperrors.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound, got %v", err)
		}
	})
}
