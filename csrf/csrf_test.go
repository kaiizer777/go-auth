package csrf

import (
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/kaiizer777/go-auth/config"
)

func testConfig() *config.Config {
	cfg := config.DefaultConfig()
	return &cfg
}

func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestCSRF_SafeMethod_NoCookieSet(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	res := rec.Result()
	cookies := res.Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == cfg.CSRFCookieName {
			csrfCookie = c
			break
		}
	}

	if csrfCookie == nil {
		t.Fatalf("expected CSRF cookie %q to be set", cfg.CSRFCookieName)
	}

	if len(csrfCookie.Value) != 64 {
		t.Errorf("expected 64 hex chars token, got len=%d: %s", len(csrfCookie.Value), csrfCookie.Value)
	}
	if _, err := hex.DecodeString(csrfCookie.Value); err != nil {
		t.Errorf("expected valid hex string, got err: %v", err)
	}
}

func TestCSRF_SafeMethod_ExistingCookie(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	existingToken := "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.CSRFCookieName,
		Value: existingToken,
	})
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.CSRFCookieName {
			t.Errorf("expected existing CSRF cookie to not be rewritten, but got set-cookie: %v", c)
		}
	}
}

func TestCSRF_StateChanging_ValidToken(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	token := "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	req := httptest.NewRequest(http.MethodPost, "/resource", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.CSRFCookieName,
		Value: token,
	})
	req.Header.Set(cfg.CSRFHeaderName, token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestCSRF_StateChanging_MissingCookie(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	token := "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	req := httptest.NewRequest(http.MethodPost, "/resource", nil)
	req.Header.Set(cfg.CSRFHeaderName, token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
}

func TestCSRF_StateChanging_MissingHeader(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	token := "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	req := httptest.NewRequest(http.MethodPost, "/resource", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.CSRFCookieName,
		Value: token,
	})
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
}

func TestCSRF_StateChanging_MismatchedToken(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	cookieToken := "1111111111111111111111111111111111111111111111111111111111111111"
	headerToken := "2222222222222222222222222222222222222222222222222222222222222222"
	req := httptest.NewRequest(http.MethodPost, "/resource", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.CSRFCookieName,
		Value: cookieToken,
	})
	req.Header.Set(cfg.CSRFHeaderName, headerToken)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
}

func TestCSRF_BearerAuth_SkipsCSRF(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	req := httptest.NewRequest(http.MethodPost, "/resource", nil)
	req.Header.Set("Authorization", "Bearer some-bearer-token")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestCSRF_CookieFlags(t *testing.T) {
	cfg := testConfig()
	cfg.SessionCookieSecure = true
	rec := httptest.NewRecorder()

	setCSRFCookie(rec, "dummytoken", cfg)

	res := rec.Result()
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]

	if c.HttpOnly {
		t.Errorf("expected HttpOnly to be false for CSRF cookie, got true")
	}
	if !c.Secure {
		t.Errorf("expected Secure to be true, got false")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSite=Strict (%v), got %v", http.SameSiteStrictMode, c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("expected Path='/', got %q", c.Path)
	}
}

func TestCSRF_TimingAttack(t *testing.T) {
	if !secureCompare("abc", "abc") {
		t.Errorf("expected secureCompare('abc', 'abc') == true")
	}
	if secureCompare("abc", "abd") {
		t.Errorf("expected secureCompare('abc', 'abd') == false")
	}
	if secureCompare("ab", "abc") {
		t.Errorf("expected secureCompare('ab', 'abc') == false")
	}
	if secureCompare("", "a") {
		t.Errorf("expected secureCompare('', 'a') == false")
	}
	if !secureCompare("", "") {
		t.Errorf("expected secureCompare('', '') == true")
	}
}

func TestCSRF_AllStatefulMethods(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	methods := []string{http.MethodPut, http.MethodPatch, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/resource", nil)
			rec := httptest.NewRecorder()

			mw.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("method %s: expected status 403, got %d", method, rec.Code)
			}
		})
	}
}

func TestCSRF_InvalidHexCookie(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	cases := []struct {
		name        string
		cookieVal   string
		headerVal   string
		expectedErr string
	}{
		{
			name:      "short cookie",
			cookieVal: "1",
			headerVal: "1",
		},
		{
			name:      "non-hex 64 chars",
			cookieVal: "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
			headerVal: "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/resource", nil)
			req.AddCookie(&http.Cookie{
				Name:  cfg.CSRFCookieName,
				Value: tc.cookieVal,
			})
			req.Header.Set(cfg.CSRFHeaderName, tc.headerVal)
			rec := httptest.NewRecorder()

			mw.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected status 403, got %d", rec.Code)
			}
		})
	}
}

func TestCSRF_SafeMethod_InvalidCookieRegenerated(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.CSRFCookieName,
		Value: "invalid-cookie-value",
	})
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	cookies := rec.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == cfg.CSRFCookieName {
			csrfCookie = c
			break
		}
	}

	if csrfCookie == nil {
		t.Fatalf("expected invalid cookie to be replaced with new CSRF cookie")
	}
	if len(csrfCookie.Value) != 64 {
		t.Fatalf("expected 64-char hex token, got %d chars", len(csrfCookie.Value))
	}
}

func TestCSRF_EmptyBearerToken_DoesNotBypass(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	cases := []string{
		"Bearer ",
		"Bearer    ",
		"bearer ",
		"Bearer",
	}

	for _, authHeader := range cases {
		t.Run(authHeader, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/resource", nil)
			req.Header.Set("Authorization", authHeader)
			rec := httptest.NewRecorder()

			mw.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected status 403 for header %q, got %d", authHeader, rec.Code)
			}
		})
	}
}

func TestCSRF_NilConfigFallback(t *testing.T) {
	// Middleware with nil cfg
	mw := Middleware(nil)(dummyHandler())
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from nil cfg middleware, got %d", rec.Code)
	}

	// SetCookie with nil cfg
	rec2 := httptest.NewRecorder()
	SetCookie(rec2, "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff", nil)
	if len(rec2.Result().Cookies()) == 0 {
		t.Fatal("expected cookie to be set with nil cfg")
	}

	// IssueCookie with nil cfg
	rec3 := httptest.NewRecorder()
	token, err := IssueCookie(rec3, nil)
	if err != nil || len(token) != 64 {
		t.Fatalf("IssueCookie failed with nil cfg: token=%q err=%v", token, err)
	}
}

func TestCSRF_InvalidHeaderToken(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	validCookieToken := "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"

	invalidHeaders := []struct {
		name        string
		headerToken string
	}{
		{name: "short header token", headerToken: "abcdef"},
		{name: "non-hex chars in 64 char token", headerToken: strings.Repeat("z", 64)},
		{name: "65 char token", headerToken: strings.Repeat("a", 65)},
	}

	for _, tc := range invalidHeaders {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/resource", nil)
			req.AddCookie(&http.Cookie{
				Name:  cfg.CSRFCookieName,
				Value: validCookieToken,
			})
			req.Header.Set(cfg.CSRFHeaderName, tc.headerToken)
			rec := httptest.NewRecorder()

			mw.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected status 403 Forbidden for invalid header token, got %d", rec.Code)
			}
		})
	}
}

func TestCSRF_BearerAuthAmbiguousTransportRejected(t *testing.T) {
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())

	newReq := func(method string) *http.Request {
		req := httptest.NewRequest(method, "/resource", nil)
		req.Header.Set("Authorization", "Bearer [REDACTED]")
		req.Header.Set("X-Auth-Type", "bearer")
		req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: "0123456789abcdef0123456789abcdef"})
		return req
	}

	t.Run("unsafe rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, newReq(http.MethodPost))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 ambiguous transport, got %d", rec.Code)
		}
	})

	t.Run("unsafe without session cookie exempt", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/resource", nil)
		req.Header.Set("Authorization", "Bearer [REDACTED]")
		req.Header.Set("X-Auth-Type", "bearer")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 cookie-free bearer, got %d", rec.Code)
		}
	})

	t.Run("safe with combo skipped", func(t *testing.T) {
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, newReq(http.MethodGet))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 safe method, got %d", rec.Code)
		}
	})
}

func TestCSRF_EntropyFailure(t *testing.T) {
	origRand := randReader
	defer func() { randReader = origRand }()

	randReader = iotest.ErrReader(io.ErrUnexpectedEOF)

	// generateCSRFToken failure via GenerateToken
	_, err := GenerateToken()
	if err == nil {
		t.Fatal("expected error on CSPRNG read failure in GenerateToken, got nil")
	}

	// Middleware safe method failure on token generation
	cfg := testConfig()
	mw := Middleware(cfg)(dummyHandler())
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500 when token generation fails, got %d", rec.Code)
	}
}
