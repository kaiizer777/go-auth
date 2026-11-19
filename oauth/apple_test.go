package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

func appleTestConfig() config.ProviderConfig {
	return config.ProviderConfig{
		ClientID:     "com.example.app",
		ClientSecret: "static-secret",
		RedirectURL:  "https://app.example.com/auth/apple/callback",
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func rsaJWK(pub *rsa.PublicKey, kid string) map[string]any {
	eBytes := new(big.Int).SetInt64(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func mintAppleIDToken(t *testing.T, Key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	hs := base64.RawURLEncoding.EncodeToString(header)
	ps := base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(hs + "." + ps))
	sig, err := rsa.SignPKCS1v15(rand.Reader, Key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return hs + "." + ps + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func appleFixtureClaims(email any) map[string]any {
	return map[string]any{
		"iss":            "https://appleid.apple.com",
		"aud":            "com.example.app",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"sub":            "apple-sub-123",
		"email":          "user@privaterelay.appleid.com",
		"email_verified": email,
	}
}

// capturedValue is a mutex-guarded string written by handler goroutines and
// read by the test goroutine; the mutex is the happens-before edge.
type capturedValue struct {
	mu sync.Mutex
	v  string
}

func (c *capturedValue) set(s string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.v = s
	c.mu.Unlock()
}

func (c *capturedValue) get() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.v
}

// appleMockStack serves a token endpoint returning idToken and a JWKS endpoint for Key.
func appleMockStack(t *testing.T, Key *rsa.PrivateKey, kid, idToken string, captureSecret *capturedValue) (*httptest.Server, *httptest.Server) {
	t.Helper()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		captureSecret.set(r.PostForm.Get("client_secret"))
		for _, k := range []string{"client_id", "code", "grant_type", "redirect_uri", "code_verifier"} {
			if r.PostForm.Get(k) == "" {
				http.Error(w, "missing "+k, http.StatusBadRequest)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "apple-at", "token_type": "Bearer",
			"expires_in": 3600, "id_token": idToken,
		})
	}))
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(&Key.PublicKey, kid)}})
	}))
	t.Cleanup(tokenSrv.Close)
	t.Cleanup(jwksSrv.Close)
	return tokenSrv, jwksSrv
}

func TestAppleAuthURL(t *testing.T) {
	t.Parallel()
	p := NewAppleProvider(appleTestConfig())
	u, err := url.Parse(p.AuthURL("state123", "challenge123"))
	if err != nil {
		t.Fatalf("parse AuthURL: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != "https://appleid.apple.com/auth/authorize" {
		t.Errorf("host/path = %s; want apple authorize endpoint", u.Scheme+"://"+u.Host+u.Path)
	}
	q := u.Query()
	want := map[string]string{
		"response_type":         "code",
		"response_mode":         "form_post",
		"client_id":             "com.example.app",
		"redirect_uri":          "https://app.example.com/auth/apple/callback",
		"scope":                 "name email",
		"state":                 "state123",
		"code_challenge":        "challenge123",
		"code_challenge_method": "S256",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("param %q = %q; want %q", k, q.Get(k), v)
		}
	}
}

func TestAppleValidIDToken(t *testing.T) {
	t.Parallel()
	Key := mustRSAKey(t)
	idToken := mintAppleIDToken(t, Key, "kid-1", appleFixtureClaims(true))
	tokenSrv, jwksSrv := appleMockStack(t, Key, "kid-1", idToken, nil)
	defer tokenSrv.Close()
	defer jwksSrv.Close()

	p := NewAppleProvider(appleTestConfig())
	p.tokenURL = tokenSrv.URL
	p.jwksURL = jwksSrv.URL

	tok, err := p.ExchangeCode(context.Background(), "code123", "verifier123")
	if err != nil {
		t.Fatalf("ExchangeCode = %v", err)
	}
	if tok.IDToken == "" || tok.AccessToken != "apple-at" {
		t.Errorf("tokens = %+v", tok)
	}
	info, err := p.FetchUserInfo(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUserInfo = %v", err)
	}
	if info.ProviderID != "apple" || info.ProviderUserID != "apple-sub-123" ||
		info.Email != "user@privaterelay.appleid.com" || !info.EmailVerified {
		t.Errorf("userinfo = %+v", info)
	}
}

func TestAppleEmailVerifiedForms(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		flag any
		want bool
	}{
		{"bool true", true, true},
		{"string true", "true", true},
		{"bool false", false, false},
		{"string false", "false", false},
		{"missing", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			Key := mustRSAKey(t)
			claims := appleFixtureClaims(true)
			if tc.flag == nil {
				delete(claims, "email_verified")
			} else {
				claims["email_verified"] = tc.flag
			}
			idToken := mintAppleIDToken(t, Key, "kid-1", claims)
			_, jwksSrv := appleMockStack(t, Key, "kid-1", idToken, nil)
			defer jwksSrv.Close()
			p := NewAppleProvider(appleTestConfig())
			p.jwksURL = jwksSrv.URL
			info, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: idToken})
			if err != nil {
				t.Fatalf("FetchUserInfo = %v", err)
			}
			if info.EmailVerified != tc.want {
				t.Errorf("EmailVerified = %v; want %v", info.EmailVerified, tc.want)
			}
		})
	}
}

func TestAppleUnverifiedSurfacesFalse(t *testing.T) {
	t.Parallel()
	Key := mustRSAKey(t)
	idToken := mintAppleIDToken(t, Key, "kid-1", appleFixtureClaims(false))
	_, jwksSrv := appleMockStack(t, Key, "kid-1", idToken, nil)
	defer jwksSrv.Close()
	p := NewAppleProvider(appleTestConfig())
	p.jwksURL = jwksSrv.URL
	info, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: idToken})
	if err != nil {
		t.Fatalf("FetchUserInfo = %v", err)
	}
	if info.EmailVerified {
		t.Errorf("EmailVerified = true; want false so Part 3 rejects with OAUTH_EMAIL_UNVERIFIED")
	}
}

func TestAppleIDTokenRejections(t *testing.T) {
	t.Parallel()
	Key := mustRSAKey(t)
	other := mustRSAKey(t)
	mk := func(claims map[string]any) string { return mintAppleIDToken(t, Key, "kid-1", claims) }
	tamper := func(tok string) string {
		t.Helper()
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			t.Fatalf("id token segments = %d; want 3", len(parts))
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || len(sig) == 0 {
			t.Fatalf("decode signature: %v", err)
		}
		orig := append([]byte(nil), sig...)
		sig[0] ^= 0xFF // flip a decoded byte; last-char edits only touch ignored padding bits
		out := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
		if rt, err := base64.RawURLEncoding.DecodeString(strings.Split(out, ".")[2]); err != nil || string(rt) == string(orig) {
			t.Fatalf("tamper left signature bytes unchanged")
		}
		return out
	}

	t.Run("tampered signature rejected", func(t *testing.T) {
		t.Parallel()
		_, jwksSrv := appleMockStack(t, Key, "kid-1", "", nil)
		defer jwksSrv.Close()
		p := NewAppleProvider(appleTestConfig())
		p.jwksURL = jwksSrv.URL
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: tamper(mk(appleFixtureClaims(true)))})
		requireProviderError(t, err)
	})

	t.Run("wrong signer rejected", func(t *testing.T) {
		t.Parallel()
		bad := mintAppleIDToken(t, other, "kid-1", appleFixtureClaims(true))
		_, jwksSrv := appleMockStack(t, Key, "kid-1", "", nil)
		defer jwksSrv.Close()
		p := NewAppleProvider(appleTestConfig())
		p.jwksURL = jwksSrv.URL
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: bad})
		requireProviderError(t, err)
	})

	t.Run("expired token rejected", func(t *testing.T) {
		t.Parallel()
		claims := appleFixtureClaims(true)
		claims["exp"] = time.Now().Add(-time.Hour).Unix()
		_, jwksSrv := appleMockStack(t, Key, "kid-1", "", nil)
		defer jwksSrv.Close()
		p := NewAppleProvider(appleTestConfig())
		p.jwksURL = jwksSrv.URL
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: mk(claims)})
		requireProviderError(t, err)
	})

	t.Run("wrong audience rejected", func(t *testing.T) {
		t.Parallel()
		claims := appleFixtureClaims(true)
		claims["aud"] = "com.evil.app"
		_, jwksSrv := appleMockStack(t, Key, "kid-1", "", nil)
		defer jwksSrv.Close()
		p := NewAppleProvider(appleTestConfig())
		p.jwksURL = jwksSrv.URL
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: mk(claims)})
		requireProviderError(t, err)
	})

	t.Run("wrong issuer rejected", func(t *testing.T) {
		t.Parallel()
		claims := appleFixtureClaims(true)
		claims["iss"] = "https://evil.example.com"
		_, jwksSrv := appleMockStack(t, Key, "kid-1", "", nil)
		defer jwksSrv.Close()
		p := NewAppleProvider(appleTestConfig())
		p.jwksURL = jwksSrv.URL
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: mk(claims)})
		requireProviderError(t, err)
	})

	t.Run("empty sub rejected", func(t *testing.T) {
		t.Parallel()
		claims := appleFixtureClaims(true)
		claims["sub"] = ""
		_, jwksSrv := appleMockStack(t, Key, "kid-1", "", nil)
		defer jwksSrv.Close()
		p := NewAppleProvider(appleTestConfig())
		p.jwksURL = jwksSrv.URL
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: mk(claims)})
		requireProviderError(t, err)
	})

	t.Run("alg none rejected", func(t *testing.T) {
		t.Parallel()
		_, jwksSrv := appleMockStack(t, Key, "kid-1", "", nil)
		defer jwksSrv.Close()
		p := NewAppleProvider(appleTestConfig())
		p.jwksURL = jwksSrv.URL
		parts := strings.Split(mk(appleFixtureClaims(true)), ".")
		header, err := json.Marshal(map[string]any{"alg": "none", "kid": "kid-1", "typ": "JWT"})
		if err != nil {
			t.Fatalf("marshal header: %v", err)
		}
		unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + parts[1] + "."
		_, err = p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: unsigned})
		requireProviderError(t, err)
	})

	t.Run("empty kid rejected", func(t *testing.T) {
		t.Parallel()
		_, jwksSrv := appleMockStack(t, Key, "kid-1", "", nil)
		defer jwksSrv.Close()
		p := NewAppleProvider(appleTestConfig())
		p.jwksURL = jwksSrv.URL
		noKid := mintAppleIDToken(t, Key, "", appleFixtureClaims(true))
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: noKid})
		requireProviderError(t, err)
	})

	t.Run("empty id token rejected", func(t *testing.T) {
		t.Parallel()
		p := NewAppleProvider(appleTestConfig())
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{AccessToken: "at"})
		requireProviderError(t, err)
	})
}

func TestAppleUnknownKidRefresh(t *testing.T) {
	t.Parallel()
	oldKey := mustRSAKey(t)
	newKey := mustRSAKey(t)
	staleToken := mintAppleIDToken(t, oldKey, "kid-1", appleFixtureClaims(true))
	rotatedToken := mintAppleIDToken(t, newKey, "kid-2", appleFixtureClaims(true))
	tokenSrv, _ := appleMockStack(t, newKey, "kid-2", rotatedToken, nil)
	defer tokenSrv.Close()

	// JWKS serves kid-1 until the test flips rotated, then kid-2.
	var mu sync.Mutex
	var fetches int
	rotated := false
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetches++
		kid, key := "kid-1", oldKey
		if rotated {
			kid, key = "kid-2", newKey
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(&key.PublicKey, kid)}})
	}))
	defer jwksSrv.Close()

	p := NewAppleProvider(appleTestConfig())
	p.tokenURL = tokenSrv.URL
	p.jwksURL = jwksSrv.URL

	// Prime the cache through the real path: kid-1 validates with one fetch.
	if _, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: staleToken}); err != nil {
		t.Fatalf("prime kid-1 FetchUserInfo = %v", err)
	}
	// Rotate upstream pre-TTL-expiry; the cached set is now stale.
	mu.Lock()
	rotated = true
	mu.Unlock()

	tok, err := p.ExchangeCode(context.Background(), "code123", "verifier123")
	if err != nil {
		t.Fatalf("ExchangeCode = %v", err)
	}
	info, err := p.FetchUserInfo(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUserInfo after rotation = %v", err)
	}
	if info.ProviderUserID != "apple-sub-123" {
		t.Errorf("userinfo = %+v; want apple-sub-123", info)
	}
	mu.Lock()
	defer mu.Unlock()
	if fetches != 2 {
		t.Errorf("JWKS fetches = %d; want 2 (prime + refresh-on-miss)", fetches)
	}
}

func TestAppleES256ClientSecret(t *testing.T) {
	t.Parallel()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	Key := mustRSAKey(t)
	idToken := mintAppleIDToken(t, Key, "kid-1", appleFixtureClaims(true))
	captured := &capturedValue{}
	tokenSrv, jwksSrv := appleMockStack(t, Key, "kid-1", idToken, captured)
	defer tokenSrv.Close()
	defer jwksSrv.Close()

	cfg := config.ProviderConfig{
		ClientID: "com.example.app", RedirectURL: "https://app.example.com/auth/apple/callback",
		TeamID: "TEAM123456", KeyID: "KEY1234567", PrivateKey: pemKey,
	}
	p := NewAppleProvider(cfg)
	p.tokenURL = tokenSrv.URL
	p.jwksURL = jwksSrv.URL

	if _, err := p.ExchangeCode(context.Background(), "code123", "verifier123"); err != nil {
		t.Fatalf("ExchangeCode = %v", err)
	}
	parts := strings.Split(captured.get(), ".")
	if len(parts) != 3 {
		t.Fatalf("client_secret segments = %d; want 3", len(parts))
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(raw, &header) != nil {
		t.Fatalf("decode client_secret header: %v", err)
	}
	if header.Alg != "ES256" || header.Kid != "KEY1234567" {
		t.Errorf("header = %+v; want alg ES256 kid KEY1234567", header)
	}
	// Verify the ES256 signature over the header.payload input.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("decode client_secret signature: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&ecKey.PublicKey, digest[:], r, s) {
		t.Errorf("client_secret ES256 signature does not verify")
	}
	var claims map[string]any
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		t.Fatalf("decode client_secret claims: %v", err)
	}
	if claims["iss"] != "TEAM123456" || claims["sub"] != "com.example.app" ||
		claims["aud"] != "https://appleid.apple.com" {
		t.Errorf("claims = %v", claims)
	}
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	if int64(exp)-int64(iat) != 300 {
		t.Errorf("exp-iat = %v; want 300s", int64(exp)-int64(iat))
	}
}

func TestAppleTokenErrors(t *testing.T) {
	t.Parallel()

	t.Run("token 4xx maps to provider error", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		}))
		defer srv.Close()
		p := NewAppleProvider(appleTestConfig())
		p.tokenURL = srv.URL
		_, err := p.ExchangeCode(context.Background(), "bad", "v")
		requireProviderError(t, err)
	})

	t.Run("token invalid JSON maps to provider error", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{oops`))
		}))
		defer srv.Close()
		p := NewAppleProvider(appleTestConfig())
		p.tokenURL = srv.URL
		_, err := p.ExchangeCode(context.Background(), "code", "v")
		requireProviderError(t, err)
	})

	t.Run("bad private key maps to provider error", func(t *testing.T) {
		t.Parallel()
		cfg := appleTestConfig()
		cfg.ClientSecret = ""
		cfg.TeamID, cfg.KeyID, cfg.PrivateKey = "T", "K", "not-a-pem-key"
		p := NewAppleProvider(cfg)
		_, err := p.ExchangeCode(context.Background(), "code", "v")
		requireProviderError(t, err)
	})
}

func TestAppleClientSecretRejectsNonP256(t *testing.T) {
	t.Parallel()
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	_, err = appleClientSecretJWT("TEAM123456", "KEY1234567", "com.example.app", pemKey, time.Now())
	if err == nil {
		t.Fatal("P-384 key accepted for ES256; want configuration error")
	}
	var appErr *errors.Error
	if !errors.As(err, &appErr) {
		t.Fatalf("error type = %T; want *errors.Error", err)
	}
	if appErr.Code() != errors.CodeInvalidConfig {
		t.Fatalf("code = %q; want %q", appErr.Code(), errors.CodeInvalidConfig)
	}
	if appErr.HTTPStatus() != http.StatusInternalServerError {
		t.Fatalf("status = %d; want 500", appErr.HTTPStatus())
	}
}

func TestAppleConcurrentJWKSRefreshCoalesced(t *testing.T) {
	t.Parallel()
	key := mustRSAKey(t)
	idToken := mintAppleIDToken(t, key, "kid-1", appleFixtureClaims(true))
	var hits atomic.Int64
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(&key.PublicKey, "kid-1")}})
	}))
	defer jwksSrv.Close()

	p := NewAppleProvider(appleTestConfig())
	p.jwksURL = jwksSrv.URL

	const workers = 16
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: idToken})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d FetchUserInfo = %v", i, err)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("JWKS fetches = %d; want 1 (shared in-flight refresh)", n)
	}
}

func TestAppleStaleJWKSRefreshSuperseded(t *testing.T) {
	t.Parallel()
	keyA := mustRSAKey(t)
	keyB := mustRSAKey(t)

	var mu sync.Mutex
	reqs := 0
	started := make(chan struct{})
	release := make(chan struct{})
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs++
		n := reqs
		mu.Unlock()
		if n == 2 {
			close(started)
			<-release
		}
		kid, key := "kid-A", keyA
		if n >= 3 {
			kid, key = "kid-B", keyB
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(&key.PublicKey, kid)}})
	}))
	defer jwksSrv.Close()

	p := NewAppleProvider(appleTestConfig())
	p.jwksURL = jwksSrv.URL

	tokenA := mintAppleIDToken(t, keyA, "kid-A", appleFixtureClaims(true))
	if _, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: tokenA}); err != nil {
		t.Fatalf("prime kid-A FetchUserInfo = %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- p.refreshJWKS(context.Background()) }()
	<-started // slow refresh holds the stale fetch open
	newerErr := p.refreshJWKS(context.Background())
	close(release)
	staleErr := <-done
	if newerErr != nil {
		t.Fatalf("newer refresh = %v", newerErr)
	}
	if staleErr != nil {
		t.Fatalf("stale refresh = %v", staleErr)
	}

	// Cache must hold the newer set without another upstream fetch.
	if _, err := p.jwksKey(context.Background(), "kid-B"); err != nil {
		t.Fatalf("jwksKey(kid-B) = %v; want newer published set", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if reqs != 3 {
		t.Errorf("JWKS fetches = %d; want 3 (prime + stale + newer, no re-fetch)", reqs)
	}
}

func TestAppleJoinedCallerMissRefreshes(t *testing.T) {
	t.Parallel()
	oldKey := mustRSAKey(t)
	newKey := mustRSAKey(t)
	var mu sync.Mutex
	fetches := 0
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetches++
		n := fetches
		mu.Unlock()
		kid, key := "kid-1", oldKey
		if n >= 2 {
			kid, key = "kid-2", newKey
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(&key.PublicKey, kid)}})
	}))
	defer jwksSrv.Close()

	p := NewAppleProvider(appleTestConfig())
	p.jwksURL = jwksSrv.URL

	// Empty cache: the first flight serves the pre-rotation set, so the
	// caller's kid still misses and one bounded re-refresh must recover it.
	rotatedToken := mintAppleIDToken(t, newKey, "kid-2", appleFixtureClaims(true))
	info, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: rotatedToken})
	if err != nil {
		t.Fatalf("FetchUserInfo after rotation = %v", err)
	}
	if info.ProviderUserID != "apple-sub-123" {
		t.Errorf("userinfo = %+v; want apple-sub-123", info)
	}
	mu.Lock()
	defer mu.Unlock()
	if fetches != 2 {
		t.Errorf("JWKS fetches = %d; want 2 (shared flight + one bounded re-refresh)", fetches)
	}
}

func TestAppleOwnerCancelKeepsSharedFetch(t *testing.T) {
	t.Parallel()
	key := mustRSAKey(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var fetches atomic.Int64
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		once.Do(func() { close(entered) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(&key.PublicKey, "kid-1")}})
	}))
	defer jwksSrv.Close()

	p := NewAppleProvider(appleTestConfig())
	p.jwksURL = jwksSrv.URL

	ownerCtx, cancelOwner := context.WithCancel(context.Background())
	defer cancelOwner()
	ownerDone := make(chan error, 1)
	go func() {
		_, err := p.jwksKey(ownerCtx, "kid-1")
		ownerDone <- err
	}()
	<-entered // owner's upstream fetch is in flight

	joining := make(chan struct{})
	joinerDone := make(chan error, 1)
	go func() {
		close(joining)
		_, err := p.jwksKey(context.Background(), "kid-1")
		joinerDone <- err
	}()
	<-joining
	time.Sleep(200 * time.Millisecond) // let the joiner attach to the shared flight
	cancelOwner()                      // must not abort the shared fetch
	close(release)

	if err := <-joinerDone; err != nil {
		t.Fatalf("joiner jwksKey = %v; want success after owner cancel", err)
	}
	if err := <-ownerDone; err != nil {
		t.Fatalf("owner jwksKey = %v; want success", err)
	}
	if n := fetches.Load(); n != 1 {
		t.Errorf("JWKS fetches = %d; want 1 (shared flight, no re-fetch)", n)
	}
}

func TestAppleEmptyJWKSNotCached(t *testing.T) {
	t.Parallel()
	Key := mustRSAKey(t)
	var mu sync.Mutex
	publishEmpty := true
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		servingEmpty := publishEmpty
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if servingEmpty {
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(&Key.PublicKey, "kid-1")}})
	}))
	defer jwksSrv.Close()

	p := NewAppleProvider(appleTestConfig())
	p.jwksURL = jwksSrv.URL
	idToken := mintAppleIDToken(t, Key, "kid-1", appleFixtureClaims(true))

	if _, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: idToken}); err == nil {
		t.Fatal("empty JWKS accepted; want provider error")
	} else {
		requireProviderError(t, err)
	}

	p.mu.RLock()
	gen, cached, expires := p.jwksGen, len(p.jwks), p.jwksExpires
	p.mu.RUnlock()
	if gen != 0 || cached != 0 || !expires.IsZero() {
		t.Fatalf("cache touched by empty document: gen=%d keys=%d expires=%v", gen, cached, expires)
	}

	mu.Lock()
	publishEmpty = false
	mu.Unlock()
	info, err := p.FetchUserInfo(context.Background(), &TokenResponse{IDToken: idToken})
	if err != nil {
		t.Fatalf("FetchUserInfo after valid JWKS = %v; want success without TTL wait", err)
	}
	if info.ProviderUserID != "apple-sub-123" {
		t.Fatalf("userinfo = %+v; want apple-sub-123", info)
	}
}
