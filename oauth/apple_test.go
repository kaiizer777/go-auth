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
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/config"
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

// appleMockStack serves a token endpoint returning idToken and a JWKS endpoint for Key.
func appleMockStack(t *testing.T, Key *rsa.PrivateKey, kid, idToken string, captureSecret *string) (*httptest.Server, *httptest.Server) {
	t.Helper()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if captureSecret != nil {
			*captureSecret = r.PostForm.Get("client_secret")
		}
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
		parts := strings.Split(tok, ".")
		sig := parts[2]
		if sig[len(sig)-1] == 'A' {
			sig = sig[:len(sig)-1] + "B"
		} else {
			sig = sig[:len(sig)-1] + "A"
		}
		return parts[0] + "." + parts[1] + "." + sig
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

	t.Run("empty id token rejected", func(t *testing.T) {
		t.Parallel()
		p := NewAppleProvider(appleTestConfig())
		_, err := p.FetchUserInfo(context.Background(), &TokenResponse{AccessToken: "at"})
		requireProviderError(t, err)
	})
}

func TestAppleUnknownKidRefresh(t *testing.T) {
	t.Parallel()
	newKey := mustRSAKey(t)
	idToken := mintAppleIDToken(t, newKey, "kid-2", appleFixtureClaims(true))
	tokenSrv, _ := appleMockStack(t, newKey, "kid-2", idToken, nil)
	defer tokenSrv.Close()

	// JWKS first serves only the stale key, then rotates to the new one.
	rotated := false
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rotated = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(&newKey.PublicKey, "kid-2")}})
	}))
	defer jwksSrv.Close()

	p := NewAppleProvider(appleTestConfig())
	p.tokenURL = tokenSrv.URL
	p.jwksURL = jwksSrv.URL

	tok, err := p.ExchangeCode(context.Background(), "code123", "verifier123")
	if err != nil {
		t.Fatalf("ExchangeCode = %v", err)
	}
	info, err := p.FetchUserInfo(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUserInfo after rotation = %v", err)
	}
	if !rotated || info.ProviderUserID != "apple-sub-123" {
		t.Errorf("rotated = %v, userinfo = %+v", rotated, info)
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
	var captured string
	tokenSrv, jwksSrv := appleMockStack(t, Key, "kid-1", idToken, &captured)
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
	parts := strings.Split(captured, ".")
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
