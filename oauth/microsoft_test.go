package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// helper to mint a valid test RSA key and generate RS256 JWTs
func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	nRaw := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
	eBytes := big.NewInt(int64(privKey.E)).Bytes()
	eRaw := base64.RawURLEncoding.EncodeToString(eBytes)
	return privKey, nRaw, eRaw
}

func signRS256JWT(t *testing.T, privKey *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	headerBytes, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"kid": kid,
	})
	if err != nil {
		t.Fatalf("failed to marshal header: %v", err)
	}

	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	hB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	pB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := hB64 + "." + pB64

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("failed to sign jwt: %v", err)
	}

	sB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sB64
}

func TestOIDC_DiscoveryAndJWKS(t *testing.T) {
	privKey, nRaw, eRaw := generateTestRSAKey(t)
	var jwksRequests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			disc := OIDCDiscovery{
				Issuer:                "http://" + r.Host,
				AuthorizationEndpoint: "https://login.example.com/auth",
				TokenEndpoint:         "https://login.example.com/token",
				JWKSURI:               "http://" + r.Host + "/keys",
				UserinfoEndpoint:      "https://login.example.com/userinfo",
			}
			_ = json.NewEncoder(w).Encode(disc)
		case "/keys":
			jwksRequests.Add(1)
			doc := JWKDoc{
				Keys: []JWKKey{
					{
						Kty: "RSA",
						Use: "sig",
						Kid: "key-1",
						Alg: "RS256",
						N:   nRaw,
						E:   eRaw,
					},
				},
			}
			_ = json.NewEncoder(w).Encode(doc)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	client := server.Client()

	t.Run("fetch oidc discovery", func(t *testing.T) {
		disc, err := FetchOIDCDiscovery(ctx, client, server.URL+"/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("unexpected discovery error: %v", err)
		}
		if disc.TokenEndpoint != "https://login.example.com/token" {
			t.Errorf("token endpoint = %q", disc.TokenEndpoint)
		}
		if disc.JWKSURI != server.URL+"/keys" {
			t.Errorf("jwks_uri = %q", disc.JWKSURI)
		}
		if disc.Issuer != server.URL {
			t.Errorf("issuer = %q, want discovery origin %q", disc.Issuer, server.URL)
		}
	})

	t.Run("jwks manager cache and singleflight", func(t *testing.T) {
		mgr := NewJWKSManager(server.URL+"/keys", client, 1*time.Hour)

		key, err := mgr.GetKey(ctx, "key-1")
		if err != nil {
			t.Fatalf("failed to get key: %v", err)
		}
		if key.Key.N.Cmp(privKey.N) != 0 {
			t.Fatalf("modulus mismatch")
		}

		// Second fetch should be cached (jwksRequests == 1)
		_, err = mgr.GetKey(ctx, "key-1")
		if err != nil {
			t.Fatalf("cached fetch failed: %v", err)
		}
		if jwksRequests.Load() != 1 {
			t.Fatalf("expected 1 jwks request, got %d", jwksRequests.Load())
		}
	})

	t.Run("verify valid rs256 jwt", func(t *testing.T) {
		mgr := NewJWKSManager(server.URL+"/keys", client, 1*time.Hour)
		claims := map[string]any{
			"iss":   "https://example.com",
			"sub":   "user-123",
			"aud":   "client-xyz",
			"email": "test@example.com",
		}
		rawJWT := signRS256JWT(t, privKey, "key-1", claims)

		parsed, err := VerifyRS256JWT(ctx, rawJWT, mgr)
		if err != nil {
			t.Fatalf("verification failed: %v", err)
		}
		if parsed["email"] != "test@example.com" {
			t.Errorf("email = %v", parsed["email"])
		}
	})

	t.Run("reject tampered jwt signature", func(t *testing.T) {
		mgr := NewJWKSManager(server.URL+"/keys", client, 1*time.Hour)
		claims := map[string]any{"sub": "user-123"}
		rawJWT := signRS256JWT(t, privKey, "key-1", claims)

		// Tamper with payload
		parts := strings.Split(rawJWT, ".")
		tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker"}`)) + "." + parts[2]

		_, err := VerifyRS256JWT(ctx, tampered, mgr)
		if err == nil {
			t.Fatal("expected signature error for tampered token, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthIDTokenInvalid {
			t.Fatalf("expected CodeOAuthIDTokenInvalid, got %v", err)
		}
	})

	t.Run("ignore non-signing keys in jwks", func(t *testing.T) {
		privKeyEnc, nEnc, eEnc := generateTestRSAKey(t)
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			doc := JWKDoc{
				Keys: []JWKKey{
					{
						Kty: "RSA",
						Use: "enc", // Encryption key, must be ignored
						Kid: "key-enc",
						N:   nEnc,
						E:   eEnc,
					},
					{
						Kty: "RSA",
						Use: "sig",
						Kid: "key-sig",
						N:   nRaw,
						E:   eRaw,
					},
				},
			}
			_ = json.NewEncoder(w).Encode(doc)
		}))
		defer s.Close()

		mgr := NewJWKSManager(s.URL, s.Client(), 1*time.Hour)
		_, err := mgr.GetKey(ctx, "key-enc")
		if err == nil {
			t.Fatal("expected error getting encryption key, got nil")
		}
		sigKey, err := mgr.GetKey(ctx, "key-sig")
		if err != nil {
			t.Fatalf("failed to get sig key: %v", err)
		}
		if sigKey.Key.N.Cmp(privKey.N) != 0 {
			t.Fatalf("modulus mismatch")
		}
		_ = privKeyEnc
	})
}

func TestJWKSManager_UnknownKidRepeatUsesNegativeCache(t *testing.T) {
	_, nRaw, eRaw := generateTestRSAKey(t)
	var jwksRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksRequests.Add(1)
		_ = json.NewEncoder(w).Encode(JWKDoc{Keys: []JWKKey{
			{Kty: "RSA", Use: "sig", Kid: "key-1", Alg: "RS256", N: nRaw, E: eRaw},
		}})
	}))
	defer server.Close()

	ctx := context.Background()
	mgr := NewJWKSManager(server.URL, server.Client(), time.Hour)

	if _, err := mgr.GetKey(ctx, "unknown-kid"); err == nil {
		t.Fatal("expected not-found error for unknown kid, got nil")
	}
	if _, err := mgr.GetKey(ctx, "unknown-kid"); err == nil {
		t.Fatal("expected not-found error for unknown kid, got nil")
	}
	// A first miss costs the primary fetch plus the rollover re-check that
	// confirms a rotation; the negative cache makes the repeat free.
	if got := jwksRequests.Load(); got != 2 {
		t.Fatalf("sequential unknown-kid lookups cost %d fetches, want 2", got)
	}
}

func TestJWKSManager_UnknownKidPerKidCooldown(t *testing.T) {
	_, n1, e1 := generateTestRSAKey(t)
	_, n2, e2 := generateTestRSAKey(t)
	var jwksRequests atomic.Int32
	var rotated atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksRequests.Add(1)
		keys := []JWKKey{
			{Kty: "RSA", Use: "sig", Kid: "key-1", Alg: "RS256", N: n1, E: e1},
		}
		if rotated.Load() {
			keys = append(keys, JWKKey{Kty: "RSA", Use: "sig", Kid: "key-2", Alg: "RS256", N: n2, E: e2})
		}
		_ = json.NewEncoder(w).Encode(JWKDoc{Keys: keys})
	}))
	defer server.Close()

	ctx := context.Background()
	mgr := NewJWKSManager(server.URL, server.Client(), time.Hour)

	// Each first miss costs the primary fetch plus the rollover re-check;
	// repeats ride the per-kid negative cache.
	if _, err := mgr.GetKey(ctx, "unknown-a"); err == nil {
		t.Fatal("expected not-found for unknown-a, got nil")
	}
	if got := jwksRequests.Load(); got != 2 {
		t.Fatalf("first miss cost %d fetches, want 2", got)
	}
	// Genuine rotation: key-2 appears after unknown-a miss; lookup must fetch,
	// not fail closed on unknown-a's cooldown.
	rotated.Store(true)
	if _, err := mgr.GetKey(ctx, "key-2"); err != nil {
		t.Fatalf("rotation pickup failed: %v (fetches=%d)", err, jwksRequests.Load())
	}
	if got := jwksRequests.Load(); got != 3 {
		t.Fatalf("rotation lookup cost %d fetches, want 3", got)
	}
	// A different unknown kid must also fetch, not ride unknown-a's cooldown.
	if _, err := mgr.GetKey(ctx, "unknown-b"); err == nil {
		t.Fatal("expected not-found for unknown-b, got nil")
	}
	if got := jwksRequests.Load(); got != 5 {
		t.Fatalf("different unknown kid cost %d fetches, want 5", got)
	}
	// Same-kid negative cache still holds.
	if _, err := mgr.GetKey(ctx, "unknown-b"); err == nil {
		t.Fatal("expected not-found for unknown-b repeat, got nil")
	}
	if got := jwksRequests.Load(); got != 5 {
		t.Fatalf("repeat unknown-b cost %d fetches, want 5", got)
	}
	if _, err := mgr.GetKey(ctx, "unknown-a"); err == nil {
		t.Fatal("expected not-found for unknown-a repeat, got nil")
	}
	if got := jwksRequests.Load(); got != 5 {
		t.Fatalf("repeat unknown-a cost %d fetches, want 5", got)
	}
}

func TestJWKSManager_RefreshFailureOnFreshSetStaysAuthError(t *testing.T) {
	_, nRaw, eRaw := generateTestRSAKey(t)
	var fail atomic.Bool
	var jwksRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwksRequests.Add(1)
		if fail.Load() {
			http.Error(w, "upstream down", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(JWKDoc{Keys: []JWKKey{
			{Kty: "RSA", Use: "sig", Kid: "key-1", Alg: "RS256", N: nRaw, E: eRaw},
		}})
	}))
	defer server.Close()

	ctx := context.Background()
	mgr := NewJWKSManager(server.URL, server.Client(), time.Hour)
	if _, err := mgr.GetKey(ctx, "key-1"); err != nil {
		t.Fatalf("warm fetch failed: %v", err)
	}
	fail.Store(true)

	// The committed set is fresh, so a failed fetch cannot explain the kid away:
	// an unknown kid is an auth failure, never a provider 502.
	_, err := mgr.GetKey(ctx, "unknown-kid")
	if err == nil {
		t.Fatal("expected auth failure for unknown kid, got nil")
	}
	var appErr *errors.Error
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthIDTokenInvalid {
		t.Fatalf("expected CodeOAuthIDTokenInvalid against a fresh set, got %v", err)
	}

	before := jwksRequests.Load()
	if _, err := mgr.GetKey(ctx, "unknown-kid"); err == nil {
		t.Fatal("expected auth failure for cached miss, got nil")
	}
	if got := jwksRequests.Load(); got != before {
		t.Fatalf("recorded miss cost %d fetches, want 0", got-before)
	}
}

func TestJWKSManager_RefreshFailureServesStaleWithinGrace(t *testing.T) {
	_, nRaw, eRaw := generateTestRSAKey(t)
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "upstream down", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(JWKDoc{Keys: []JWKKey{
			{Kty: "RSA", Use: "sig", Kid: "key-1", Alg: "RS256", N: nRaw, E: eRaw},
		}})
	}))
	defer server.Close()

	ctx := context.Background()
	mgr := NewJWKSManager(server.URL, server.Client(), time.Hour)
	if _, err := mgr.GetKey(ctx, "key-1"); err != nil {
		t.Fatalf("warm fetch failed: %v", err)
	}
	fail.Store(true)

	mgr.mu.Lock()
	mgr.expires = time.Now().Add(-30 * time.Minute)
	mgr.mu.Unlock()
	if _, err := mgr.GetKey(ctx, "key-1"); err != nil {
		t.Fatalf("stale within grace failed: %v", err)
	}

	mgr.mu.Lock()
	mgr.expires = time.Now().Add(-2 * jwksStaleGracePeriod)
	mgr.mu.Unlock()
	if _, err := mgr.GetKey(ctx, "key-1"); err == nil {
		t.Fatal("expected error beyond stale grace, got nil")
	}
}

func TestValidateDiscoveryDocument(t *testing.T) {
	valid := OIDCDiscovery{
		Issuer:                "https://login.example.com/tenant",
		AuthorizationEndpoint: "https://login.example.com/auth",
		TokenEndpoint:         "https://login.example.com/token",
		JWKSURI:               "https://login.example.com/keys",
	}
	discoveryURL := "https://login.example.com/.well-known/openid-configuration"
	if err := validateDiscoveryDocument(discoveryURL, &valid); err != nil {
		t.Fatalf("valid doc rejected: %v", err)
	}

	swapped := valid
	swapped.Issuer = "https://evil.example.com/tenant"
	if err := validateDiscoveryDocument(discoveryURL, &swapped); err == nil {
		t.Fatal("expected issuer mismatch error, got nil")
	}

	noIssuer := valid
	noIssuer.Issuer = ""
	if err := validateDiscoveryDocument(discoveryURL, &noIssuer); err == nil {
		t.Fatal("expected missing issuer error, got nil")
	}

	plainHTTP := valid
	plainHTTP.JWKSURI = "http://login.example.com/keys"
	if err := validateDiscoveryDocument(discoveryURL, &plainHTTP); err == nil {
		t.Fatal("expected non-loopback http jwks_uri error, got nil")
	}

	loopback := valid
	loopback.Issuer = "http://127.0.0.1:8080"
	loopback.JWKSURI = "http://127.0.0.1:8080/keys"
	if err := validateDiscoveryDocument("http://127.0.0.1:8080/.well-known/openid-configuration", &loopback); err != nil {
		t.Fatalf("loopback http doc rejected: %v", err)
	}
}

func TestVerifyRS256JWT_KeyIssuerBinding(t *testing.T) {
	const (
		tenantAIssuer = "https://login.microsoftonline.com/tenant-a/v2.0"
		tenantBIssuer = "https://login.microsoftonline.com/tenant-b/v2.0"
		templated     = "https://login.microsoftonline.com/{tenantid}/v2.0"
	)

	privKey, nRaw, eRaw := generateTestRSAKey(t)
	ctx := context.Background()

	newManager := func(t *testing.T, issuer string) *JWKSManager {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(JWKDoc{Keys: []JWKKey{{
				Kty: "RSA", Use: "sig", Kid: "k1", Alg: "RS256", N: nRaw, E: eRaw, Issuer: issuer,
			}}})
		}))
		t.Cleanup(srv.Close)
		return NewJWKSManager(srv.URL, srv.Client(), time.Hour)
	}

	tests := []struct {
		name      string
		keyIssuer string
		iss       string
		tid       string
		wantErr   bool
	}{
		{name: "matching concrete issuer", keyIssuer: tenantAIssuer, iss: tenantAIssuer, tid: "tenant-a"},
		{name: "foreign concrete issuer", keyIssuer: tenantAIssuer, iss: tenantBIssuer, tid: "tenant-b", wantErr: true},
		{name: "templated issuer resolved by tid", keyIssuer: templated, iss: tenantAIssuer, tid: "tenant-a"},
		{name: "templated issuer rejects iss that disagrees with resolved tid", keyIssuer: templated, iss: tenantBIssuer, tid: "tenant-a", wantErr: true},
		{name: "unresolvable template is not enforced", keyIssuer: "https://login.example.com/{unknown}/v2.0", iss: tenantAIssuer, tid: "tenant-a"},
		{name: "absent key issuer is not enforced", keyIssuer: "", iss: tenantAIssuer, tid: "tenant-a"},
		{name: "concrete issuer with missing token issuer", keyIssuer: tenantAIssuer, iss: "", tid: "tenant-a", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newManager(t, tt.keyIssuer)
			rawJWT := signRS256JWT(t, privKey, "k1", map[string]any{
				"iss": tt.iss,
				"tid": tt.tid,
				"sub": "user-1",
				"aud": "client-1",
			})

			_, err := VerifyRS256JWT(ctx, rawJWT, mgr)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("verification failed: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected issuer binding rejection, got nil")
			}
			var appErr *errors.Error
			if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthIDTokenInvalid {
				t.Fatalf("expected CodeOAuthIDTokenInvalid, got %v", err)
			}
		})
	}
}

func TestMicrosoftProvider(t *testing.T) {
	privKey, nRaw, eRaw := generateTestRSAKey(t)
	var jwksRequests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/keys":
			jwksRequests.Add(1)
			doc := JWKDoc{
				Keys: []JWKKey{
					{
						Kty: "RSA",
						Use: "sig",
						Kid: "ms-key-1",
						Alg: "RS256",
						N:   nRaw,
						E:   eRaw,
					},
				},
			}
			_ = json.NewEncoder(w).Encode(doc)
		case "/token":
			if r.Method != http.MethodPost {
				http.Error(w, "bad method", http.StatusMethodNotAllowed)
				return
			}
			_ = r.ParseForm()
			if r.FormValue("client_id") != "client-test-id" || r.FormValue("client_secret") != "client-test-secret" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if r.FormValue("grant_type") != "authorization_code" {
				http.Error(w, "bad grant_type", http.StatusBadRequest)
				return
			}
			if r.FormValue("redirect_uri") != "https://example.com/callback" {
				http.Error(w, "bad redirect_uri", http.StatusBadRequest)
				return
			}
			if r.FormValue("code_verifier") != "verifier-123" {
				http.Error(w, "bad verifier", http.StatusBadRequest)
				return
			}
			if r.FormValue("code") == "bad-code" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
				return
			}

			// Valid token response
			idTokenClaims := map[string]any{
				"iss":   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
				"sub":   "consumer-sub-1",
				"aud":   "client-test-id",
				"exp":   time.Now().Add(10 * time.Minute).Unix(),
				"iat":   time.Now().Unix(),
				"email": "consumer@outlook.com",
				"tid":   MicrosoftConsumerTenantGUID,
				"name":  "Consumer User",
			}
			idTok := signRS256JWT(t, privKey, "ms-key-1", idTokenClaims)

			resp := map[string]any{
				"token_type":    "Bearer",
				"access_token":  "mock-access-token",
				"refresh_token": "mock-refresh-token",
				"expires_in":    3600,
				"id_token":      idTok,
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	newTestProvider := func(tenant string, trusted []string) *MicrosoftProvider {
		cfg := config.MicrosoftConfig{
			ClientID:       "client-test-id",
			ClientSecret:   "client-test-secret",
			Tenant:         tenant,
			TrustedTenants: trusted,
			RedirectURI:    "https://example.com/callback",
		}
		p := NewMicrosoftProvider(cfg)
		p.client = server.Client()
		p.tokenURL = server.URL + "/token"
		p.jwksURL = server.URL + "/keys"
		p.jwksMgr = NewJWKSManager(server.URL+"/keys", p.client, 24*time.Hour)
		p.jwksRetriever = p.jwksMgr
		return p
	}

	ctx := context.Background()

	t.Run("AuthCodeURL generation", func(t *testing.T) {
		p := newTestProvider("common", nil)
		authURL := p.AuthCodeURL("state-123", "challenge-xyz", NonceOption("nonce-abc"), PromptOption("consent"))

		u, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("failed to parse url: %v", err)
		}
		q := u.Query()
		if q.Get("client_id") != "client-test-id" {
			t.Errorf("client_id = %q", q.Get("client_id"))
		}
		if q.Get("state") != "state-123" {
			t.Errorf("state = %q", q.Get("state"))
		}
		if q.Get("code_challenge") != "challenge-xyz" {
			t.Errorf("code_challenge = %q", q.Get("code_challenge"))
		}
		if q.Get("code_challenge_method") != "S256" {
			t.Errorf("code_challenge_method = %q", q.Get("code_challenge_method"))
		}
		if q.Get("nonce") != "nonce-abc" {
			t.Errorf("nonce = %q", q.Get("nonce"))
		}
		if q.Get("prompt") != "consent" {
			t.Errorf("prompt = %q", q.Get("prompt"))
		}
	})

	t.Run("per-authority URL construction", func(t *testing.T) {
		cases := []struct{ tenant, want string }{
			{"common", "common"},
			{"consumers", "consumers"},
			{"organizations", "organizations"},
			{"target-tenant-uuid", "target-tenant-uuid"},
			{"", "common"},
		}
		for _, tc := range cases {
			p := NewMicrosoftProvider(config.MicrosoftConfig{ClientID: "cid", Tenant: tc.tenant})
			for name, got := range map[string]string{"authURL": p.authURL, "tokenURL": p.tokenURL, "jwksURL": p.jwksURL} {
				if !strings.Contains(got, "/"+tc.want+"/") {
					t.Errorf("tenant %q: %s = %q, want segment %q", tc.tenant, name, got, tc.want)
				}
			}
		}
	})

	t.Run("ExchangeCode success and failure", func(t *testing.T) {
		p := newTestProvider("common", nil)
		tok, err := p.ExchangeCode(ctx, "good-code", "verifier-123")
		if err != nil {
			t.Fatalf("exchange code failed: %v", err)
		}
		if tok.AccessToken != "mock-access-token" {
			t.Errorf("access_token = %q", tok.AccessToken)
		}
		if tok.IDToken == "" {
			t.Errorf("expected id_token")
		}

		// Bad code
		_, err = p.ExchangeCode(ctx, "bad-code", "verifier-123")
		if err == nil {
			t.Fatal("expected error for bad code, got nil")
		}
	})

	t.Run("VerifyIDToken dynamic issuer and authority modes", func(t *testing.T) {
		// 1. Consumers authority mode accepts consumer GUID
		pConsumer := newTestProvider("consumers", nil)
		claimsConsumer := map[string]any{
			"iss":   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			"sub":   "sub-consumer",
			"aud":   "client-test-id",
			"exp":   time.Now().Add(10 * time.Minute).Unix(),
			"email": "user@outlook.com",
			"tid":   MicrosoftConsumerTenantGUID,
		}
		tokConsumer := signRS256JWT(t, privKey, "ms-key-1", claimsConsumer)
		c, err := pConsumer.VerifyIDToken(ctx, tokConsumer, "")
		if err != nil {
			t.Fatalf("consumers mode verification failed: %v", err)
		}
		if !c.EmailVerified {
			t.Errorf("expected consumer email to be verified")
		}

		// Consumers mode rejects non-consumer issuer
		claimsOrgInConsumer := map[string]any{
			"iss": "https://login.microsoftonline.com/custom-tenant-guid/v2.0",
			"sub": "sub-org",
			"aud": "client-test-id",
			"exp": time.Now().Add(10 * time.Minute).Unix(),
			"tid": "custom-tenant-guid",
		}
		tokOrgInConsumer := signRS256JWT(t, privKey, "ms-key-1", claimsOrgInConsumer)
		_, err = pConsumer.VerifyIDToken(ctx, tokOrgInConsumer, "")
		if err == nil {
			t.Fatal("expected error for non-consumer issuer in consumers mode")
		}

		// 2. Organizations mode accepts custom tenant GUID but rejects consumer account
		pOrg := newTestProvider("organizations", nil)
		claimsOrg := map[string]any{
			"iss":   "https://login.microsoftonline.com/corp-tenant-guid/v2.0",
			"sub":   "sub-corp",
			"aud":   "client-test-id",
			"exp":   time.Now().Add(10 * time.Minute).Unix(),
			"email": "corp@company.com",
			"tid":   "corp-tenant-guid",
		}
		tokOrg := signRS256JWT(t, privKey, "ms-key-1", claimsOrg)
		_, err = pOrg.VerifyIDToken(ctx, tokOrg, "")
		if err != nil {
			t.Fatalf("organizations mode verification failed: %v", err)
		}

		// Organizations mode rejects consumer account
		_, err = pOrg.VerifyIDToken(ctx, tokConsumer, "")
		if err == nil {
			t.Fatal("expected error when consumer account logs in under organizations mode")
		}

		// 3. Specific tenant GUID
		pSingle := newTestProvider("target-tenant-uuid", nil)
		claimsSingle := map[string]any{
			"iss":   "https://login.microsoftonline.com/target-tenant-uuid/v2.0",
			"sub":   "sub-single",
			"aud":   "client-test-id",
			"exp":   time.Now().Add(10 * time.Minute).Unix(),
			"email": "single@target.com",
			"tid":   "target-tenant-uuid",
		}
		tokSingle := signRS256JWT(t, privKey, "ms-key-1", claimsSingle)
		cSingle, err := pSingle.VerifyIDToken(ctx, tokSingle, "")
		if err != nil {
			t.Fatalf("single tenant verification failed: %v", err)
		}
		if !cSingle.EmailVerified {
			t.Errorf("expected single tenant email to be verified")
		}

		// Specific tenant rejects foreign tenant
		_, err = pSingle.VerifyIDToken(ctx, tokOrg, "")
		if err == nil {
			t.Fatal("expected error when foreign tenant connects to single-tenant adapter")
		}
	})

	t.Run("nOauth defense - untrusted tenant vs domain ownership attestation", func(t *testing.T) {
		pMulti := newTestProvider("common", nil)
		pCommon := newTestProvider("common", []string{"trusted-partner-guid"})

		// 1. Untrusted tenant without xms_edov -> EmailVerified must be FALSE
		claimsUntrusted := map[string]any{
			"iss":   "https://login.microsoftonline.com/untrusted-guid/v2.0",
			"sub":   "attacker-sub",
			"aud":   "client-test-id",
			"exp":   time.Now().Add(10 * time.Minute).Unix(),
			"email": "victim@victim-corp.com",
			"tid":   "untrusted-guid",
		}
		tokUntrusted := signRS256JWT(t, privKey, "ms-key-1", claimsUntrusted)
		cUntrusted, err := pMulti.VerifyIDToken(ctx, tokUntrusted, "")
		if err != nil {
			t.Fatalf("unexpected verification error: %v", err)
		}
		if cUntrusted.EmailVerified {
			t.Errorf("nOauth vulnerability: untrusted tenant should have EmailVerified == false")
		}
		if !cUntrusted.UntrustedTenant {
			t.Errorf("untrusted tenant must set UntrustedTenant == true")
		}

		// 2. Untrusted tenant with xms_edov == '1' -> EmailVerified must be TRUE
		// when no allowlist bounds the tenants. The allowlist case is covered by
		// the tenant-allowlist table below.
		claimsAttested := map[string]any{
			"iss":      "https://login.microsoftonline.com/untrusted-guid/v2.0",
			"sub":      "verified-sub",
			"aud":      "client-test-id",
			"exp":      time.Now().Add(10 * time.Minute).Unix(),
			"email":    "user@attested-corp.com",
			"tid":      "untrusted-guid",
			"xms_edov": "1",
		}
		tokAttested := signRS256JWT(t, privKey, "ms-key-1", claimsAttested)
		cAttested, err := pMulti.VerifyIDToken(ctx, tokAttested, "")
		if err != nil {
			t.Fatalf("unexpected verification error: %v", err)
		}
		if !cAttested.EmailVerified {
			t.Errorf("expected EmailVerified == true when xms_edov == '1'")
		}
		if cAttested.UntrustedTenant {
			t.Errorf("attested tenant must leave UntrustedTenant == false")
		}

		// 2b. Boolean true attestation -> EmailVerified must be TRUE
		claimsBool := map[string]any{
			"iss":      "https://login.microsoftonline.com/untrusted-guid/v2.0",
			"sub":      "bool-sub",
			"aud":      "client-test-id",
			"exp":      time.Now().Add(10 * time.Minute).Unix(),
			"email":    "user@attested-corp.com",
			"tid":      "untrusted-guid",
			"xms_edov": true,
		}
		tokBool := signRS256JWT(t, privKey, "ms-key-1", claimsBool)
		cBool, err := pMulti.VerifyIDToken(ctx, tokBool, "")
		if err != nil {
			t.Fatalf("unexpected verification error: %v", err)
		}
		if !cBool.EmailVerified {
			t.Errorf("expected EmailVerified == true when xms_edov is bool true")
		}
		if cBool.UntrustedTenant {
			t.Errorf("attested tenant must leave UntrustedTenant == false")
		}

		// 2c. Numeric 1 attestation -> EmailVerified must be TRUE
		claimsNum := map[string]any{
			"iss":      "https://login.microsoftonline.com/untrusted-guid/v2.0",
			"sub":      "num-sub",
			"aud":      "client-test-id",
			"exp":      time.Now().Add(10 * time.Minute).Unix(),
			"email":    "user@attested-corp.com",
			"tid":      "untrusted-guid",
			"xms_edov": 1,
		}
		tokNum := signRS256JWT(t, privKey, "ms-key-1", claimsNum)
		cNum, err := pMulti.VerifyIDToken(ctx, tokNum, "")
		if err != nil {
			t.Fatalf("unexpected verification error: %v", err)
		}
		if !cNum.EmailVerified {
			t.Errorf("expected EmailVerified == true when xms_edov is numeric 1")
		}
		if cNum.UntrustedTenant {
			t.Errorf("attested tenant must leave UntrustedTenant == false")
		}

		// 2d. Boolean false attestation -> EmailVerified must stay FALSE
		claimsFalse := map[string]any{
			"iss":      "https://login.microsoftonline.com/untrusted-guid/v2.0",
			"sub":      "false-sub",
			"aud":      "client-test-id",
			"exp":      time.Now().Add(10 * time.Minute).Unix(),
			"email":    "user@attested-corp.com",
			"tid":      "untrusted-guid",
			"xms_edov": false,
		}
		tokFalse := signRS256JWT(t, privKey, "ms-key-1", claimsFalse)
		cFalse, err := pMulti.VerifyIDToken(ctx, tokFalse, "")
		if err != nil {
			t.Fatalf("unexpected verification error: %v", err)
		}
		if cFalse.EmailVerified {
			t.Errorf("expected EmailVerified == false when xms_edov is bool false")
		}
		if !cFalse.UntrustedTenant {
			t.Errorf("denied attestation must set UntrustedTenant == true")
		}

		// 3. Whitelist alone never verifies the email value.
		claimsTrusted := map[string]any{
			"iss":   "https://login.microsoftonline.com/trusted-partner-guid/v2.0",
			"sub":   "partner-sub",
			"aud":   "client-test-id",
			"exp":   time.Now().Add(10 * time.Minute).Unix(),
			"email": "partner@partner.com",
			"tid":   "trusted-partner-guid",
		}
		tokTrusted := signRS256JWT(t, privKey, "ms-key-1", claimsTrusted)
		cTrusted, err := pCommon.VerifyIDToken(ctx, tokTrusted, "")
		if err != nil {
			t.Fatalf("unexpected verification error: %v", err)
		}
		if cTrusted.EmailVerified {
			t.Errorf("whitelist alone must leave EmailVerified == false")
		}
		if !cTrusted.UntrustedTenant {
			t.Errorf("whitelist alone must set UntrustedTenant == true")
		}

		// 3b. Whitelist + attestation verifies.
		claimsTrustedAttested := map[string]any{
			"iss":      "https://login.microsoftonline.com/trusted-partner-guid/v2.0",
			"sub":      "partner-sub",
			"aud":      "client-test-id",
			"exp":      time.Now().Add(10 * time.Minute).Unix(),
			"email":    "partner@partner.com",
			"tid":      "trusted-partner-guid",
			"xms_edov": true,
		}
		tokTrustedAttested := signRS256JWT(t, privKey, "ms-key-1", claimsTrustedAttested)
		cTrustedAttested, err := pCommon.VerifyIDToken(ctx, tokTrustedAttested, "")
		if err != nil {
			t.Fatalf("unexpected verification error: %v", err)
		}
		if !cTrustedAttested.EmailVerified {
			t.Errorf("expected EmailVerified == true for whitelisted tenant with xms_edov")
		}
		if cTrustedAttested.UntrustedTenant {
			t.Errorf("attested whitelisted tenant must leave UntrustedTenant == false")
		}
	})

	t.Run("token expiration, audience and nonce security checks", func(t *testing.T) {
		p := newTestProvider("common", nil)

		// 1. Expired token (outside 1m skew)
		claimsExpired := map[string]any{
			"iss": "https://login.microsoftonline.com/tid-1/v2.0",
			"sub": "sub-1",
			"aud": "client-test-id",
			"exp": time.Now().Add(-5 * time.Minute).Unix(),
			"tid": "tid-1",
		}
		tokExpired := signRS256JWT(t, privKey, "ms-key-1", claimsExpired)
		_, err := p.VerifyIDToken(ctx, tokExpired, "")
		if err == nil {
			t.Fatal("expected error for expired token, got nil")
		}

		// 2. Audience mismatch
		claimsBadAud := map[string]any{
			"iss": "https://login.microsoftonline.com/tid-1/v2.0",
			"sub": "sub-1",
			"aud": "wrong-client-id",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"tid": "tid-1",
		}
		tokBadAud := signRS256JWT(t, privKey, "ms-key-1", claimsBadAud)
		_, err = p.VerifyIDToken(ctx, tokBadAud, "")
		if err == nil {
			t.Fatal("expected error for audience mismatch, got nil")
		}

		// 3. Nonce mismatch
		claimsNonce := map[string]any{
			"iss":   "https://login.microsoftonline.com/tid-1/v2.0",
			"sub":   "sub-1",
			"aud":   "client-test-id",
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"tid":   "tid-1",
			"nonce": "valid-nonce",
		}
		tokNonce := signRS256JWT(t, privKey, "ms-key-1", claimsNonce)
		_, err = p.VerifyIDToken(ctx, tokNonce, "tampered-nonce")
		if err == nil {
			t.Fatal("expected error for nonce mismatch, got nil")
		}
		cNonce, err := p.VerifyIDToken(ctx, tokNonce, "valid-nonce")
		if err != nil || cNonce.Nonce != "valid-nonce" {
			t.Fatalf("failed to verify valid nonce: %v", err)
		}

		// 4. Future IssuedAt (> now + 60)
		claimsFuture := map[string]any{
			"iss": "https://login.microsoftonline.com/tid-1/v2.0",
			"sub": "sub-1",
			"aud": "client-test-id",
			"exp": time.Now().Add(10 * time.Minute).Unix(),
			"iat": time.Now().Add(5 * time.Minute).Unix(),
			"tid": "tid-1",
		}
		tokFuture := signRS256JWT(t, privKey, "ms-key-1", claimsFuture)
		_, err = p.VerifyIDToken(ctx, tokFuture, "")
		if err == nil {
			t.Fatal("expected error for future iat, got nil")
		}

		// 5. json.Number iat is parsed correctly
		nowUnix := time.Now().Unix()
		claimsJSONNumber := map[string]any{
			"iss": "https://login.microsoftonline.com/tid-1/v2.0",
			"sub": "sub-1",
			"aud": "client-test-id",
			"exp": json.Number(strconv.FormatInt(nowUnix+600, 10)),
			"iat": json.Number(strconv.FormatInt(nowUnix, 10)),
			"tid": "tid-1",
		}
		tokJSONNumber := signRS256JWT(t, privKey, "ms-key-1", claimsJSONNumber)
		cNum, err := p.VerifyIDToken(ctx, tokJSONNumber, "")
		if err != nil {
			t.Fatalf("failed to verify token with json.Number: %v", err)
		}
		if cNum.IssuedAt != nowUnix {
			t.Fatalf("expected IssuedAt %d from json.Number, got %d", nowUnix, cNum.IssuedAt)
		}
	})

	t.Run("VerifyIDToken requires an identity claim", func(t *testing.T) {
		p := newTestProvider("common", nil)

		claimsMissing := map[string]any{
			"iss": "https://login.microsoftonline.com/tid-1/v2.0",
			"aud": "client-test-id",
			"exp": time.Now().Add(10 * time.Minute).Unix(),
			"tid": "tid-1",
		}
		tokMissing := signRS256JWT(t, privKey, "ms-key-1", claimsMissing)
		_, err := p.VerifyIDToken(ctx, tokMissing, "")
		if err == nil {
			t.Fatal("expected rejection for token missing sub and oid")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthIDTokenInvalid {
			t.Fatalf("expected CodeOAuthIDTokenInvalid, got %v", err)
		}

		claimsOIDOnly := map[string]any{
			"iss": "https://login.microsoftonline.com/tid-1/v2.0",
			"oid": "oid-only",
			"aud": "client-test-id",
			"exp": time.Now().Add(10 * time.Minute).Unix(),
			"tid": "tid-1",
		}
		tokOIDOnly := signRS256JWT(t, privKey, "ms-key-1", claimsOIDOnly)
		if _, err := p.VerifyIDToken(ctx, tokOIDOnly, ""); err != nil {
			t.Fatalf("token with oid but no sub must verify: %v", err)
		}
	})

	t.Run("FetchUserInfo maps OID and uses only the email claim", func(t *testing.T) {
		p := newTestProvider("common", nil)

		newToken := func(t *testing.T, extra map[string]any) string {
			t.Helper()
			claims := map[string]any{
				"iss":                "https://login.microsoftonline.com/tid-1/v2.0",
				"sub":                "sub-fallback",
				"oid":                "immutable-oid-guid",
				"aud":                "client-test-id",
				"exp":                time.Now().Add(10 * time.Minute).Unix(),
				"preferred_username": "fallback.user@example.com",
				"tid":                "tid-1",
				"name":               "Fallback User",
			}
			for k, v := range extra {
				claims[k] = v
			}
			return signRS256JWT(t, privKey, "ms-key-1", claims)
		}

		t.Run("preferred_username fallback stays unverified", func(t *testing.T) {
			user, err := p.FetchUserInfo(ctx, &OAuthToken{IDToken: newToken(t, nil)})
			if err != nil {
				t.Fatalf("FetchUserInfo failed: %v", err)
			}
			if user.ProviderUserID != "immutable-oid-guid" {
				t.Errorf("ProviderUserID = %q, want immutable-oid-guid", user.ProviderUserID)
			}
			// Merge premise (oauth sync): the fail-closed UPN fallback keeps
			// the admin-mutable address for display but never verifies it, so
			// registration still rejects it as unverified below.
			if user.Email != "fallback.user@example.com" {
				t.Errorf("Email = %q, want lowercased UPN fallback", user.Email)
			}
			if user.EmailVerified {
				t.Error("EmailVerified = true for a profile without an email claim")
			}
			if got := user.RawClaims["preferred_username"]; got != "fallback.user@example.com" {
				t.Errorf("RawClaims[preferred_username] = %v, want fallback.user@example.com", got)
			}
			if err := validateProviderIdentity(user); !errors.Is(err, errors.ErrOAuthEmailUnverified) {
				t.Errorf("validateProviderIdentity = %v, want ErrOAuthEmailUnverified", err)
			}
		})

		t.Run("email claim wins over preferred_username", func(t *testing.T) {
			user, err := p.FetchUserInfo(ctx, &OAuthToken{IDToken: newToken(t, map[string]any{
				"email": "Primary.User@Example.com",
			})})
			if err != nil {
				t.Fatalf("FetchUserInfo failed: %v", err)
			}
			if user.Email != "primary.user@example.com" {
				t.Errorf("Email = %q, want primary.user@example.com", user.Email)
			}
		})
	})

	t.Run("FetchUserInfo preferred_username fallback never verifies", func(t *testing.T) {
		p := newTestProvider("target-tenant-uuid", nil)
		claims := map[string]any{
			"iss":                "https://login.microsoftonline.com/target-tenant-uuid/v2.0",
			"sub":                "sub-single-fallback",
			"oid":                "immutable-oid-guid",
			"aud":                "client-test-id",
			"exp":                time.Now().Add(10 * time.Minute).Unix(),
			"preferred_username": "victim@local.com",
			"tid":                "target-tenant-uuid",
			"name":               "Fallback Victim",
		}
		idTok := signRS256JWT(t, privKey, "ms-key-1", claims)

		user, err := p.FetchUserInfo(ctx, &OAuthToken{IDToken: idTok})
		if err != nil {
			t.Fatalf("FetchUserInfo failed: %v", err)
		}
		if user.Email != "victim@local.com" {
			t.Errorf("Email = %q, want victim@local.com", user.Email)
		}
		if user.EmailVerified {
			t.Errorf("UPN fallback must force EmailVerified == false even on trusted tenant")
		}
	})
}

func TestMicrosoftProvider_DomainOwnershipAttestation(t *testing.T) {
	privKey, nRaw, eRaw := generateTestRSAKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(JWKDoc{Keys: []JWKKey{{
			Kty: "RSA", Use: "sig", Kid: "ms-key-1", Alg: "RS256", N: nRaw, E: eRaw,
		}}})
	}))
	defer server.Close()

	newProvider := func(t *testing.T, trusted []string) *MicrosoftProvider {
		t.Helper()
		p := NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:       "client-test-id",
			ClientSecret:   "client-test-secret",
			Tenant:         "common",
			TrustedTenants: trusted,
			RedirectURI:    "https://example.com/callback",
		})
		p.client = server.Client()
		p.jwksMgr = NewJWKSManager(server.URL, p.client, time.Hour)
		p.jwksRetriever = p.jwksMgr
		return p
	}

	const (
		listedTenant   = "listed-tenant-guid"
		unlistedTenant = "unlisted-tenant-guid"
	)
	allowlist := []string{listedTenant}

	tests := []struct {
		name         string
		trusted      []string
		tenant       string
		edov         any
		setEdov      bool
		wantVerified bool
	}{
		{name: "no allowlist string one", tenant: unlistedTenant, edov: "1", setEdov: true, wantVerified: true},
		{name: "no allowlist string true", tenant: unlistedTenant, edov: "true", setEdov: true, wantVerified: true},
		{name: "no allowlist bool true", tenant: unlistedTenant, edov: true, setEdov: true, wantVerified: true},
		{name: "no allowlist string zero", tenant: unlistedTenant, edov: "0", setEdov: true},
		{name: "no allowlist bool false", tenant: unlistedTenant, edov: false, setEdov: true},
		{name: "no allowlist missing claim", tenant: unlistedTenant},
		// The allowlist bounds tenant trust: listed tenants still need domain
		// attestation for the email value, and attestation cannot admit an
		// unlisted tenant.
		{name: "allowlist listed tenant unattested", trusted: allowlist, tenant: listedTenant},
		{name: "allowlist listed tenant attested", trusted: allowlist, tenant: listedTenant, edov: "1", setEdov: true, wantVerified: true},
		{name: "allowlist unlisted tenant string one", trusted: allowlist, tenant: unlistedTenant, edov: "1", setEdov: true},
		{name: "allowlist unlisted tenant string true", trusted: allowlist, tenant: unlistedTenant, edov: "true", setEdov: true},
		{name: "allowlist unlisted tenant bool true", trusted: allowlist, tenant: unlistedTenant, edov: true, setEdov: true},
		{name: "allowlist unlisted tenant string zero", trusted: allowlist, tenant: unlistedTenant, edov: "0", setEdov: true},
		{name: "allowlist unlisted tenant bool false", trusted: allowlist, tenant: unlistedTenant, edov: false, setEdov: true},
		{name: "allowlist unlisted tenant missing claim", trusted: allowlist, tenant: unlistedTenant},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newProvider(t, tt.trusted)
			claims := map[string]any{
				"iss":   "https://login.microsoftonline.com/" + tt.tenant + "/v2.0",
				"sub":   "sub-1",
				"aud":   "client-test-id",
				"exp":   time.Now().Add(10 * time.Minute).Unix(),
				"email": "user@example.com",
				"tid":   tt.tenant,
			}
			if tt.setEdov {
				claims["xms_edov"] = tt.edov
			}
			tok := signRS256JWT(t, privKey, "ms-key-1", claims)

			c, err := p.VerifyIDToken(context.Background(), tok, "")
			if err != nil {
				t.Fatalf("VerifyIDToken = %v", err)
			}
			if c.EmailVerified != tt.wantVerified {
				t.Fatalf("EmailVerified = %v; want %v", c.EmailVerified, tt.wantVerified)
			}
			if !tt.wantVerified && !c.UntrustedTenant {
				t.Error("rejected tenant is missing the untrusted_tenant marker")
			}
			if tt.wantVerified && c.UntrustedTenant {
				t.Error("verified tenant carries the untrusted_tenant marker")
			}
		})
	}
}

const (
	contosoTenantGUID = "11111111-2222-3333-4444-555555555555"
	otherTenantGUID   = "99999999-8888-7777-6666-555555555555"
)

func TestMicrosoftProvider_TenantAllowlist(t *testing.T) {
	privKey, nRaw, eRaw := generateTestRSAKey(t)

	var serverURL string
	discovery := map[string]string{
		"contoso.onmicrosoft.com": contosoTenantGUID,
		"other.onmicrosoft.com":   otherTenantGUID,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domain, ok := strings.CutSuffix(r.URL.Path, "/v2.0/.well-known/openid-configuration")
		if ok {
			guid, found := discovery[strings.TrimPrefix(domain, "/")]
			if !found {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(OIDCDiscovery{
				Issuer:                serverURL + "/" + guid + "/v2.0",
				AuthorizationEndpoint: serverURL + "/authorize",
				TokenEndpoint:         serverURL + "/token",
				JWKSURI:               serverURL + "/keys",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(JWKDoc{Keys: []JWKKey{{
			Kty: "RSA", Use: "sig", Kid: "ms-key-1", Alg: "RS256", N: nRaw, E: eRaw,
		}}})
	}))
	defer server.Close()
	serverURL = server.URL

	newProvider := func(t *testing.T, tenant string, trusted []string) *MicrosoftProvider {
		t.Helper()
		if tenant == "" {
			tenant = "common"
		}
		p := NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:       "client-test-id",
			Tenant:         tenant,
			TrustedTenants: trusted,
			RedirectURI:    "https://example.com/callback",
		})
		p.client = server.Client()
		p.discoveryBaseURL = server.URL
		p.jwksMgr = NewJWKSManager(server.URL, p.client, time.Hour)
		p.jwksRetriever = p.jwksMgr
		return p
	}

	tests := []struct {
		name         string
		tenantCfg    string
		trusted      []string
		tid          string
		issuer       string
		wantTrusted  bool
		wantVerified bool
	}{
		{name: "no allowlist accepts any tenant", tid: "tenant-a", wantTrusted: true, wantVerified: true},
		{name: "listed guid", trusted: []string{"tenant-a"}, tid: "tenant-a", wantTrusted: true, wantVerified: true},
		{name: "listed guid uppercase entry", trusted: []string{"TENANT-A"}, tid: "tenant-a", wantTrusted: true, wantVerified: true},
		{name: "listed guid uppercase tid", trusted: []string{"tenant-a"}, tid: "TENANT-A", wantTrusted: true, wantVerified: true},
		{name: "listed domain resolves to guid", trusted: []string{"contoso.onmicrosoft.com"}, tid: contosoTenantGUID, wantTrusted: true, wantVerified: true},
		{name: "listed domain uppercase entry", trusted: []string{"Contoso.OnMicrosoft.com"}, tid: contosoTenantGUID, wantTrusted: true, wantVerified: true},
		{name: "domain tenant and domain allowlist", tenantCfg: "contoso.onmicrosoft.com", trusted: []string{"contoso.onmicrosoft.com"}, tid: contosoTenantGUID, wantTrusted: true, wantVerified: true},
		{name: "allowlist domain does not match", trusted: []string{"contoso.onmicrosoft.com"}, tid: otherTenantGUID},
		{name: "unlisted tenant rejected despite attestation", trusted: []string{"tenant-a"}, tid: "tenant-b"},
		{name: "unlisted domain rejected", trusted: []string{"tenant-a"}, tid: "evil.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newProvider(t, tt.tenantCfg, tt.trusted)
			issuer := tt.issuer
			if issuer == "" {
				issuer = "https://login.microsoftonline.com/" + tt.tid + "/v2.0"
			}
			claims := map[string]any{
				"iss":      issuer,
				"sub":      "sub-1",
				"aud":      "client-test-id",
				"exp":      time.Now().Add(10 * time.Minute).Unix(),
				"email":    "user@example.com",
				"tid":      tt.tid,
				"xms_edov": "1",
			}
			tok := signRS256JWT(t, privKey, "ms-key-1", claims)

			c, err := p.VerifyIDToken(context.Background(), tok, "")
			if err != nil {
				t.Fatalf("VerifyIDToken = %v", err)
			}
			if c.UntrustedTenant == tt.wantTrusted {
				t.Errorf("UntrustedTenant = %v; want trusted = %v", c.UntrustedTenant, tt.wantTrusted)
			}
			if c.EmailVerified != tt.wantVerified {
				t.Errorf("EmailVerified = %v; want %v", c.EmailVerified, tt.wantVerified)
			}
		})
	}
}

// TestMicrosoftProvider_TenantIdentityResolution pins the domain-vs-GUID rule:
// Microsoft always emits a GUID tid and a GUID issuer, so a domain configured
// as the authority or in the allowlist must be resolved to its tenant GUID.
func TestMicrosoftProvider_TenantIdentityResolution(t *testing.T) {
	privKey, nRaw, eRaw := generateTestRSAKey(t)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domain, ok := strings.CutSuffix(r.URL.Path, "/v2.0/.well-known/openid-configuration")
		if ok {
			guid, found := map[string]string{
				"contoso.onmicrosoft.com": contosoTenantGUID,
			}[strings.TrimPrefix(domain, "/")]
			if !found {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(OIDCDiscovery{
				Issuer:                serverURL + "/" + guid + "/v2.0",
				AuthorizationEndpoint: serverURL + "/authorize",
				TokenEndpoint:         serverURL + "/token",
				JWKSURI:               serverURL + "/keys",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(JWKDoc{Keys: []JWKKey{{
			Kty: "RSA", Use: "sig", Kid: "ms-key-1", Alg: "RS256", N: nRaw, E: eRaw,
		}}})
	}))
	defer server.Close()
	serverURL = server.URL

	tests := []struct {
		name          string
		tenant        string
		trusted       []string
		tid           string
		wantErrCode   errors.Code
		wantVerified  bool
		wantUntrusted bool
	}{
		{name: "domain tenant succeeds", tenant: "contoso.onmicrosoft.com", tid: contosoTenantGUID, wantVerified: true},
		{name: "guid tenant succeeds", tenant: contosoTenantGUID, tid: contosoTenantGUID, wantVerified: true},
		{name: "unlisted tenant rejected and marked", tenant: "common", trusted: []string{otherTenantGUID}, tid: contosoTenantGUID, wantUntrusted: true},
		{name: "allowlist domain matches", tenant: "common", trusted: []string{"contoso.onmicrosoft.com"}, tid: contosoTenantGUID, wantVerified: true},
		{name: "allowlist domain does not match", tenant: "common", trusted: []string{"contoso.onmicrosoft.com"}, tid: otherTenantGUID, wantUntrusted: true},
		{name: "unresolvable domain surfaces a config error", tenant: "unresolvable.onmicrosoft.com", tid: contosoTenantGUID, wantErrCode: errors.CodeOAuthProviderError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewMicrosoftProvider(config.MicrosoftConfig{
				ClientID:       "client-test-id",
				Tenant:         tt.tenant,
				TrustedTenants: tt.trusted,
				RedirectURI:    "https://example.com/callback",
			})
			p.client = server.Client()
			p.discoveryBaseURL = server.URL
			p.jwksMgr = NewJWKSManager(server.URL+"/keys", p.client, time.Hour)
			p.jwksRetriever = p.jwksMgr

			claims := map[string]any{
				"iss":   "https://login.microsoftonline.com/" + tt.tid + "/v2.0",
				"sub":   "sub-1",
				"aud":   "client-test-id",
				"exp":   time.Now().Add(10 * time.Minute).Unix(),
				"email": "user@contoso.com",
				"tid":   tt.tid,
			}
			if tt.tenant == "common" {
				claims["xms_edov"] = true
			}
			tok := signRS256JWT(t, privKey, "ms-key-1", claims)

			c, err := p.VerifyIDToken(context.Background(), tok, "")
			if tt.wantErrCode != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				var appErr *errors.Error
				if !errors.As(err, &appErr) || appErr.Code() != tt.wantErrCode {
					t.Fatalf("error = %v; want code %q", err, tt.wantErrCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyIDToken = %v", err)
			}
			if c.EmailVerified != tt.wantVerified {
				t.Errorf("EmailVerified = %v; want %v", c.EmailVerified, tt.wantVerified)
			}
			if c.UntrustedTenant != tt.wantUntrusted {
				t.Errorf("UntrustedTenant = %v; want %v", c.UntrustedTenant, tt.wantUntrusted)
			}
		})
	}
}

func TestMicrosoftProvider_SingleTenantVerification(t *testing.T) {
	privKey, nRaw, eRaw := generateTestRSAKey(t)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := strings.CutSuffix(r.URL.Path, "/v2.0/.well-known/openid-configuration"); ok {
			_ = json.NewEncoder(w).Encode(OIDCDiscovery{
				Issuer:                serverURL + "/" + contosoTenantGUID + "/v2.0",
				AuthorizationEndpoint: serverURL + "/authorize",
				TokenEndpoint:         serverURL + "/token",
				JWKSURI:               serverURL + "/keys",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(JWKDoc{Keys: []JWKKey{{
			Kty: "RSA", Use: "sig", Kid: "ms-key-1", Alg: "RS256", N: nRaw, E: eRaw,
		}}})
	}))
	defer server.Close()
	serverURL = server.URL

	newProvider := func(t *testing.T, tenant string) *MicrosoftProvider {
		t.Helper()
		p := NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:    "client-test-id",
			Tenant:      tenant,
			RedirectURI: "https://example.com/callback",
		})
		p.client = server.Client()
		p.discoveryBaseURL = server.URL
		p.jwksMgr = NewJWKSManager(server.URL, p.client, time.Hour)
		p.jwksRetriever = p.jwksMgr
		return p
	}

	tests := []struct {
		name         string
		tenantCfg    string
		issuerTenant string
		tid          string
		wantErr      bool
		wantVerified bool
	}{
		{name: "matching tid inherits verification", tenantCfg: "contoso-guid", issuerTenant: "contoso-guid", tid: "contoso-guid", wantVerified: true},
		{name: "matching tid is case insensitive", tenantCfg: "contoso-guid", issuerTenant: "contoso-guid", tid: "CONTOSO-GUID", wantVerified: true},
		{name: "domain tenant inherits verification by resolved guid", tenantCfg: "contoso.onmicrosoft.com", issuerTenant: contosoTenantGUID, tid: contosoTenantGUID, wantVerified: true},
		{name: "domain tenant foreign tid does not inherit verification", tenantCfg: "contoso.onmicrosoft.com", issuerTenant: contosoTenantGUID, tid: otherTenantGUID},
		{name: "foreign tid does not inherit verification", tenantCfg: "contoso-guid", issuerTenant: "contoso-guid", tid: "other-guid"},
		{name: "foreign issuer rejected", tenantCfg: "contoso-guid", issuerTenant: "other-guid", tid: "contoso-guid", wantErr: true},
		{name: "domain tenant foreign issuer rejected", tenantCfg: "contoso.onmicrosoft.com", issuerTenant: otherTenantGUID, tid: contosoTenantGUID, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := map[string]any{
				"iss":   "https://login.microsoftonline.com/" + tt.issuerTenant + "/v2.0",
				"sub":   "sub-1",
				"aud":   "client-test-id",
				"exp":   time.Now().Add(10 * time.Minute).Unix(),
				"email": "user@contoso.com",
				"tid":   tt.tid,
			}
			tok := signRS256JWT(t, privKey, "ms-key-1", claims)

			c, err := newProvider(t, tt.tenantCfg).VerifyIDToken(context.Background(), tok, "")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected issuer rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyIDToken = %v", err)
			}
			if c.EmailVerified != tt.wantVerified {
				t.Errorf("EmailVerified = %v; want %v", c.EmailVerified, tt.wantVerified)
			}
		})
	}
}

func TestMicrosoftProvider_UserInfoTenantGate(t *testing.T) {
	var userinfoClaims atomic.Value
	userinfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(userinfoClaims.Load())
	}))
	defer userinfo.Close()

	newProvider := func(t *testing.T, trusted []string) *MicrosoftProvider {
		t.Helper()
		p := NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:       "client-test-id",
			Tenant:         "common",
			TrustedTenants: trusted,
			RedirectURI:    "https://example.com/callback",
		})
		p.client = userinfo.Client()
		p.userinfoURL = userinfo.URL
		return p
	}

	tests := []struct {
		name        string
		trusted     []string
		claims      map[string]any
		wantUntrust bool
	}{
		{name: "no allowlist keeps userinfo untrusted-free", claims: map[string]any{"sub": "sub-1", "tid": "tenant-a"}},
		{name: "listed tenant", trusted: []string{"tenant-a"}, claims: map[string]any{"sub": "sub-1", "tid": "tenant-a"}},
		{name: "listed tenant uppercase", trusted: []string{"TENANT-A"}, claims: map[string]any{"sub": "sub-1", "tid": "tenant-a"}},
		{name: "unlisted tenant", trusted: []string{"tenant-a"}, claims: map[string]any{"sub": "sub-1", "tid": "tenant-b"}, wantUntrust: true},
		{name: "missing tid with allowlist fails closed", trusted: []string{"tenant-a"}, claims: map[string]any{"sub": "sub-1"}, wantUntrust: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userinfoClaims.Store(tt.claims)
			user, err := newProvider(t, tt.trusted).FetchUserInfo(context.Background(), &OAuthToken{AccessToken: "access-token"})
			if err != nil {
				t.Fatalf("FetchUserInfo = %v", err)
			}
			if user.EmailVerified {
				t.Error("userinfo alone must never verify the email")
			}
			untrusted, _ := user.RawClaims["untrusted_tenant"].(bool)
			if untrusted != tt.wantUntrust {
				t.Errorf("RawClaims[untrusted_tenant] = %v; want %v", user.RawClaims["untrusted_tenant"], tt.wantUntrust)
			}
		})
	}
}

func TestMicrosoftProvider_FetchUserInfoCarriesRawClaims(t *testing.T) {
	privKey, nRaw, eRaw := generateTestRSAKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(JWKDoc{Keys: []JWKKey{{
			Kty: "RSA", Use: "sig", Kid: "ms-key-1", Alg: "RS256", N: nRaw, E: eRaw,
		}}})
	}))
	defer server.Close()

	p := NewMicrosoftProvider(config.MicrosoftConfig{
		ClientID:       "client-test-id",
		Tenant:         "common",
		TrustedTenants: []string{"tenant-a"},
		RedirectURI:    "https://example.com/callback",
	})
	p.client = server.Client()
	p.jwksMgr = NewJWKSManager(server.URL, p.client, time.Hour)
	p.jwksRetriever = p.jwksMgr

	claims := map[string]any{
		"iss":   "https://login.microsoftonline.com/tenant-b/v2.0",
		"sub":   "sub-1",
		"oid":   "immutable-oid",
		"aud":   "client-test-id",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
		"email": "user@example.com",
		"tid":   "tenant-b",
	}
	tok := signRS256JWT(t, privKey, "ms-key-1", claims)

	user, err := p.FetchUserInfo(context.Background(), &OAuthToken{IDToken: tok})
	if err != nil {
		t.Fatalf("FetchUserInfo = %v", err)
	}
	if untrusted, _ := user.RawClaims["untrusted_tenant"].(bool); !untrusted {
		t.Fatal("identity claims dropped the untrusted_tenant marker")
	}
	if user.ProviderUserID != "immutable-oid" {
		t.Errorf("ProviderUserID = %q; want immutable-oid", user.ProviderUserID)
	}
	if got := user.RawClaims["oid"]; got != "immutable-oid" {
		t.Errorf("RawClaims[oid] = %v; want immutable-oid", got)
	}
	if got := user.RawClaims["tid"]; got != "tenant-b" {
		t.Errorf("RawClaims[tid] = %v; want tenant-b", got)
	}
}

func TestMicrosoftProvider_ProviderUserIDConsistency(t *testing.T) {
	privKey, nRaw, eRaw := generateTestRSAKey(t)

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(JWKDoc{Keys: []JWKKey{{
			Kty: "RSA", Use: "sig", Kid: "ms-key-1", Alg: "RS256", N: nRaw, E: eRaw,
		}}})
	}))
	defer jwks.Close()

	var userinfoClaims atomic.Value
	userinfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(userinfoClaims.Load())
	}))
	defer userinfo.Close()

	newProvider := func(t *testing.T) *MicrosoftProvider {
		t.Helper()
		p := NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:    "client-test-id",
			Tenant:      "common",
			RedirectURI: "https://example.com/callback",
		})
		p.client = jwks.Client()
		p.jwksMgr = NewJWKSManager(jwks.URL, p.client, time.Hour)
		p.jwksRetriever = p.jwksMgr
		p.userinfoURL = userinfo.URL
		return p
	}

	idToken := func(t *testing.T, extra map[string]any) string {
		t.Helper()
		claims := map[string]any{
			"iss": "https://login.microsoftonline.com/tid-1/v2.0",
			"aud": "client-test-id",
			"exp": time.Now().Add(10 * time.Minute).Unix(),
			"tid": "tid-1",
		}
		for k, v := range extra {
			claims[k] = v
		}
		return signRS256JWT(t, privKey, "ms-key-1", claims)
	}

	t.Run("id token", func(t *testing.T) {
		tests := []struct {
			name string
			oid  string
			sub  string
			want string
		}{
			{name: "oid preferred over sub", oid: "immutable-oid", sub: "app-sub", want: "immutable-oid"},
			{name: "sub fallback without oid", sub: "app-sub", want: "app-sub"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				claims := map[string]any{"sub": tt.sub}
				if tt.oid != "" {
					claims["oid"] = tt.oid
				}
				user, err := newProvider(t).FetchUserInfo(context.Background(), &OAuthToken{IDToken: idToken(t, claims)})
				if err != nil {
					t.Fatalf("FetchUserInfo = %v", err)
				}
				if user.ProviderUserID != tt.want {
					t.Errorf("ProviderUserID = %q; want %q", user.ProviderUserID, tt.want)
				}
			})
		}
	})

	t.Run("userinfo", func(t *testing.T) {
		tests := []struct {
			name   string
			claims map[string]any
			want   string
		}{
			{name: "oid preferred over sub", claims: map[string]any{"oid": "immutable-oid", "sub": "app-sub"}, want: "immutable-oid"},
			{name: "sub fallback without oid", claims: map[string]any{"sub": "app-sub"}, want: "app-sub"},
			{name: "oid without sub", claims: map[string]any{"oid": "immutable-oid"}, want: "immutable-oid"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				userinfoClaims.Store(tt.claims)
				user, err := newProvider(t).FetchUserInfo(context.Background(), &OAuthToken{AccessToken: "access-token"})
				if err != nil {
					t.Fatalf("FetchUserInfo = %v", err)
				}
				if user.ProviderUserID != tt.want {
					t.Errorf("ProviderUserID = %q; want %q", user.ProviderUserID, tt.want)
				}
			})
		}

		t.Run("rejects missing oid and sub", func(t *testing.T) {
			userinfoClaims.Store(map[string]any{"email": "user@example.com"})
			_, err := newProvider(t).FetchUserInfo(context.Background(), &OAuthToken{AccessToken: "access-token"})
			if err == nil {
				t.Fatal("expected rejection for userinfo without oid and sub")
			}
			var appErr *errors.Error
			if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthProviderError {
				t.Fatalf("expected CodeOAuthProviderError, got %v", err)
			}
		})
	})
}

func TestMicrosoftProvider_KeyIssuerBinding(t *testing.T) {
	const (
		tenantA = "tenant-a"
		tenantB = "tenant-b"
	)

	privKey, nRaw, eRaw := generateTestRSAKey(t)
	ctx := context.Background()

	serve := func(t *testing.T, keyIssuer string) *MicrosoftProvider {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(JWKDoc{Keys: []JWKKey{{
				Kty: "RSA", Use: "sig", Kid: "ms-key-1", Alg: "RS256", N: nRaw, E: eRaw, Issuer: keyIssuer,
			}}})
		}))
		t.Cleanup(srv.Close)

		p := NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:    "client-test-id",
			Tenant:      tenantA,
			RedirectURI: "https://example.com/callback",
		})
		p.client = srv.Client()
		p.jwksMgr = NewJWKSManager(srv.URL, p.client, time.Hour)
		p.jwksRetriever = p.jwksMgr
		return p
	}

	rawJWT := signRS256JWT(t, privKey, "ms-key-1", map[string]any{
		"iss": "https://login.microsoftonline.com/" + tenantA + "/v2.0",
		"tid": tenantA,
		"sub": "sub-1",
		"aud": "client-test-id",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	})

	t.Run("key scoped to a foreign tenant is rejected", func(t *testing.T) {
		p := serve(t, "https://login.microsoftonline.com/"+tenantB+"/v2.0")
		if _, err := p.VerifyIDToken(ctx, rawJWT, ""); err == nil {
			t.Fatal("token verified with a key scoped to another tenant")
		}
	})

	t.Run("templated key issuer resolves to the token tenant", func(t *testing.T) {
		p := serve(t, "https://login.microsoftonline.com/{tenantid}/v2.0")
		if _, err := p.VerifyIDToken(ctx, rawJWT, ""); err != nil {
			t.Fatalf("verification failed: %v", err)
		}
	})
}
