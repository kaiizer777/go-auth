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
		if key.N.Cmp(privKey.N) != 0 {
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
		if sigKey.N.Cmp(privKey.N) != 0 {
			t.Fatalf("modulus mismatch")
		}
		_ = privKeyEnc
	})
}

func TestJWKSManager_UnknownKidSingleFetch(t *testing.T) {
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
	if got := jwksRequests.Load(); got != 1 {
		t.Fatalf("sequential unknown-kid lookups cost %d fetches, want 1", got)
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

	if _, err := mgr.GetKey(ctx, "unknown-a"); err == nil {
		t.Fatal("expected not-found for unknown-a, got nil")
	}
	if got := jwksRequests.Load(); got != 1 {
		t.Fatalf("first miss cost %d fetches, want 1", got)
	}
	// Genuine rotation: key-2 appears after unknown-a miss; lookup must fetch,
	// not fail closed on unknown-a's cooldown.
	rotated.Store(true)
	if _, err := mgr.GetKey(ctx, "key-2"); err != nil {
		t.Fatalf("rotation pickup failed: %v (fetches=%d)", err, jwksRequests.Load())
	}
	if got := jwksRequests.Load(); got != 2 {
		t.Fatalf("rotation lookup cost %d fetches, want 2", got)
	}
	// A different unknown kid must also fetch, not ride unknown-a's cooldown.
	if _, err := mgr.GetKey(ctx, "unknown-b"); err == nil {
		t.Fatal("expected not-found for unknown-b, got nil")
	}
	if got := jwksRequests.Load(); got != 3 {
		t.Fatalf("different unknown kid cost %d fetches, want 3", got)
	}
	// Same-kid negative cache still holds.
	if _, err := mgr.GetKey(ctx, "unknown-b"); err == nil {
		t.Fatal("expected not-found for unknown-b repeat, got nil")
	}
	if got := jwksRequests.Load(); got != 3 {
		t.Fatalf("repeat unknown-b cost %d fetches, want 3", got)
	}
	if _, err := mgr.GetKey(ctx, "unknown-a"); err == nil {
		t.Fatal("expected not-found for unknown-a repeat, got nil")
	}
	if got := jwksRequests.Load(); got != 3 {
		t.Fatalf("repeat unknown-a cost %d fetches, want 3", got)
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
		cUntrusted, err := pCommon.VerifyIDToken(ctx, tokUntrusted, "")
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
		cAttested, err := pCommon.VerifyIDToken(ctx, tokAttested, "")
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
		cBool, err := pCommon.VerifyIDToken(ctx, tokBool, "")
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
		cNum, err := pCommon.VerifyIDToken(ctx, tokNum, "")
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
		cFalse, err := pCommon.VerifyIDToken(ctx, tokFalse, "")
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

	t.Run("FetchUserInfo maps OID and PreferredUsername", func(t *testing.T) {
		p := newTestProvider("common", nil)
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
		idTok := signRS256JWT(t, privKey, "ms-key-1", claims)

		user, err := p.FetchUserInfo(ctx, &OAuthToken{IDToken: idTok})
		if err != nil {
			t.Fatalf("FetchUserInfo failed: %v", err)
		}
		if user.ProviderUserID != "immutable-oid-guid" {
			t.Errorf("ProviderUserID = %q, want immutable-oid-guid", user.ProviderUserID)
		}
		if user.Email != "fallback.user@example.com" {
			t.Errorf("Email = %q, want fallback.user@example.com", user.Email)
		}
		if user.Name != "Fallback User" {
			t.Errorf("Name = %q, want Fallback User", user.Name)
		}
		if user.EmailVerified {
			t.Errorf("preferred_username fallback must leave EmailVerified == false")
		}
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
