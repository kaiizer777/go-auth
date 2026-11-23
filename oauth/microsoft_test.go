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

		// 2. Untrusted tenant with xms_edov == '1' under a configured allowlist ->
		// attestation does not override the allowlist, EmailVerified must be FALSE
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
		if cAttested.EmailVerified {
			t.Errorf("allowlist bypass: attestation must not verify an unlisted tenant")
		}
		if !cAttested.UntrustedTenant {
			t.Errorf("expected untrusted_tenant marker on the rejected attestation path")
		}

		// 3. Trusted tenant whitelist match -> EmailVerified must be TRUE
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
		if !cTrusted.EmailVerified {
			t.Errorf("expected EmailVerified == true for whitelisted trusted tenant")
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

		t.Run("preferred_username never becomes the email", func(t *testing.T) {
			user, err := p.FetchUserInfo(ctx, &OAuthToken{IDToken: newToken(t, nil)})
			if err != nil {
				t.Fatalf("FetchUserInfo failed: %v", err)
			}
			if user.ProviderUserID != "immutable-oid-guid" {
				t.Errorf("ProviderUserID = %q, want immutable-oid-guid", user.ProviderUserID)
			}
			if user.Email != "" {
				t.Errorf("Email = %q, want empty without an email claim", user.Email)
			}
			if user.EmailVerified {
				t.Error("EmailVerified = true for a profile without an email claim")
			}
			if got := user.RawClaims["preferred_username"]; got != "fallback.user@example.com" {
				t.Errorf("RawClaims[preferred_username] = %v, want fallback.user@example.com", got)
			}
			if err := validateProviderIdentity(user); !errors.Is(err, errors.ErrOAuthEmailRequired) {
				t.Errorf("validateProviderIdentity = %v, want ErrOAuthEmailRequired", err)
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
		{name: "allowlist listed tenant unattested", trusted: allowlist, tenant: listedTenant, wantVerified: true},
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
