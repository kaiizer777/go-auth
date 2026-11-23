package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

func TestFacebookProvider_AuthCodeURL(t *testing.T) {
	t.Parallel()

	cfg := config.FacebookConfig{
		AppID:        "fb-app-123456",
		AppSecret:    "fb-app-secret",
		RedirectURI:  "https://myapp.com/fb/callback",
		Scopes:       []string{"email", "public_profile"},
		GraphVersion: "v19.0",
	}

	p := NewFacebookProvider(cfg)

	if p.ID() != "facebook" {
		t.Fatalf("ID() = %q; want facebook", p.ID())
	}

	rawURL := p.AuthCodeURL("fb-state-nonce", "fb-code-challenge", AuthCodeOption{Key: "auth_type", Value: "rerequest"})
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse AuthCodeURL: %v", err)
	}

	if parsed.Scheme != "https" || parsed.Host != "www.facebook.com" || parsed.Path != "/v19.0/dialog/oauth" {
		t.Fatalf("unexpected endpoint: %s", parsed.String())
	}

	q := parsed.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q; want code", q.Get("response_type"))
	}
	if q.Get("client_id") != "fb-app-123456" {
		t.Errorf("client_id = %q; want fb-app-123456", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://myapp.com/fb/callback" {
		t.Errorf("redirect_uri = %q; want https://myapp.com/fb/callback", q.Get("redirect_uri"))
	}
	if q.Get("scope") != "email public_profile" {
		t.Errorf("scope = %q; want 'email public_profile'", q.Get("scope"))
	}
	if q.Get("state") != "fb-state-nonce" {
		t.Errorf("state = %q; want fb-state-nonce", q.Get("state"))
	}
	if q.Get("code_challenge") != "fb-code-challenge" {
		t.Errorf("code_challenge = %q; want fb-code-challenge", q.Get("code_challenge"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q; want S256", q.Get("code_challenge_method"))
	}
	if q.Get("auth_type") != "rerequest" {
		t.Errorf("auth_type = %q; want rerequest", q.Get("auth_type"))
	}

	// Test custom GraphVersion in AuthURL
	cfgCustom := cfg
	cfgCustom.GraphVersion = "v20.0"
	pCustom := NewFacebookProvider(cfgCustom)
	authURLCustom := pCustom.AuthCodeURL("state", "challenge")
	if !strings.Contains(authURLCustom, "/v20.0/dialog/oauth") {
		t.Errorf("custom version not reflected in URL: %s", authURLCustom)
	}

	// Test AuthURL convenience alias
	authURL := p.AuthURL("state", "challenge")
	if !strings.Contains(authURL, "state=state") || !strings.Contains(authURL, "code_challenge=challenge") {
		t.Fatalf("AuthURL missing state or challenge: %s", authURL)
	}
}

func TestGenerateAppSecretProof(t *testing.T) {
	t.Parallel()

	// Verification with known test vectors:
	// key = "test-secret", data = "test-token"
	// HMAC-SHA256("test-secret", "test-token")
	// Expected lowercase hex:
	proof := GenerateAppSecretProof("test-token", "test-secret")
	if len(proof) != 64 {
		t.Fatalf("proof length = %d; want 64", len(proof))
	}
	if proof != strings.ToLower(proof) {
		t.Fatalf("proof contains uppercase hex: %s", proof)
	}

	// Verify idempotency and deterministic output
	proof2 := GenerateAppSecretProof("test-token", "test-secret")
	if proof != proof2 {
		t.Fatalf("non-deterministic proof calculation")
	}

	// Different token produces different proof
	proofDiff := GenerateAppSecretProof("diff-token", "test-secret")
	if proof == proofDiff {
		t.Fatalf("different tokens produced identical proof")
	}
}

func TestFacebookProvider_ExchangeCode_And_ConfusedDeputyDefense(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/access_token":
			if r.Method != http.MethodPost {
				http.Error(w, "bad method", http.StatusMethodNotAllowed)
				return
			}
			_ = r.ParseForm()
			if r.FormValue("client_id") != "fb-valid-app-id" || r.FormValue("client_secret") != "fb-valid-app-secret" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if r.FormValue("grant_type") != "authorization_code" {
				http.Error(w, "bad grant_type", http.StatusBadRequest)
				return
			}
			if r.FormValue("redirect_uri") != "https://myapp.com/callback" {
				http.Error(w, "bad redirect_uri", http.StatusBadRequest)
				return
			}
			if r.FormValue("code_verifier") != "verifier" {
				http.Error(w, "bad verifier", http.StatusBadRequest)
				return
			}

			code := r.FormValue("code")
			if code == "bad-code" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
				return
			}
			if code == "server-error" {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "token-for-" + code,
				"token_type":   "bearer",
				"expires_in":   5184000,
			})

		case "/debug_token":
			if r.Method != http.MethodGet {
				http.Error(w, "bad method", http.StatusMethodNotAllowed)
				return
			}
			q := r.URL.Query()
			inputToken := q.Get("input_token")
			accessToken := q.Get("access_token")
			proof := q.Get("appsecret_proof")

			if accessToken != "fb-valid-app-id|fb-valid-app-secret" {
				http.Error(w, "invalid app token", http.StatusUnauthorized)
				return
			}
			expectedProof := GenerateAppSecretProof(accessToken, "fb-valid-app-secret")
			if proof != expectedProof {
				http.Error(w, "invalid proof", http.StatusForbidden)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			switch inputToken {
			case "token-for-valid-code":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{
						"app_id":   "fb-valid-app-id",
						"is_valid": true,
						"user_id":  "12345678",
					},
				})
			case "token-for-confused-deputy":
				// Token was generated for an attacker's Facebook application!
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{
						"app_id":   "attacker-app-id",
						"is_valid": true,
						"user_id":  "victim-user-id",
					},
				})
			case "token-for-invalid-token":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{
						"app_id":   "fb-valid-app-id",
						"is_valid": false,
					},
				})
			case "token-for-debug-server-error":
				http.Error(w, "debug api outage", http.StatusBadGateway)
			default:
				http.Error(w, "unknown token", http.StatusBadRequest)
			}
		}
	}))
	t.Cleanup(ts.Close)

	cfg := config.FacebookConfig{
		AppID:        "fb-valid-app-id",
		AppSecret:    "fb-valid-app-secret",
		RedirectURI:  "https://myapp.com/callback",
		GraphVersion: "v19.0",
	}

	p := NewFacebookProvider(cfg)
	p.tokenURL = ts.URL + "/oauth/access_token"
	p.debugURL = ts.URL + "/debug_token"

	t.Run("successful code exchange and debug token validation", func(t *testing.T) {
		tok, err := p.ExchangeCode(context.Background(), "valid-code", "verifier")
		if err != nil {
			t.Fatalf("ExchangeCode failed: %v", err)
		}
		if tok.AccessToken != "token-for-valid-code" {
			t.Errorf("AccessToken = %q; want token-for-valid-code", tok.AccessToken)
		}
		if tok.ExpiresIn != 5184000 {
			t.Errorf("ExpiresIn = %d; want 5184000", tok.ExpiresIn)
		}
	})

	t.Run("confused deputy attack (app_id mismatch) rejected with 502", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "confused-deputy", "verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, errors.ErrOAuthTokenExchangeFailed) {
			t.Fatalf("expected ErrOAuthTokenExchangeFailed, got: %v", err)
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.HTTPStatus() != http.StatusBadGateway {
			t.Fatalf("expected 502 Bad Gateway status, got: %v", err)
		}
	})

	t.Run("invalid token (is_valid == false) rejected with 502", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "invalid-token", "verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, errors.ErrOAuthTokenExchangeFailed) {
			t.Fatalf("expected ErrOAuthTokenExchangeFailed, got: %v", err)
		}
	})

	t.Run("debug endpoint network or server error fails closed with 502", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "debug-server-error", "verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, errors.ErrOAuthTokenExchangeFailed) {
			t.Fatalf("expected ErrOAuthTokenExchangeFailed, got: %v", err)
		}
	})

	t.Run("token endpoint rejection returns error", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "bad-code", "verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestFacebookProvider_FetchUserInfo(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		if q.Get("access_token") != "" || q.Get("appsecret_proof") != "" {
			http.Error(w, "credentials must not appear in URL query", http.StatusBadRequest)
			return
		}
		var accessToken string
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			accessToken = strings.TrimPrefix(auth, "Bearer ")
		}
		proof := r.Header.Get("X-AppSecret-Proof")
		fields := q.Get("fields")

		if !strings.Contains(fields, "id") || !strings.Contains(fields, "email") || !strings.Contains(fields, "picture") {
			http.Error(w, "missing required fields in query", http.StatusBadRequest)
			return
		}

		expectedProof := GenerateAppSecretProof(accessToken, "fb-test-secret")
		if proof != expectedProof {
			http.Error(w, "invalid appsecret_proof", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch accessToken {
		case "token-full-profile":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":    "1000987654321",
				"name":  "Alice Test",
				"email": "alice@fb-test.com",
				"picture": map[string]any{
					"data": map[string]any{
						"url":           "https://platform-lookaside.fbsbx.com/profile.jpg",
						"width":         200,
						"height":        200,
						"is_silhouette": false,
					},
				},
			})
		case "token-omitted-email":
			// Meta omits email field when unverified or phone registered
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":   "1000987654322",
				"name": "Bob PhoneOnly",
			})
		case "token-whitespace-email":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":    "1000987654323",
				"name":  "Charlie Whitespace",
				"email": "   ",
			})
		case "token-missing-id":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":  "No ID User",
				"email": "noid@fb-test.com",
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)

	p := NewFacebookProvider(config.FacebookConfig{
		AppID:        "fb-test-app",
		AppSecret:    "fb-test-secret",
		RedirectURI:  "https://myapp.com/callback",
		GraphVersion: "v19.0",
	})
	p.userInfoURL = ts.URL

	t.Run("full profile email stays unverified", func(t *testing.T) {
		tok := &OAuthToken{AccessToken: "token-full-profile"}
		user, err := p.FetchUserInfo(context.Background(), tok)
		if err != nil {
			t.Fatalf("FetchUserInfo failed: %v", err)
		}

		if user.ProviderID != "facebook" {
			t.Errorf("ProviderID = %q; want facebook", user.ProviderID)
		}
		if user.ProviderUserID != "1000987654321" {
			t.Errorf("ProviderUserID = %q; want 1000987654321", user.ProviderUserID)
		}
		if user.Name != "Alice Test" {
			t.Errorf("Name = %q; want 'Alice Test'", user.Name)
		}
		if user.Email != "alice@fb-test.com" {
			t.Errorf("Email = %q; want alice@fb-test.com", user.Email)
		}
		// Graph exposes no per-address verification signal: a present
		// address must never imply verified.
		if user.EmailVerified {
			t.Errorf("EmailVerified = true; want false for facebook email")
		}
		expectedAvatar := "https://platform-lookaside.fbsbx.com/profile.jpg"
		if user.AvatarURL != expectedAvatar {
			t.Errorf("AvatarURL = %q; want %q", user.AvatarURL, expectedAvatar)
		}
	})

	t.Run("omitted email field produces EmailVerified false", func(t *testing.T) {
		tok := &OAuthToken{AccessToken: "token-omitted-email"}
		user, err := p.FetchUserInfo(context.Background(), tok)
		if err != nil {
			t.Fatalf("FetchUserInfo failed: %v", err)
		}

		if user.Email != "" {
			t.Errorf("Email = %q; want empty string", user.Email)
		}
		if user.EmailVerified {
			t.Errorf("EmailVerified = true; want false when email omitted")
		}
		if user.AvatarURL != "" {
			t.Errorf("AvatarURL = %q; want empty string when picture omitted", user.AvatarURL)
		}
	})

	t.Run("whitespace email produces EmailVerified false", func(t *testing.T) {
		tok := &OAuthToken{AccessToken: "token-whitespace-email"}
		user, err := p.FetchUserInfo(context.Background(), tok)
		if err != nil {
			t.Fatalf("FetchUserInfo failed: %v", err)
		}

		if user.EmailVerified {
			t.Errorf("EmailVerified = true; want false for whitespace email")
		}
		if user.Email != "" {
			t.Errorf("Email = %q; want empty string", user.Email)
		}
	})

	t.Run("missing user id returns error", func(t *testing.T) {
		tok := &OAuthToken{AccessToken: "token-missing-id"}
		_, err := p.FetchUserInfo(context.Background(), tok)
		if err == nil {
			t.Fatal("expected error for missing id, got nil")
		}
	})

	t.Run("empty access token returns error", func(t *testing.T) {
		_, err := p.FetchUserInfo(context.Background(), &OAuthToken{AccessToken: ""})
		if err == nil {
			t.Fatal("expected error for empty access token, got nil")
		}
		_, err = p.FetchUserInfo(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil token, got nil")
		}
	})

	t.Run("transport failure error carries no credentials", func(t *testing.T) {
		dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		deadURL := dead.URL
		dead.Close()
		pDead := NewFacebookProvider(config.FacebookConfig{
			AppID:        "fb-test-app",
			AppSecret:    "fb-test-secret",
			RedirectURI:  "https://myapp.com/callback",
			GraphVersion: "v19.0",
		})
		pDead.userInfoURL = deadURL
		const token = "leak-check-token-abc123"
		_, err := pDead.FetchUserInfo(context.Background(), &OAuthToken{AccessToken: token})
		if err == nil {
			t.Fatal("expected transport error, got nil")
		}
		msg := err.Error()
		if strings.Contains(msg, token) {
			t.Errorf("error exposes access token: %q", msg)
		}
		if proof := GenerateAppSecretProof(token, "fb-test-secret"); strings.Contains(msg, proof) {
			t.Errorf("error exposes appsecret_proof: %q", msg)
		}
	})
}

func TestFacebookProvider_RegistryIntegration(t *testing.T) {
	t.Parallel()

	reg := NewRegistry()
	p := NewFacebookProvider(config.FacebookConfig{
		AppID:        "fb-app",
		AppSecret:    "fb-sec",
		RedirectURI:  "https://example.com/fb/cb",
		GraphVersion: "v19.0",
	})

	if err := reg.Register(p); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	retrieved, err := reg.Get("facebook")
	if err != nil {
		t.Fatalf("Get('facebook') failed: %v", err)
	}
	if retrieved.ID() != "facebook" {
		t.Errorf("ID() = %q; want facebook", retrieved.ID())
	}
}
