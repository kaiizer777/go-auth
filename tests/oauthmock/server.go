package oauthmock

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kaiizer777/go-auth/config"
)

// MockOAuthServers bundles loopback test servers simulating Microsoft, X, Facebook, and Discord IDPs.
type MockOAuthServers struct {
	MicrosoftServer *httptest.Server
	XServer         *httptest.Server
	FacebookServer  *httptest.Server
	DiscordServer   *httptest.Server

	// Microsoft settings
	MSPrivKey       *rsa.PrivateKey
	MSKeyID         string
	MSModulus       string
	MSExponent      string
	MSRolloverPriv  *rsa.PrivateKey
	MSRolloverKeyID string
	MSRolloverMod   string
	MSRolloverExp   string
	MSRolloverActive atomic.Bool
	MSJWKSRequests   atomic.Int32
	MSTenantID       string
	MSEmail          string
	MSName           string
	MSEmailVerified  bool
	MSEDov           string // "1" if domain verified, "" otherwise
	MSCustomClaims   map[string]any

	// X settings
	XClientID       string
	XClientSecret   string
	XRateLimited    atomic.Bool
	XRateLimitReset int64
	XRetryAfter     int
	XUserID         string
	XUsername       string
	XProfileImage   string
	XTokenRequests  atomic.Int32

	// Facebook settings
	FBAppID         string
	FBAppSecret     string
	FBUserID        string
	FBEmail         string
	FBName          string
	FBInvalidProof  atomic.Bool
	FBTokenValid    atomic.Bool
	FBWrongAppID    atomic.Bool

	// Discord settings
	DiscordClientID string
	DiscordSecret   string
	DiscordUserID   string
	DiscordUsername string
	DiscordEmail    string
	DiscordVerified bool
	DiscordAvatar   string

	mu sync.Mutex
}

// NewMockServers initializes loopback servers for Microsoft, X, Facebook, and Discord with secure test defaults.
func NewMockServers() (*MockOAuthServers, error) {
	msPriv, msMod, msExp, err := GenerateRSAKey()
	if err != nil {
		return nil, fmt.Errorf("generate ms key: %w", err)
	}
	rollPriv, rollMod, rollExp, err := GenerateRSAKey()
	if err != nil {
		return nil, fmt.Errorf("generate ms rollover key: %w", err)
	}

	m := &MockOAuthServers{
		MSPrivKey:       msPriv,
		MSKeyID:         "ms-test-key-1",
		MSModulus:       msMod,
		MSExponent:      msExp,
		MSRolloverPriv:  rollPriv,
		MSRolloverKeyID: "ms-rollover-key-2",
		MSRolloverMod:   rollMod,
		MSRolloverExp:   rollExp,
		MSTenantID:       "9188040d-6c67-4c5b-b112-36a304b66dad", // Default consumer tenant
		MSEmail:          "test-ms-user@example.com",
		MSName:           "Microsoft Test User",
		MSEmailVerified:  true,
		MSEDov:           "1",

		XClientID:       "mock-x-client-id",
		XClientSecret:   "mock-x-client-secret",
		XUserID:         "x-123456789",
		XUsername:       "x_test_user",
		XProfileImage:   "https://abs.twimg.com/mock_normal.jpg",

		FBAppID:         "mock-fb-app-id-123",
		FBAppSecret:     "mock-fb-app-secret-456",
		FBUserID:        "fb-user-987654",
		FBEmail:         "fb-user@example.com",
		FBName:          "Facebook Test User",

		DiscordClientID: "mock-discord-client-id",
		DiscordSecret:   "mock-discord-secret",
		DiscordUserID:   "803511102246789120",
		DiscordUsername: "discord_user",
		DiscordEmail:    "discord-user@example.com",
		DiscordVerified: true,
		DiscordAvatar:   "a_mock_avatar_hash_123",
	}
	m.FBTokenValid.Store(true)

	// Microsoft loopback server
	m.MicrosoftServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 m.MicrosoftServer.URL + "/v2.0",
				"authorization_endpoint": m.MicrosoftServer.URL + "/authorize",
				"token_endpoint":         m.MicrosoftServer.URL + "/token",
				"jwks_uri":               m.MicrosoftServer.URL + "/keys",
				"userinfo_endpoint":      m.MicrosoftServer.URL + "/userinfo",
			})
		case "/keys":
			m.MSJWKSRequests.Add(1)
			keys := []map[string]any{
				BuildJWK(m.MSKeyID, m.MSModulus, m.MSExponent),
			}
			if m.MSRolloverActive.Load() {
				keys = append(keys, BuildJWK(m.MSRolloverKeyID, m.MSRolloverMod, m.MSRolloverExp))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		case "/token":
			m.mu.Lock()
			claims := map[string]any{
				"iss":                fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", m.MSTenantID),
				"aud":                r.FormValue("client_id"),
				"sub":                "ms-sub-" + m.MSKeyID,
				"oid":                "ms-oid-778899",
				"tid":                m.MSTenantID,
				"email":              m.MSEmail,
				"preferred_username": m.MSEmail,
				"name":               m.MSName,
				"exp":                time.Now().Add(1 * time.Hour).Unix(),
				"iat":                time.Now().Unix(),
			}
			if m.MSEDov != "" {
				claims["xms_edov"] = m.MSEDov
			}
			for k, v := range m.MSCustomClaims {
				claims[k] = v
			}
			priv := m.MSPrivKey
			kid := m.MSKeyID
			if m.MSRolloverActive.Load() {
				priv = m.MSRolloverPriv
				kid = m.MSRolloverKeyID
			}
			m.mu.Unlock()

			idToken, err := SignRS256JWT(priv, kid, claims)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token_type":    "Bearer",
				"access_token":  "ms-access-token-xyz",
				"id_token":      idToken,
				"expires_in":    3600,
				"refresh_token": "ms-refresh-token-xyz",
			})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":   "ms-oid-778899",
				"email": m.MSEmail,
				"name":  m.MSName,
			})
		default:
			http.NotFound(w, r)
		}
	}))

	// X (Twitter) loopback server
	m.XServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.XRateLimited.Load() {
			w.Header().Set("Content-Type", "application/json")
			if m.XRetryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(m.XRetryAfter))
			}
			if m.XRateLimitReset > 0 {
				w.Header().Set("x-rate-limit-reset", strconv.FormatInt(m.XRateLimitReset, 10))
			}
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"title":  "Too Many Requests",
				"detail": "Too Many Requests",
				"type":   "about:blank",
				"status": 429,
			})
			return
		}

		switch r.URL.Path {
		case "/2/oauth2/token":
			m.XTokenRequests.Add(1)
			_ = r.ParseForm()

			// RFC 6749 §2.3.1 Client Authentication via Basic Auth check
			authHeader := r.Header.Get("Authorization")
			expectedBasic := "Basic " + base64.StdEncoding.EncodeToString(
				[]byte(url.QueryEscape(m.XClientID) + ":" + url.QueryEscape(m.XClientSecret)),
			)
			if authHeader != expectedBasic {
				http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
				return
			}

			// Invariant: client_id MUST NOT be present in body
			if r.PostForm.Get("client_id") != "" {
				http.Error(w, `{"error":"invalid_request","detail":"client_id in body forbidden when using basic auth"}`, http.StatusBadRequest)
				return
			}
			if r.PostForm.Get("code_verifier") == "" {
				http.Error(w, `{"error":"invalid_request","detail":"code_verifier required"}`, http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token_type":    "bearer",
				"access_token":  "x-mock-access-token-12345",
				"expires_in":    7200,
				"scope":         "tweet.read users.read offline.access",
				"refresh_token": "x-mock-refresh-token",
			})
		case "/2/users/me":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":                m.XUserID,
					"name":              m.XUsername,
					"username":          m.XUsername,
					"profile_image_url": m.XProfileImage,
					"verified":          true,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))

	// Facebook loopback server
	m.FacebookServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v19.0/oauth/access_token", "/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fb-mock-access-token-123",
				"token_type":   "bearer",
				"expires_in":   5184000,
			})
		case "/debug_token":
			appID := m.FBAppID
			if m.FBWrongAppID.Load() {
				appID = "confused-deputy-app-999"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"app_id":     appID,
					"type":       "USER",
					"is_valid":   m.FBTokenValid.Load(),
					"user_id":    m.FBUserID,
					"expires_at": time.Now().Add(60 * 24 * time.Hour).Unix(),
				},
			})
		case "/v19.0/me", "/me":
			token := r.URL.Query().Get("access_token")
			proof := r.URL.Query().Get("appsecret_proof")
			expectedMac := hmac.New(sha256.New, []byte(m.FBAppSecret))
			expectedMac.Write([]byte(token))
			expectedProof := hex.EncodeToString(expectedMac.Sum(nil))

			if m.FBInvalidProof.Load() || proof != expectedProof {
				w.WriteHeader(http.StatusBadRequest)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{
						"message": "Invalid appsecret_proof provided in the API argument",
						"type":    "OAuthException",
						"code":    100,
					},
				})
				return
			}

			resp := map[string]any{
				"id":   m.FBUserID,
				"name": m.FBName,
				"picture": map[string]any{
					"data": map[string]any{
						"url": "https://graph.facebook.com/picture.jpg",
					},
				},
			}
			if m.FBEmail != "" {
				resp["email"] = m.FBEmail
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))

	// Discord loopback server
	m.DiscordServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v10/oauth2/token":
			_ = r.ParseForm()
			if r.PostForm.Get("grant_type") != "authorization_code" {
				http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "discord-mock-access-token",
				"token_type":    "Bearer",
				"expires_in":    604800,
				"refresh_token": "discord-mock-refresh",
				"scope":         "identify email",
			})
		case "/api/v10/users/@me":
			resp := map[string]any{
				"id":            m.DiscordUserID,
				"username":      m.DiscordUsername,
				"discriminator": "0",
				"verified":      m.DiscordVerified,
				"avatar":        m.DiscordAvatar,
			}
			if m.DiscordEmail != "" {
				resp["email"] = m.DiscordEmail
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))

	return m, nil
}

// Close shuts down all mock loopback servers.
func (m *MockOAuthServers) Close() {
	if m.MicrosoftServer != nil {
		m.MicrosoftServer.Close()
	}
	if m.XServer != nil {
		m.XServer.Close()
	}
	if m.FacebookServer != nil {
		m.FacebookServer.Close()
	}
	if m.DiscordServer != nil {
		m.DiscordServer.Close()
	}
}

// MicrosoftConfig returns valid provider configuration pointing to the mock server.
func (m *MockOAuthServers) MicrosoftConfig() config.MicrosoftConfig {
	return config.MicrosoftConfig{
		ClientID:     "ms-mock-client-id",
		ClientSecret: "ms-mock-client-secret",
		Tenant:       m.MSTenantID,
		RedirectURI:  "https://app.example.com/callback/microsoft",
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
	}
}

// XConfig returns valid provider configuration pointing to the mock server.
func (m *MockOAuthServers) XConfig() config.XConfig {
	return config.XConfig{
		ClientID:     m.XClientID,
		ClientSecret: m.XClientSecret,
		RedirectURI:  "https://app.example.com/callback/x",
		Scopes:       []string{"tweet.read", "users.read", "offline.access"},
	}
}

// FacebookConfig returns valid provider configuration pointing to the mock server.
func (m *MockOAuthServers) FacebookConfig() config.FacebookConfig {
	return config.FacebookConfig{
		AppID:        m.FBAppID,
		AppSecret:    m.FBAppSecret,
		RedirectURI:  "https://app.example.com/callback/facebook",
		Scopes:       []string{"email", "public_profile"},
		GraphVersion: "v19.0",
	}
}

// DiscordConfig returns valid provider configuration pointing to the mock server.
func (m *MockOAuthServers) DiscordConfig() config.DiscordConfig {
	return config.DiscordConfig{
		ClientID:     m.DiscordClientID,
		ClientSecret: m.DiscordSecret,
		RedirectURI:  "https://app.example.com/callback/discord",
		Scopes:       []string{"identify", "email"},
	}
}
