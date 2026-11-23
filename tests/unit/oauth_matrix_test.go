package unit_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/oauth"
)

func TestOAuthMatrix_ConfigValidationAndSecretRedaction(t *testing.T) {
	t.Parallel()

	t.Run("microsoft config redaction", func(t *testing.T) {
		cfg := config.MicrosoftConfig{
			ClientID:     "ms-client-123",
			ClientSecret: "super-secret-ms-token-xyz",
			Tenant:       "common",
			RedirectURI:  "https://example.com/cb",
			Scopes:       []string{"openid", "email"},
		}
		str := fmt.Sprintf("%v", cfg)
		if strings.Contains(str, "super-secret-ms-token-xyz") {
			t.Fatalf("ClientSecret leaked in fmt.Sprintf: %s", str)
		}
		if !strings.Contains(str, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] in String(), got: %s", str)
		}

		val := cfg.LogValue()
		valStr := val.String()
		if strings.Contains(valStr, "super-secret-ms-token-xyz") {
			t.Fatalf("ClientSecret leaked in LogValue: %s", valStr)
		}
	})

	t.Run("x config redaction", func(t *testing.T) {
		cfg := config.XConfig{
			ClientID:     "x-client-id-abc",
			ClientSecret: "x-client-secret-def",
			RedirectURI:  "https://example.com/cb",
			Scopes:       []string{"tweet.read", "users.read"},
		}
		str := fmt.Sprintf("%v", cfg)
		if strings.Contains(str, "x-client-secret-def") {
			t.Fatalf("ClientSecret leaked in fmt.Sprintf: %s", str)
		}
		if !strings.Contains(str, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] in String(), got: %s", str)
		}
	})

	t.Run("facebook config redaction", func(t *testing.T) {
		cfg := config.FacebookConfig{
			AppID:        "fb-app-123",
			AppSecret:    "fb-app-secret-456",
			RedirectURI:  "https://example.com/cb",
			GraphVersion: "v19.0",
		}
		str := fmt.Sprintf("%v", cfg)
		if strings.Contains(str, "fb-app-secret-456") {
			t.Fatalf("AppSecret leaked in fmt.Sprintf: %s", str)
		}
		if !strings.Contains(str, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] in String(), got: %s", str)
		}
	})

	t.Run("discord config redaction", func(t *testing.T) {
		cfg := config.DiscordConfig{
			ClientID:     "discord-client-123",
			ClientSecret: "discord-secret-789",
			RedirectURI:  "https://example.com/cb",
		}
		str := fmt.Sprintf("%v", cfg)
		if strings.Contains(str, "discord-secret-789") {
			t.Fatalf("ClientSecret leaked in fmt.Sprintf: %s", str)
		}
		if !strings.Contains(str, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] in String(), got: %s", str)
		}
	})

	t.Run("oauth app config state secret redaction", func(t *testing.T) {
		appCfg := config.DefaultConfig()
		appCfg.OAuth.StateSecret = "confidential-state-hmac-secret-32b"
		val := appCfg.OAuth.LogValue()
		valStr := val.String()
		if strings.Contains(valStr, "confidential-state-hmac-secret-32b") {
			t.Fatalf("StateSecret leaked in LogValue: %s", valStr)
		}
		if !strings.Contains(valStr, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] for StateSecret in LogValue, got: %s", valStr)
		}
	})
}

func TestOAuthMatrix_PKCEAndStateEntropyAcross7Providers(t *testing.T) {
	t.Parallel()

	appCfg := config.DefaultConfig()
	appCfg.OAuth.StateSecret = "super-secret-signing-key-for-state-tests-32b"

	providers := []string{"google", "github", "apple", "microsoft", "facebook", "discord", "x"}

	for _, p := range providers {
		t.Run(p+"_pkce_and_state_generation", func(t *testing.T) {
			pkce, err := oauth.GeneratePKCE()
			if err != nil {
				t.Fatalf("GeneratePKCE failed: %v", err)
			}
			if len(pkce.Verifier) < 43 {
				t.Fatalf("code verifier entropy too short: len=%d", len(pkce.Verifier))
			}
			if len(pkce.Challenge) == 0 {
				t.Fatal("empty code challenge")
			}

			rec := httptest.NewRecorder()
			state, err := oauth.SetStateCookie(rec, &appCfg, p, pkce.Verifier, "/dashboard")
			if err != nil {
				t.Fatalf("SetStateCookie failed: %v", err)
			}
			if len(state) == 0 {
				t.Fatal("expected non-empty state")
			}

			cookies := rec.Result().Cookies()
			if len(cookies) == 0 {
				t.Fatal("expected state cookie to be set")
			}
			var cookie *http.Cookie
			for _, c := range cookies {
				if c.Name == appCfg.OAuth.StateCookieName {
					cookie = c
					break
				}
			}
			if cookie == nil {
				t.Fatalf("cookie %q not found", appCfg.OAuth.StateCookieName)
			}
			if !cookie.HttpOnly {
				t.Fatal("state cookie must be HttpOnly")
			}

			// Validate state
			req := httptest.NewRequest(http.MethodGet, "/auth/oauth/"+p+"/callback?state="+state, nil)
			req.AddCookie(cookie)
			valRec := httptest.NewRecorder()

			payload, err := oauth.ValidateState(valRec, req, &appCfg, p, state)
			if err != nil {
				t.Fatalf("ValidateState failed: %v", err)
			}
			if payload.ProviderID != p {
				t.Fatalf("provider ID mismatch: got %q, want %q", payload.ProviderID, p)
			}
			if payload.CodeVerifier != pkce.Verifier {
				t.Fatalf("code verifier mismatch: got %q, want %q", payload.CodeVerifier, pkce.Verifier)
			}
			if payload.RedirectURL != "/dashboard" {
				t.Fatalf("redirect url mismatch: got %q, want /dashboard", payload.RedirectURL)
			}
		})
	}
}

func TestOAuthMatrix_AuthURLParametersAcross7Providers(t *testing.T) {
	t.Parallel()

	commonCfg := config.ProviderConfig{
		ClientID:     "client-id-123",
		ClientSecret: "client-secret-456",
		RedirectURL:  "https://app.example.com/callback",
		Scopes:       []string{"scope1", "scope2"},
	}

	providers := []string{"google", "github", "apple", "microsoft", "facebook", "discord", "x"}

	for _, pID := range providers {
		t.Run(pID+"_auth_url_construction", func(t *testing.T) {
			p, err := oauth.NewProvider(pID, commonCfg)
			if err != nil {
				t.Fatalf("NewProvider(%q) failed: %v", pID, err)
			}
			if p.ID() != pID {
				t.Fatalf("provider.ID() = %q; want %q", p.ID(), pID)
			}

			pkce, err := oauth.GeneratePKCE()
			if err != nil {
				t.Fatalf("GeneratePKCE failed: %v", err)
			}

			authURL := p.AuthURL("state-test-nonce", pkce.Challenge)
			u, err := url.Parse(authURL)
			if err != nil {
				t.Fatalf("invalid auth URL %q: %v", authURL, err)
			}
			q := u.Query()

			if q.Get("state") != "state-test-nonce" {
				t.Fatalf("expected state=state-test-nonce, got %q", q.Get("state"))
			}

			// Invariant: PKCE code_challenge present
			if q.Get("code_challenge") != pkce.Challenge {
				t.Fatalf("expected code_challenge=%q, got %q", pkce.Challenge, q.Get("code_challenge"))
			}
			if q.Get("code_challenge_method") != "S256" {
				t.Fatalf("expected code_challenge_method=S256, got %q", q.Get("code_challenge_method"))
			}

			// Invariant: client_id matches
			if q.Get("client_id") != "client-id-123" {
				t.Fatalf("expected client_id=client-id-123, got %q", q.Get("client_id"))
			}

			// Invariant: redirect_uri matches
			if q.Get("redirect_uri") != "https://app.example.com/callback" {
				t.Fatalf("expected redirect_uri=https://app.example.com/callback, got %q", q.Get("redirect_uri"))
			}
		})
	}
}

func TestOAuthMatrix_DiscordAvatarURLFormatting(t *testing.T) {
	t.Parallel()

	// Animated avatar (a_ prefix) -> gif
	gifURL := oauth.FormatDiscordAvatarURL("12345", "a_animatedavatarhash", "0")
	if !strings.HasSuffix(gifURL, ".gif") {
		t.Fatalf("expected .gif extension for animated avatar, got %q", gifURL)
	}

	// Static avatar -> png
	pngURL := oauth.FormatDiscordAvatarURL("12345", "staticavatarhash", "0")
	if !strings.HasSuffix(pngURL, ".png") {
		t.Fatalf("expected .png extension for static avatar, got %q", pngURL)
	}

	// Empty avatar with discriminator
	discURL := oauth.FormatDiscordAvatarURL("12345", "", "1337")
	if !strings.Contains(discURL, "embed/avatars/") {
		t.Fatalf("expected default embed avatar for discriminator, got %q", discURL)
	}
}

func TestOAuthMatrix_FacebookAppSecretProof(t *testing.T) {
	t.Parallel()

	token := "fb-user-access-token-123"
	secret := "fb-app-secret-456"

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(token))
	expected := hex.EncodeToString(mac.Sum(nil))

	actual := oauth.GenerateAppSecretProof(token, secret)
	if actual != expected {
		t.Fatalf("GenerateAppSecretProof mismatch: got %q, want %q", actual, expected)
	}
}
