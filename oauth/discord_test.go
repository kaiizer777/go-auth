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

func TestDiscordProvider_AuthCodeURL(t *testing.T) {
	t.Parallel()

	cfg := config.DiscordConfig{
		ClientID:     "123456789012345678",
		ClientSecret: "discord-secret",
		RedirectURI:  "https://myapp.com/callback",
		Scopes:       []string{"identify", "email", "guilds"},
	}

	p := NewDiscordProvider(cfg)

	if p.ID() != "discord" {
		t.Fatalf("ID() = %q; want %q", p.ID(), "discord")
	}

	rawURL := p.AuthCodeURL("test-state-nonce", "test-code-challenge", AuthCodeOption{Key: "prompt", Value: "consent"})
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse AuthCodeURL: %v", err)
	}

	if parsed.Scheme != "https" || parsed.Host != "discord.com" || parsed.Path != "/oauth2/authorize" {
		t.Fatalf("unexpected endpoint: %s", parsed.String())
	}

	q := parsed.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q; want code", q.Get("response_type"))
	}
	if q.Get("client_id") != "123456789012345678" {
		t.Errorf("client_id = %q; want 123456789012345678", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://myapp.com/callback" {
		t.Errorf("redirect_uri = %q; want https://myapp.com/callback", q.Get("redirect_uri"))
	}
	if q.Get("scope") != "identify email guilds" {
		t.Errorf("scope = %q; want 'identify email guilds'", q.Get("scope"))
	}
	if q.Get("state") != "test-state-nonce" {
		t.Errorf("state = %q; want test-state-nonce", q.Get("state"))
	}
	if q.Get("code_challenge") != "test-code-challenge" {
		t.Errorf("code_challenge = %q; want test-code-challenge", q.Get("code_challenge"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q; want S256", q.Get("code_challenge_method"))
	}
	if q.Get("prompt") != "consent" {
		t.Errorf("prompt = %q; want consent", q.Get("prompt"))
	}

	// Test AuthURL convenience alias
	authURL := p.AuthURL("test-state", "test-challenge")
	if !strings.Contains(authURL, "state=test-state") || !strings.Contains(authURL, "code_challenge=test-challenge") {
		t.Fatalf("AuthURL missing state or challenge: %s", authURL)
	}
}

func TestDiscordProvider_ExchangeCode(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/x-www-form-urlencoded") {
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		if r.FormValue("client_id") != "test-client-id" || r.FormValue("client_secret") != "test-client-secret" {
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

		code := r.FormValue("code")
		if code == "bad-code" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		if code == "server-error" {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		if r.FormValue("code_verifier") != "test-code-verifier" {
			http.Error(w, "bad verifier", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "discord-access-token-123",
			"token_type":    "Bearer",
			"expires_in":    604800,
			"refresh_token": "discord-refresh-token-456",
			"scope":         "identify email",
		})
	}))
	t.Cleanup(ts.Close)

	cfg := config.DiscordConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "https://myapp.com/callback",
	}
	p := NewDiscordProvider(cfg)
	p.tokenURL = ts.URL

	t.Run("successful code exchange", func(t *testing.T) {
		tok, err := p.ExchangeCode(context.Background(), "good-code", "test-code-verifier")
		if err != nil {
			t.Fatalf("ExchangeCode failed: %v", err)
		}
		if tok.AccessToken != "discord-access-token-123" {
			t.Errorf("AccessToken = %q; want discord-access-token-123", tok.AccessToken)
		}
		if tok.TokenType != "Bearer" {
			t.Errorf("TokenType = %q; want Bearer", tok.TokenType)
		}
		if tok.ExpiresIn != 604800 {
			t.Errorf("ExpiresIn = %d; want 604800", tok.ExpiresIn)
		}
		if tok.RefreshToken != "discord-refresh-token-456" {
			t.Errorf("RefreshToken = %q; want discord-refresh-token-456", tok.RefreshToken)
		}
	})

	t.Run("rejected with invalid_grant", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "bad-code", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthProviderError {
			t.Fatalf("expected CodeOAuthProviderError, got: %v", err)
		}
	})

	t.Run("server error rejects exchange", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "server-error", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestDiscordProvider_FetchUserInfo(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")

		w.Header().Set("Content-Type", "application/json")
		switch token {
		case "token-global-name-verified":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":            "157733188964352000",
				"username":      "discord_user",
				"global_name":   "Cool Display Name",
				"discriminator": "0",
				"avatar":        "8342729096ea367544fb1b3dd0723b4f",
				"email":         "verified@discord.com",
				"verified":      true,
			})
		case "token-username-fallback-unverified":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":            "157733188964352000",
				"username":      "fallback_user",
				"global_name":   "",
				"discriminator": "0",
				"avatar":        "",
				"email":         "unverified@discord.com",
				"verified":      false,
			})
		case "token-verified-empty-email":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":            "157733188964352000",
				"username":      "no_email_user",
				"discriminator": "0",
				"email":         "",
				"verified":      true,
			})
		case "token-missing-id":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"username": "no_id_user",
			})
		case "token-animated-avatar":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":            "157733188964352000",
				"username":      "nitro_user",
				"discriminator": "0",
				"avatar":        "a_1234567890abcdef1234567890abcdef",
				"email":         "nitro@discord.com",
				"verified":      true,
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)

	p := NewDiscordProvider(config.DiscordConfig{
		ClientID:     "cid",
		ClientSecret: "csecret",
		RedirectURI:  "https://myapp.com/cb",
	})
	p.userInfoURL = ts.URL

	t.Run("global name with verified email and static avatar", func(t *testing.T) {
		tok := &OAuthToken{AccessToken: "token-global-name-verified"}
		user, err := p.FetchUserInfo(context.Background(), tok)
		if err != nil {
			t.Fatalf("FetchUserInfo failed: %v", err)
		}

		if user.ProviderID != "discord" {
			t.Errorf("ProviderID = %q; want discord", user.ProviderID)
		}
		if user.ProviderUserID != "157733188964352000" {
			t.Errorf("ProviderUserID = %q; want 157733188964352000", user.ProviderUserID)
		}
		if user.Name != "Cool Display Name" {
			t.Errorf("Name = %q; want 'Cool Display Name'", user.Name)
		}
		if user.Email != "verified@discord.com" {
			t.Errorf("Email = %q; want verified@discord.com", user.Email)
		}
		if !user.EmailVerified {
			t.Errorf("EmailVerified = false; want true")
		}
		expectedAvatar := "https://cdn.discordapp.com/avatars/157733188964352000/8342729096ea367544fb1b3dd0723b4f.png"
		if user.AvatarURL != expectedAvatar {
			t.Errorf("AvatarURL = %q; want %q", user.AvatarURL, expectedAvatar)
		}
	})

	t.Run("username fallback when global_name empty and unverified email", func(t *testing.T) {
		tok := &OAuthToken{AccessToken: "token-username-fallback-unverified"}
		user, err := p.FetchUserInfo(context.Background(), tok)
		if err != nil {
			t.Fatalf("FetchUserInfo failed: %v", err)
		}

		if user.Name != "fallback_user" {
			t.Errorf("Name = %q; want fallback_user", user.Name)
		}
		if user.EmailVerified {
			t.Errorf("EmailVerified = true; want false for unverified email")
		}
		// Migrated Pomelo default avatar: (157733188964352000 >> 22) % 6 = 2
		expectedAvatar := "https://cdn.discordapp.com/embed/avatars/2.png"
		if user.AvatarURL != expectedAvatar {
			t.Errorf("AvatarURL = %q; want %q", user.AvatarURL, expectedAvatar)
		}
	})

	t.Run("verified flag true but email empty results in EmailVerified false", func(t *testing.T) {
		tok := &OAuthToken{AccessToken: "token-verified-empty-email"}
		user, err := p.FetchUserInfo(context.Background(), tok)
		if err != nil {
			t.Fatalf("FetchUserInfo failed: %v", err)
		}

		if user.EmailVerified {
			t.Errorf("EmailVerified = true; want false when email is empty string")
		}
	})

	t.Run("animated gif avatar formatted correctly", func(t *testing.T) {
		tok := &OAuthToken{AccessToken: "token-animated-avatar"}
		user, err := p.FetchUserInfo(context.Background(), tok)
		if err != nil {
			t.Fatalf("FetchUserInfo failed: %v", err)
		}

		expectedAvatar := "https://cdn.discordapp.com/avatars/157733188964352000/a_1234567890abcdef1234567890abcdef.gif"
		if user.AvatarURL != expectedAvatar {
			t.Errorf("AvatarURL = %q; want %q", user.AvatarURL, expectedAvatar)
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
}

func TestFormatDiscordAvatarURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		userID        string
		avatarHash    string
		discriminator string
		want          string
	}{
		{
			name:          "animated gif avatar",
			userID:        "80351110224678912",
			avatarHash:    "a_1234567890abcdef",
			discriminator: "0",
			want:          "https://cdn.discordapp.com/avatars/80351110224678912/a_1234567890abcdef.gif",
		},
		{
			name:          "static png avatar",
			userID:        "80351110224678912",
			avatarHash:    "1234567890abcdef",
			discriminator: "1337",
			want:          "https://cdn.discordapp.com/avatars/80351110224678912/1234567890abcdef.png",
		},
		{
			name:          "migrated username discriminator 0 modulo 6 index 2",
			userID:        "157733188964352000",
			avatarHash:    "",
			discriminator: "0",
			want:          "https://cdn.discordapp.com/embed/avatars/2.png",
		},
		{
			name:          "migrated username discriminator empty modulo 6 index 2",
			userID:        "157733188964352000",
			avatarHash:    "",
			discriminator: "",
			want:          "https://cdn.discordapp.com/embed/avatars/2.png",
		},
		{
			name:          "migrated username discriminator 0 modulo 6 index 5",
			userID:        "80351110224678912", // 80351110224678912 >> 22 = 19157209703; 19157209703 % 6 = 5
			avatarHash:    "",
			discriminator: "0",
			want:          "https://cdn.discordapp.com/embed/avatars/5.png",
		},
		{
			name:          "legacy discriminator 1337 modulo 5 is 2",
			userID:        "80351110224678912",
			avatarHash:    "",
			discriminator: "1337",
			want:          "https://cdn.discordapp.com/embed/avatars/2.png",
		},
		{
			name:          "legacy discriminator 0001 modulo 5 is 1",
			userID:        "80351110224678912",
			avatarHash:    "",
			discriminator: "0001",
			want:          "https://cdn.discordapp.com/embed/avatars/1.png",
		},
		{
			name:          "invalid non-numeric user id falls back to 0.png",
			userID:        "not-a-number",
			avatarHash:    "",
			discriminator: "0",
			want:          "https://cdn.discordapp.com/embed/avatars/0.png",
		},
		{
			name:          "invalid non-numeric legacy discriminator falls back to 0.png",
			userID:        "80351110224678912",
			avatarHash:    "",
			discriminator: "invalid-disc",
			want:          "https://cdn.discordapp.com/embed/avatars/0.png",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatDiscordAvatarURL(tt.userID, tt.avatarHash, tt.discriminator)
			if got != tt.want {
				t.Errorf("FormatDiscordAvatarURL() = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestDiscordProvider_RegistryIntegration(t *testing.T) {
	t.Parallel()

	reg := NewRegistry()
	p := NewDiscordProvider(config.DiscordConfig{
		ClientID:     "cid",
		ClientSecret: "csec",
		RedirectURI:  "https://example.com/cb",
	})

	if err := reg.Register(p); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	retrieved, err := reg.Get("discord")
	if err != nil {
		t.Fatalf("Get('discord') failed: %v", err)
	}
	if retrieved.ID() != "discord" {
		t.Errorf("ID() = %q; want discord", retrieved.ID())
	}
}
