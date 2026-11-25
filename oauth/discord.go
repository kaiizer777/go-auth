package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// DiscordProvider implements OAuth 2.0 authentication for Discord API v10.
type DiscordProvider struct {
	cfg         config.DiscordConfig
	client      *http.Client
	authURL     string
	tokenURL    string
	userInfoURL string
}

var _ Provider = (*DiscordProvider)(nil)

// NewDiscordProvider constructs a new Discord OAuth provider adapter.
func NewDiscordProvider(cfg config.DiscordConfig, opts ...EndpointOption) *DiscordProvider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"identify", "email"}
	}

	ep := resolveEndpoints(EndpointOverride{
		AuthorizeURL: "https://discord.com/oauth2/authorize",
		TokenURL:     "https://discord.com/api/v10/oauth2/token",
		UserInfoURL:  "https://discord.com/api/v10/users/@me",
	}, opts)

	return &DiscordProvider{
		cfg:         cfg,
		client:      newHTTPClient(),
		authURL:     ep.AuthorizeURL,
		tokenURL:    ep.TokenURL,
		userInfoURL: ep.UserInfoURL,
	}
}

// ID returns the canonical provider slug.
func (p *DiscordProvider) ID() string {
	return "discord"
}

// AuthURL builds the Discord authorization URL with default options.
func (p *DiscordProvider) AuthURL(state, codeChallenge string) string {
	return p.AuthCodeURL(state, codeChallenge)
}

// AuthCodeURL constructs the authorization URL with PKCE challenge, state, and scopes.
func (p *DiscordProvider) AuthCodeURL(state, codeChallenge string, opts ...AuthCodeOption) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURI)
	q.Set("scope", scopesOrDefault(p.cfg.Scopes, "identify", "email"))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	applyAuthCodeOptions(q, opts)

	return p.authURL + "?" + q.Encode()
}

// ExchangeCode exchanges an authorization code and PKCE code verifier for an OAuthToken.
func (p *DiscordProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*OAuthToken, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURI)
	form.Set("code_verifier", codeVerifier)

	return postTokenForm(ctx, p.client, p.tokenURL, form.Encode())
}

// FetchUserInfo retrieves and normalizes the Discord user profile via /users/@me.
func (p *DiscordProvider) FetchUserInfo(ctx context.Context, tokens *OAuthToken) (*OAuthUser, error) {
	if tokens == nil || tokens.AccessToken == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "access token required", nil)
	}

	raw, err := getJSON(ctx, p.client, p.userInfoURL, tokens.AccessToken)
	if err != nil {
		return nil, err
	}

	id, _ := raw["id"].(string)
	if strings.TrimSpace(id) == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "discord user id missing", nil)
	}

	username, _ := raw["username"].(string)
	discriminator, _ := raw["discriminator"].(string)
	globalName, _ := raw["global_name"].(string)
	avatar, _ := raw["avatar"].(string)
	email, _ := raw["email"].(string)
	verified, _ := raw["verified"].(bool)

	name := globalName
	if strings.TrimSpace(name) == "" {
		name = username
	}

	avatarURL := FormatDiscordAvatarURL(id, avatar, discriminator)
	emailVerified := verified && strings.TrimSpace(email) != ""

	return &OAuthUser{
		ProviderID:     "discord",
		ProviderUserID: id,
		Email:          email,
		EmailVerified:  emailVerified,
		Name:           name,
		AvatarURL:      avatarURL,
		RawClaims:      raw,
	}, nil
}

// FormatDiscordAvatarURL builds the CDN avatar URL per Discord guidelines.
// Animated avatars (starting with "a_") produce .gif URLs, static avatars produce .png URLs,
// migrated Pomelo usernames (discriminator "0" or "") use (userID >> 22) % 6,
// and legacy discriminators use discNum % 5.
func FormatDiscordAvatarURL(userID, avatarHash, discriminator string) string {
	if avatarHash != "" {
		ext := "png"
		if strings.HasPrefix(avatarHash, "a_") {
			ext = "gif"
		}
		return fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.%s", userID, avatarHash, ext)
	}

	if discriminator == "0" || discriminator == "" {
		uid, err := strconv.ParseUint(userID, 10, 64)
		if err != nil {
			return "https://cdn.discordapp.com/embed/avatars/0.png"
		}
		index := (uid >> 22) % 6
		return fmt.Sprintf("https://cdn.discordapp.com/embed/avatars/%d.png", index)
	}

	discNum, err := strconv.Atoi(discriminator)
	if err != nil {
		return "https://cdn.discordapp.com/embed/avatars/0.png"
	}
	return fmt.Sprintf("https://cdn.discordapp.com/embed/avatars/%d.png", discNum%5)
}
