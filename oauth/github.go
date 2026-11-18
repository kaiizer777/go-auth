package oauth

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// GitHubProvider implements GitHub OAuth with hidden-email fallback.
type GitHubProvider struct {
	cfg       config.ProviderConfig
	client    *http.Client
	authURL   string
	tokenURL  string
	userURL   string
	emailsURL string
}

// NewGitHubProvider builds a GitHub provider with production endpoints.
func NewGitHubProvider(cfg config.ProviderConfig) *GitHubProvider {
	return &GitHubProvider{
		cfg:       cfg,
		client:    newHTTPClient(),
		authURL:   "https://github.com/login/oauth/authorize",
		tokenURL:  "https://github.com/login/oauth/access_token",
		userURL:   "https://api.github.com/user",
		emailsURL: "https://api.github.com/user/emails",
	}
}

// ID returns the canonical provider slug.
func (p *GitHubProvider) ID() string { return "github" }

// AuthURL builds the GitHub authorization URL with PKCE S256 parameters.
func (p *GitHubProvider) AuthURL(state, codeChallenge string) string {
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", scopesOrDefault(p.cfg.Scopes, "read:user", "user:email"))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	return p.authURL + "?" + q.Encode()
}

// ExchangeCode trades the authorization code plus PKCE verifier for tokens.
func (p *GitHubProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURL)
	form.Set("code_verifier", codeVerifier)
	return postTokenForm(ctx, p.client, p.tokenURL, form.Encode())
}

// FetchUserInfo normalizes the GitHub profile, falling back to /user/emails
// when the public email is hidden. Only a primary AND verified address sets EmailVerified.
func (p *GitHubProvider) FetchUserInfo(ctx context.Context, tokens *TokenResponse) (*UserInfo, error) {
	if tokens == nil || tokens.AccessToken == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth userinfo request failed", nil)
	}
	user, err := getJSON(ctx, p.client, p.userURL, tokens.AccessToken)
	if err != nil {
		return nil, err
	}
	id, _ := user["id"].(float64)
	if id == 0 {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", nil)
	}
	login, _ := user["login"].(string)
	name, _ := user["name"].(string)
	if name == "" {
		name = login
	}
	avatar, _ := user["avatar_url"].(string)
	publicEmail, _ := user["email"].(string)

	emails, err := getJSONArray(ctx, p.client, p.emailsURL, tokens.AccessToken)
	if err != nil {
		return nil, err
	}
	email, verified := resolveGitHubEmail(publicEmail, emails)
	return &UserInfo{
		ProviderID:     "github",
		ProviderUserID: strconv.Itoa(int(id)),
		Email:          email,
		EmailVerified:  verified,
		Name:           name,
		AvatarURL:      avatar,
	}, nil
}

// resolveGitHubEmail prefers the primary verified address; a public email counts
// only when the emails list confirms it verified. Otherwise EmailVerified is false.
func resolveGitHubEmail(public string, emails []any) (string, bool) {
	verifiedByAddress := make(map[string]bool, len(emails))
	for _, e := range emails {
		entry, ok := e.(map[string]any)
		if !ok {
			continue
		}
		addr, _ := entry["email"].(string)
		primary, _ := entry["primary"].(bool)
		isVerified, _ := entry["verified"].(bool)
		if addr == "" {
			continue
		}
		if isVerified {
			verifiedByAddress[addr] = true
		}
		if primary && isVerified {
			return addr, true
		}
	}
	if public != "" && verifiedByAddress[public] {
		return public, true
	}
	return public, false
}
