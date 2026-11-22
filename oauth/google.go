package oauth

import (
	"context"
	"net/http"
	"net/url"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// GoogleProvider implements Google OpenID Connect.
type GoogleProvider struct {
	cfg         config.ProviderConfig
	client      *http.Client
	authURL     string
	tokenURL    string
	userInfoURL string
}

// NewGoogleProvider builds a Google provider with production endpoints.
func NewGoogleProvider(cfg config.ProviderConfig) *GoogleProvider {
	return &GoogleProvider{
		cfg:         cfg,
		client:      newHTTPClient(),
		authURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		tokenURL:    "https://oauth2.googleapis.com/token",
		userInfoURL: "https://openidconnect.googleapis.com/v1/userinfo",
	}
}

// ID returns the canonical provider slug.
func (p *GoogleProvider) ID() string { return "google" }

// AuthURL builds the Google authorization URL with PKCE S256 parameters.
func (p *GoogleProvider) AuthURL(state, codeChallenge string) string {
	return p.AuthCodeURL(state, codeChallenge)
}

// AuthCodeURL builds the Google authorization URL with options.
func (p *GoogleProvider) AuthCodeURL(state, codeChallenge string, opts ...AuthCodeOption) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", scopesOrDefault(p.cfg.Scopes, "openid", "email", "profile"))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("access_type", "offline")
	q.Set("prompt", "select_account")
	for _, opt := range opts {
		if opt.Key != "" {
			q.Set(opt.Key, opt.Value)
		}
	}
	return p.authURL + "?" + q.Encode()
}

// ExchangeCode trades the authorization code plus PKCE verifier for tokens.
func (p *GoogleProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	form.Set("redirect_uri", p.cfg.RedirectURL)
	form.Set("grant_type", "authorization_code")
	form.Set("code_verifier", codeVerifier)
	return postTokenForm(ctx, p.client, p.tokenURL, form.Encode())
}

// FetchUserInfo normalizes the Google userinfo response; sub is mandatory.
func (p *GoogleProvider) FetchUserInfo(ctx context.Context, tokens *TokenResponse) (*UserInfo, error) {
	if tokens == nil || tokens.AccessToken == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth userinfo request failed", nil)
	}
	raw, err := getJSON(ctx, p.client, p.userInfoURL, tokens.AccessToken)
	if err != nil {
		return nil, err
	}
	sub, _ := raw["sub"].(string)
	if sub == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", nil)
	}
	email, _ := raw["email"].(string)
	verified, _ := raw["email_verified"].(bool)
	name, _ := raw["name"].(string)
	picture, _ := raw["picture"].(string)
	return &UserInfo{
		ProviderID:     "google",
		ProviderUserID: sub,
		Email:          email,
		EmailVerified:  verified,
		Name:           name,
		AvatarURL:      picture,
	}, nil
}
