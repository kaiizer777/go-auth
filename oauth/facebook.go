package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// FacebookProvider implements OAuth 2.0 authentication for Meta Facebook Graph API v19.0+.
type FacebookProvider struct {
	cfg         config.FacebookConfig
	client      *http.Client
	authURL     string
	tokenURL    string
	debugURL    string
	userInfoURL string
}

var _ Provider = (*FacebookProvider)(nil)

// NewFacebookProvider constructs a new Facebook Graph API provider adapter.
func NewFacebookProvider(cfg config.FacebookConfig) *FacebookProvider {
	version := cfg.GraphVersion
	if version == "" {
		version = "v19.0"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"email", "public_profile"}
	}

	return &FacebookProvider{
		cfg:         cfg,
		client:      newHTTPClient(),
		authURL:     fmt.Sprintf("https://www.facebook.com/%s/dialog/oauth", version),
		tokenURL:    fmt.Sprintf("https://graph.facebook.com/%s/oauth/access_token", version),
		debugURL:    "https://graph.facebook.com/debug_token",
		userInfoURL: fmt.Sprintf("https://graph.facebook.com/%s/me", version),
	}
}

// ID returns the canonical provider slug.
func (p *FacebookProvider) ID() string {
	return "facebook"
}

// AuthURL builds the Facebook authorization URL with default options.
func (p *FacebookProvider) AuthURL(state, codeChallenge string) string {
	return p.AuthCodeURL(state, codeChallenge)
}

// AuthCodeURL constructs the authorization URL with PKCE challenge, state, and scopes.
func (p *FacebookProvider) AuthCodeURL(state, codeChallenge string, opts ...AuthCodeOption) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.AppID)
	q.Set("redirect_uri", p.cfg.RedirectURI)
	q.Set("scope", scopesOrDefault(p.cfg.Scopes, "email", "public_profile"))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	applyAuthCodeOptions(q, opts)

	return p.authURL + "?" + q.Encode()
}

// GenerateAppSecretProof computes the hex-encoded HMAC-SHA256 of the access token using the app secret.
func GenerateAppSecretProof(accessToken, appSecret string) string {
	mac := hmac.New(sha256.New, []byte(appSecret))
	mac.Write([]byte(accessToken))
	return hex.EncodeToString(mac.Sum(nil))
}

// debugToken queries Facebook /debug_token to defend against Confused Deputy token substitution attacks.
func (p *FacebookProvider) debugToken(ctx context.Context, userToken string) error {
	ctx, cancel := context.WithTimeout(ctx, oauthHTTPTimeout)
	defer cancel()

	appToken := p.cfg.AppID + "|" + p.cfg.AppSecret
	proof := GenerateAppSecretProof(appToken, p.cfg.AppSecret)

	// Credentials travel in the POST body, never in the URL: a transport
	// failure stringifies the URL via *url.Error and HandleCallback
	// logs that string, so any query-embedded secret would leak (same
	// invariant as FetchUserInfo below; Graph accepts form-encoded POST).
	form := url.Values{}
	form.Set("input_token", userToken)
	form.Set("access_token", appToken)
	form.Set("appsecret_proof", proof)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.debugURL, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.ErrOAuthTokenExchangeFailed
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return errors.ErrOAuthTokenExchangeFailed
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, oauthBodyLimit))
		return errors.ErrOAuthTokenExchangeFailed
	}

	var debugResp struct {
		Data struct {
			AppID   string `json:"app_id"`
			IsValid bool   `json:"is_valid"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, oauthBodyLimit)).Decode(&debugResp); err != nil {
		return errors.ErrOAuthTokenExchangeFailed
	}

	if !debugResp.Data.IsValid || debugResp.Data.AppID != p.cfg.AppID {
		return errors.ErrOAuthTokenExchangeFailed
	}

	return nil
}

// ExchangeCode exchanges an authorization code and PKCE code verifier for an OAuthToken,
// and verifies the token against /debug_token for Confused Deputy defense.
func (p *FacebookProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*OAuthToken, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.AppID)
	form.Set("client_secret", p.cfg.AppSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURI)
	form.Set("code_verifier", codeVerifier)

	tok, err := postTokenForm(ctx, p.client, p.tokenURL, form.Encode())
	if err != nil {
		return nil, err
	}

	if err := p.debugToken(ctx, tok.AccessToken); err != nil {
		return nil, err
	}

	return tok, nil
}

// FetchUserInfo retrieves and normalizes user profile information via /me with appsecret_proof.
func (p *FacebookProvider) FetchUserInfo(ctx context.Context, tokens *OAuthToken) (*OAuthUser, error) {
	if tokens == nil || tokens.AccessToken == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "access token required", nil)
	}

	proof := GenerateAppSecretProof(tokens.AccessToken, p.cfg.AppSecret)

	u, err := url.Parse(p.userInfoURL)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "invalid userinfo url", err)
	}
	q := u.Query()
	q.Set("fields", "id,name,email,picture.width(200).height(200)")
	u.RawQuery = q.Encode()

	// Credentials travel in headers, never in the URL: a transport
	// failure stringifies the URL via *url.Error and HandleCallback
	// logs that string, so any query-embedded secret would leak.
	req, err := userInfoRequest(ctx, u.String(), tokens.AccessToken)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-AppSecret-Proof", proof)

	raw, err := executeJSON[map[string]any](req, p.client, "oauth userinfo request failed")
	if err != nil {
		return nil, err
	}

	id, _ := raw["id"].(string)
	if strings.TrimSpace(id) == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "facebook user id missing", nil)
	}

	name, _ := raw["name"].(string)
	email, _ := raw["email"].(string)
	email = strings.TrimSpace(email)

	// Facebook Graph API omits email if unverified or unregistered and
	// exposes no per-address verification signal, so a present address
	// proves nothing: fail closed and never treat it as verified.
	emailVerified := false

	var avatarURL string
	if picMap, ok := raw["picture"].(map[string]any); ok {
		if dataMap, ok := picMap["data"].(map[string]any); ok {
			if picURL, ok := dataMap["url"].(string); ok {
				avatarURL = picURL
			}
		}
	}

	return &OAuthUser{
		ProviderID:     "facebook",
		ProviderUserID: id,
		Email:          email,
		EmailVerified:  emailVerified,
		Name:           name,
		AvatarURL:      avatarURL,
		RawClaims:      raw,
	}, nil
}
