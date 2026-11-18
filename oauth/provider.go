package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// UserInfo represents normalized profile data retrieved from an OAuth provider.
type UserInfo struct {
	ProviderID     string
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	AvatarURL      string
}

// TokenResponse represents token credentials received from the provider's token endpoint.
type TokenResponse struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	ExpiresIn    int
	IDToken      string
	Raw          map[string]any
}

// Provider defines the standard contract required for any OAuth2 / OIDC identity provider.
type Provider interface {
	// ID returns the canonical provider slug (e.g. "google", "github", "apple").
	ID() string

	// AuthURL constructs the provider authorization URL with PKCE challenge, state, and scopes.
	AuthURL(state, codeChallenge string) string

	// ExchangeCode exchanges an authorization code and PKCE code verifier for tokens.
	ExchangeCode(ctx context.Context, code, codeVerifier string) (*TokenResponse, error)

	// FetchUserInfo retrieves and normalizes user profile information using the granted tokens.
	FetchUserInfo(ctx context.Context, tokens *TokenResponse) (*UserInfo, error)
}

// SupportedProviders defines the canonical set of locked Big 3 providers supported in v1.
var SupportedProviders = map[string]struct{}{
	"google": {},
	"github": {},
	"apple":  {},
}

// NewProvider instantiates a concrete OAuth provider for the given provider slug.
// Strictly supports the locked Big 3 ("google", "github", "apple"). Deferred providers
// (e.g. "discord", "microsoft") return CodeOAuthProviderNotFound.
func NewProvider(id string, cfg config.ProviderConfig) (Provider, error) {
	switch id {
	case "google":
		return NewGoogleProvider(cfg), nil
	case "github":
		return NewGitHubProvider(cfg), nil
	case "apple":
		return NewAppleProvider(cfg), nil
	default:
		return nil, errors.New(errors.CodeOAuthProviderNotFound, "unsupported or deferred oauth provider: "+id, nil)
	}
}

// oauthHTTPTimeout bounds every outbound provider call.
const oauthHTTPTimeout = 10 * time.Second

// oauthBodyLimit caps provider response bodies so a hostile endpoint cannot OOM the caller.
const oauthBodyLimit = 1 << 20

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: oauthHTTPTimeout}
}

// scopesOrDefault joins configured scopes, falling back to the provider defaults.
func scopesOrDefault(cfg []string, defaults ...string) string {
	if len(cfg) > 0 {
		return strings.Join(cfg, " ")
	}
	return strings.Join(defaults, " ")
}

// tokenFromRaw extracts the standard token fields, keeping the full body in Raw.
func tokenFromRaw(raw map[string]any) *TokenResponse {
	tok := &TokenResponse{Raw: raw}
	tok.AccessToken, _ = raw["access_token"].(string)
	tok.TokenType, _ = raw["token_type"].(string)
	tok.RefreshToken, _ = raw["refresh_token"].(string)
	tok.IDToken, _ = raw["id_token"].(string)
	switch v := raw["expires_in"].(type) {
	case float64:
		tok.ExpiresIn = int(v)
	case int:
		tok.ExpiresIn = v
	case string:
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			tok.ExpiresIn = n
		}
	}
	return tok
}

// decodeJSONMap enforces a 2xx status and decodes the body as a JSON object.
func decodeJSONMap(resp *http.Response) (map[string]any, error) {
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, oauthBodyLimit))
		return nil, errors.New(errors.CodeOAuthProviderError, fmt.Sprintf("oauth provider responded with status %d", resp.StatusCode), nil)
	}
	var raw map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, oauthBodyLimit)).Decode(&raw); err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", err)
	}
	if raw == nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", nil)
	}
	return raw, nil
}

// postTokenForm POSTs an x-www-form-urlencoded token request and decodes the JSON response.
func postTokenForm(ctx context.Context, client *http.Client, endpoint, form string) (*TokenResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, oauthHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form))
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token request failed", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token request failed", err)
	}
	raw, err := decodeJSONMap(resp)
	if err != nil {
		return nil, err
	}
	if msg, _ := raw["error"].(string); msg != "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token exchange failed", nil)
	}
	return tokenFromRaw(raw), nil
}

// getJSON issues a Bearer-authenticated GET and decodes the body as a JSON object.
func getJSON(ctx context.Context, client *http.Client, endpoint, accessToken string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, oauthHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth userinfo request failed", err)
	}
	req.Header.Set("Accept", "application/json")
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth userinfo request failed", err)
	}
	return decodeJSONMap(resp)
}

// getJSONArray issues a Bearer-authenticated GET and decodes the body as a JSON array.
func getJSONArray(ctx context.Context, client *http.Client, endpoint, accessToken string) ([]any, error) {
	ctx, cancel := context.WithTimeout(ctx, oauthHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth userinfo request failed", err)
	}
	req.Header.Set("Accept", "application/json")
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth userinfo request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, oauthBodyLimit))
		return nil, errors.New(errors.CodeOAuthProviderError, fmt.Sprintf("oauth provider responded with status %d", resp.StatusCode), nil)
	}
	var raw []any
	if err := json.NewDecoder(io.LimitReader(resp.Body, oauthBodyLimit)).Decode(&raw); err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", err)
	}
	if raw == nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", nil)
	}
	return raw, nil
}
