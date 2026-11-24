package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// AuthCodeOption specifies query parameters for authorization requests.
type AuthCodeOption struct {
	Key   string
	Value string
}

// AccessTypeOffline specifies offline access for refresh token issuance.
func AccessTypeOffline() AuthCodeOption {
	return AuthCodeOption{Key: "access_type", Value: "offline"}
}

// isReservedAuthorizeParam reports security-critical authorize keys the
// service generates per login. Adapters set these before applying options;
// matching is case-insensitive because query keys cross trust boundaries.
func isReservedAuthorizeParam(key string) bool {
	switch strings.ToLower(key) {
	case "response_type", "client_id", "redirect_uri",
		"state", "code_challenge", "code_challenge_method":
		return true
	}
	return false
}

// applyAuthCodeOptions copies caller options into q, dropping reserved keys
// so options can only add parameters, never replace mandatory ones.
func applyAuthCodeOptions(q url.Values, opts []AuthCodeOption) {
	for _, opt := range opts {
		if opt.Key == "" || isReservedAuthorizeParam(opt.Key) {
			continue
		}
		q.Set(opt.Key, opt.Value)
	}
}

// PromptOption specifies prompt behavior (e.g. consent, select_account).
func PromptOption(prompt string) AuthCodeOption {
	return AuthCodeOption{Key: "prompt", Value: prompt}
}

// NonceOption specifies cryptographic nonce for OpenID Connect authorization requests.
func NonceOption(nonce string) AuthCodeOption {
	return AuthCodeOption{Key: "nonce", Value: nonce}
}

// OAuthToken encapsulates the token response returned by an OAuth 2.0 provider.
type OAuthToken struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type"`
	RefreshToken string         `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time      `json:"expires_at,omitempty"`
	ExpiresIn    int            `json:"expires_in,omitempty"`
	IDToken      string         `json:"id_token,omitempty"`
	Raw          map[string]any `json:"-"`
}

// TokenResponse is a backward-compatible alias for OAuthToken.
type TokenResponse = OAuthToken

// OAuthUser represents normalized profile data retrieved from an OAuth provider.
type OAuthUser struct {
	ProviderID     string         `json:"provider_id"`
	ProviderUserID string         `json:"provider_user_id"`
	Email          string         `json:"email"`
	EmailVerified  bool           `json:"email_verified"`
	Name           string         `json:"name"`
	AvatarURL      string         `json:"avatar_url"`
	RawClaims      map[string]any `json:"raw_claims,omitempty"`
}

// UserInfo is a backward-compatible alias for OAuthUser.
type UserInfo = OAuthUser

// Provider defines the standard contract required for any OAuth2 / OIDC identity provider.
// AuthURL is the option-free authorization URL. Providers that additionally
// accept per-login options expose AuthCodeURLProvider.
type Provider interface {
	// ID returns the canonical provider slug (e.g. "google", "github", "apple", "microsoft").
	ID() string

	// AuthURL constructs the provider authorization URL with PKCE challenge, state, and scopes.
	AuthURL(state, codeChallenge string) string

	// ExchangeCode exchanges an authorization code and PKCE code verifier for tokens.
	ExchangeCode(ctx context.Context, code, codeVerifier string) (*OAuthToken, error)

	// FetchUserInfo retrieves and normalizes user profile information using the granted tokens.
	FetchUserInfo(ctx context.Context, tokens *OAuthToken) (*OAuthUser, error)
}

// AuthCodeURLProvider is the optional capability for providers that build the
// authorization redirect with per-login options such as an OIDC nonce. Keeping
// it out of Provider preserves source compatibility for implementers written
// against the original contract; callers type-assert before using it.
// An OIDCProvider without this capability still receives the nonce: the service
// appends it to the AuthURL result, because the callback verifies every OIDC
// ID-token nonce.
// Tenant-scoped providers (Microsoft) pin the tenant in the endpoint when the
// provider is constructed, so the tenant travels through this same path.
type AuthCodeURLProvider interface {
	// AuthCodeURL constructs the authorization redirect URL with state, PKCE challenge, and options.
	AuthCodeURL(state, codeChallenge string, opts ...AuthCodeOption) string
}

// OIDCProvider extends Provider for OpenID Connect compliant providers supporting ID token discovery & verification.
type OIDCProvider interface {
	Provider

	// VerifyIDToken cryptographically validates an ID Token JWT against provider JWKS.
	VerifyIDToken(ctx context.Context, rawIDToken, nonce string) (*IDTokenClaims, error)
}

// IDTokenClaims defines the standard OpenID Connect claims extracted from an ID Token.
type IDTokenClaims struct {
	Issuer            string   `json:"iss"`
	Subject           string   `json:"sub"`
	Audience          string   `json:"aud"`
	Expiration        int64    `json:"exp"`
	IssuedAt          int64    `json:"iat"`
	Nonce             string   `json:"nonce,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	Name              string   `json:"name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	TenantID          string   `json:"tid,omitempty"`
	OID               string   `json:"oid,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	UntrustedTenant   bool     `json:"untrusted_tenant,omitempty"`
}

// supportedProviderIDs is the canonical, immutable provider set. Authorization
// decisions read this slice so no package-level map mutation can widen it.
var supportedProviderIDs = [...]string{
	"google", "github", "apple", "microsoft", "facebook", "discord", "x",
}

// SupportedProviders is a snapshot kept for source compatibility. Mutating it
// does not affect authorization decisions; call IsSupportedProvider instead.
var SupportedProviders = func() map[string]struct{} {
	m := make(map[string]struct{}, len(supportedProviderIDs))
	for _, id := range supportedProviderIDs {
		m[id] = struct{}{}
	}
	return m
}()

// IsSupportedProvider reports whether id is a canonical provider slug.
func IsSupportedProvider(id string) bool {
	return slices.Contains(supportedProviderIDs[:], id)
}

// NewProvider instantiates a concrete OAuth provider for the given provider slug.
// Supports all 7 canonical providers ("google", "github", "apple", "microsoft", "facebook", "discord", "x").
// The optional OAuth config carries the typed Microsoft/Facebook overrides
// (tenant, trusted tenants, JWKS TTL, graph version) that ProviderConfig cannot
// express; set typed fields win, generic identity fields fill the gaps.
func NewProvider(id string, cfg config.ProviderConfig, oCfg ...*config.OAuthConfig) (Provider, error) {
	var typed *config.OAuthConfig
	if len(oCfg) > 0 {
		typed = oCfg[0]
	}
	switch id {
	case "google":
		return NewGoogleProvider(cfg), nil
	case "github":
		return NewGitHubProvider(cfg), nil
	case "apple":
		return NewAppleProvider(cfg), nil
	case "microsoft":
		return NewMicrosoftProvider(mergeMicrosoftConfig(cfg, typed)), nil
	case "facebook":
		merged := mergeFacebookConfig(cfg, typed)
		if merged.AssertEmailVerified {
			return NewFacebookProvider(merged, FacebookAssertEmailVerified()), nil
		}
		return NewFacebookProvider(merged), nil
	case "discord":
		return NewDiscordProvider(config.DiscordConfig{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURI:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
		}), nil
	case "x":
		return NewXProvider(config.XConfig{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURI:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
		}), nil
	default:
		return nil, errors.New(errors.CodeOAuthProviderNotFound, "unsupported or deferred oauth provider: "+id, nil)
	}
}

// mergeMicrosoftConfig overlays typed Microsoft overrides on generic identity fields.
// Generic tenant, allowlist, and JWKS TTL survive a missing typed section so
// map-only callers (2-arg NewProvider) keep working after the merge.
func mergeMicrosoftConfig(cfg config.ProviderConfig, typed *config.OAuthConfig) config.MicrosoftConfig {
	merged := config.MicrosoftConfig{
		ClientID:       cfg.ClientID,
		ClientSecret:   cfg.ClientSecret,
		RedirectURI:    cfg.RedirectURL,
		Scopes:         cfg.Scopes,
		Tenant:         cfg.Tenant,
		TrustedTenants: cfg.TrustedTenants,
		JWKSCacheTTL:   cfg.JWKSCacheTTL,
	}
	if typed == nil || typed.Microsoft == nil {
		return merged
	}
	t := typed.Microsoft
	if t.ClientID != "" {
		merged.ClientID = t.ClientID
	}
	if t.ClientSecret != "" {
		merged.ClientSecret = t.ClientSecret
	}
	if t.RedirectURI != "" {
		merged.RedirectURI = t.RedirectURI
	}
	if len(t.Scopes) > 0 {
		merged.Scopes = t.Scopes
	}
	if t.Tenant != "" {
		merged.Tenant = t.Tenant
	}
	if len(t.TrustedTenants) > 0 {
		merged.TrustedTenants = t.TrustedTenants
	}
	if t.JWKSCacheTTL != 0 {
		merged.JWKSCacheTTL = t.JWKSCacheTTL
	}
	return merged
}

// mergeFacebookConfig overlays typed Facebook overrides on generic identity fields.
// The generic graph version survives a missing typed section for the same
// reason as mergeMicrosoftConfig above.
func mergeFacebookConfig(cfg config.ProviderConfig, typed *config.OAuthConfig) config.FacebookConfig {
	merged := config.FacebookConfig{
		AppID:               cfg.ClientID,
		AppSecret:           cfg.ClientSecret,
		RedirectURI:         cfg.RedirectURL,
		Scopes:              cfg.Scopes,
		GraphVersion:        cfg.GraphVersion,
		AssertEmailVerified: cfg.AssertEmailVerified,
	}
	if typed == nil || typed.Facebook == nil {
		return merged
	}
	t := typed.Facebook
	if t.AppID != "" {
		merged.AppID = t.AppID
	}
	if t.AppSecret != "" {
		merged.AppSecret = t.AppSecret
	}
	if t.RedirectURI != "" {
		merged.RedirectURI = t.RedirectURI
	}
	if len(t.Scopes) > 0 {
		merged.Scopes = t.Scopes
	}
	if t.GraphVersion != "" {
		merged.GraphVersion = t.GraphVersion
	}
	if t.AssertEmailVerified {
		merged.AssertEmailVerified = true
	}
	return merged
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

// jsonObjectOrArray is the closed set of provider body shapes: a JSON object
// (userinfo, token) or an array (GitHub's email list).
type jsonObjectOrArray interface {
	map[string]any | []any
}

// executeJSON sends req and decodes the bounded body into the requested shape.
// failMsg labels transport failures (token vs userinfo); status and decode
// failures share the provider-wide messages.
func executeJSON[T jsonObjectOrArray](req *http.Request, client *http.Client, failMsg string) (T, error) {
	var out T
	resp, err := client.Do(req)
	if err != nil {
		return out, errors.New(errors.CodeOAuthProviderError, failMsg, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, oauthBodyLimit))
		return out, errors.New(errors.CodeOAuthProviderError, fmt.Sprintf("oauth provider responded with status %d", resp.StatusCode), nil)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, oauthBodyLimit)).Decode(&out); err != nil {
		return out, errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", err)
	}
	if out == nil {
		return out, errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", nil)
	}
	return out, nil
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
	raw, err := executeJSON[map[string]any](req, client, "oauth token request failed")
	if err != nil {
		return nil, err
	}
	if msg, _ := raw["error"].(string); msg != "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token exchange failed", nil)
	}
	return tokenFromRaw(raw), nil
}

// userInfoRequest builds the Bearer-authenticated userinfo GET shared by both
// response shapes.
func userInfoRequest(ctx context.Context, endpoint, accessToken string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth userinfo request failed", err)
	}
	req.Header.Set("Accept", "application/json")
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	return req, nil
}

// getJSON issues a Bearer-authenticated GET and decodes the body as a JSON object.
func getJSON(ctx context.Context, client *http.Client, endpoint, accessToken string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, oauthHTTPTimeout)
	defer cancel()
	req, err := userInfoRequest(ctx, endpoint, accessToken)
	if err != nil {
		return nil, err
	}
	return executeJSON[map[string]any](req, client, "oauth userinfo request failed")
}

// getJSONArray issues a Bearer-authenticated GET and decodes the body as a JSON array.
func getJSONArray(ctx context.Context, client *http.Client, endpoint, accessToken string) ([]any, error) {
	ctx, cancel := context.WithTimeout(ctx, oauthHTTPTimeout)
	defer cancel()
	req, err := userInfoRequest(ctx, endpoint, accessToken)
	if err != nil {
		return nil, err
	}
	return executeJSON[[]any](req, client, "oauth userinfo request failed")
}
