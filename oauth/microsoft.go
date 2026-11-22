package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// MicrosoftConsumerTenantGUID is the canonical Microsoft tenant GUID for personal consumer accounts.
const MicrosoftConsumerTenantGUID = "9188040d-6c67-4c5b-b112-36a304b66dad"

// MicrosoftProvider implements OAuth 2.0 and OIDC authentication for Microsoft Entra ID (Azure AD).
type MicrosoftProvider struct {
	cfg            config.MicrosoftConfig
	client         *http.Client
	authURL        string
	tokenURL       string
	userinfoURL    string
	jwksURL        string
	jwksMgr        *JWKSManager
	jwksRetriever  JWKSKeyRetriever
	trustedTenants map[string]struct{}
}

// NewMicrosoftProvider constructs a Microsoft Entra ID adapter.
func NewMicrosoftProvider(cfg config.MicrosoftConfig) *MicrosoftProvider {
	tenant := cfg.Tenant
	if tenant == "" {
		tenant = "common"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	if cfg.JWKSCacheTTL <= 0 {
		cfg.JWKSCacheTTL = 24 * time.Hour
	}

	client := newHTTPClient()
	authURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenant)
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant)
	jwksURL := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenant)

	trusted := make(map[string]struct{}, len(cfg.TrustedTenants))
	for _, t := range cfg.TrustedTenants {
		if strings.TrimSpace(t) != "" {
			trusted[strings.TrimSpace(t)] = struct{}{}
		}
	}

	mgr := NewJWKSManager(jwksURL, client, cfg.JWKSCacheTTL)

	return &MicrosoftProvider{
		cfg:            cfg,
		client:         client,
		authURL:        authURL,
		tokenURL:       tokenURL,
		jwksURL:        jwksURL,
		jwksMgr:        mgr,
		jwksRetriever:  mgr,
		trustedTenants: trusted,
	}
}

// ID returns the canonical provider slug.
func (p *MicrosoftProvider) ID() string {
	return "microsoft"
}

// AuthURL builds the Microsoft authorization URL with default options.
func (p *MicrosoftProvider) AuthURL(state, codeChallenge string) string {
	return p.AuthCodeURL(state, codeChallenge)
}

// AuthCodeURL constructs the authorization URL with PKCE challenge, state, prompt, and options.
func (p *MicrosoftProvider) AuthCodeURL(state, codeChallenge string, opts ...AuthCodeOption) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURI)
	q.Set("scope", scopesOrDefault(p.cfg.Scopes, "openid", "profile", "email", "offline_access"))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("response_mode", "query")
	q.Set("prompt", "select_account")

	for _, opt := range opts {
		if opt.Key != "" {
			q.Set(opt.Key, opt.Value)
		}
	}

	return p.authURL + "?" + q.Encode()
}

// ExchangeCode exchanges an authorization code and PKCE code verifier for an OAuthToken.
func (p *MicrosoftProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*OAuthToken, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURI)
	form.Set("code_verifier", codeVerifier)

	return postTokenForm(ctx, p.client, p.tokenURL, form.Encode())
}

// VerifyIDToken cryptographically validates an ID Token against Microsoft's JWKS and extracts claims.
func (p *MicrosoftProvider) VerifyIDToken(ctx context.Context, rawIDToken, nonce string) (*IDTokenClaims, error) {
	if rawIDToken == "" {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "missing raw id_token", nil)
	}

	rawClaims, err := VerifyRS256JWT(ctx, rawIDToken, p.jwksRetriever)
	if err != nil {
		return nil, err
	}

	claims := &IDTokenClaims{}
	claims.Issuer, _ = rawClaims["iss"].(string)
	claims.Subject, _ = rawClaims["sub"].(string)
	claims.Audience, _ = rawClaims["aud"].(string)
	claims.Nonce, _ = rawClaims["nonce"].(string)
	claims.Email, _ = rawClaims["email"].(string)
	claims.Name, _ = rawClaims["name"].(string)
	claims.PreferredUsername, _ = rawClaims["preferred_username"].(string)
	claims.TenantID, _ = rawClaims["tid"].(string)
	claims.OID, _ = rawClaims["oid"].(string)

	switch expVal := rawClaims["exp"].(type) {
	case float64:
		claims.Expiration = int64(expVal)
	case int64:
		claims.Expiration = expVal
	case jsonNumber:
		if n, err := expVal.Int64(); err == nil {
			claims.Expiration = n
		}
	}

	switch iatVal := rawClaims["iat"].(type) {
	case float64:
		claims.IssuedAt = int64(iatVal)
	case int64:
		claims.IssuedAt = iatVal
	}

	if rolesVal, ok := rawClaims["roles"].([]any); ok {
		for _, r := range rolesVal {
			if s, ok := r.(string); ok {
				claims.Roles = append(claims.Roles, s)
			}
		}
	}

	// Audience verification
	if claims.Audience != p.cfg.ClientID {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, fmt.Sprintf("id_token aud %q does not match configured client_id %q", claims.Audience, p.cfg.ClientID), nil)
	}

	// Expiration verification with 1-minute clock skew allowance
	now := time.Now().Unix()
	if claims.Expiration <= (now - 60) {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "id_token has expired", nil)
	}

	// Nonce verification if expected nonce is supplied
	if nonce != "" && claims.Nonce != nonce {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "id_token nonce mismatch", nil)
	}

	// Dynamic issuer verification
	if err := p.verifyIssuer(claims.Issuer, claims.TenantID); err != nil {
		return nil, err
	}

	// "nOauth" anti-account-takeover defense: compute EmailVerified
	claims.EmailVerified = p.isEmailVerified(rawClaims, claims.TenantID)

	return claims, nil
}

// verifyIssuer validates that the token issuer matches the configured authority mode.
func (p *MicrosoftProvider) verifyIssuer(issuer, tenantID string) error {
	tenant := p.cfg.Tenant
	if tenant == "" {
		tenant = "common"
	}

	switch tenant {
	case "consumers":
		expected := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", MicrosoftConsumerTenantGUID)
		if issuer != expected {
			return errors.New(errors.CodeOAuthIDTokenInvalid, fmt.Sprintf("invalid issuer %q for consumers authority mode, expected %q", issuer, expected), nil)
		}
	case "organizations":
		if tenantID == "" || tenantID == MicrosoftConsumerTenantGUID {
			return errors.New(errors.CodeOAuthIDTokenInvalid, "organizations authority mode rejects consumer accounts or missing tid", nil)
		}
		expected := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
		if issuer != expected {
			return errors.New(errors.CodeOAuthIDTokenInvalid, fmt.Sprintf("invalid issuer %q for organizations mode, expected %q", issuer, expected), nil)
		}
	case "common":
		if tenantID == "" {
			return errors.New(errors.CodeOAuthIDTokenInvalid, "common authority mode requires non-empty tid in id_token", nil)
		}
		expected := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
		if issuer != expected {
			return errors.New(errors.CodeOAuthIDTokenInvalid, fmt.Sprintf("invalid issuer %q for common mode, expected %q", issuer, expected), nil)
		}
	default:
		// Specific tenant GUID or domain
		expected := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenant)
		if issuer != expected {
			return errors.New(errors.CodeOAuthIDTokenInvalid, fmt.Sprintf("invalid issuer %q for specific tenant %q, expected %q", issuer, tenant, expected), nil)
		}
	}

	return nil
}

// isEmailVerified implements Microsoft's "nOauth" anti-takeover verification gate.
func (p *MicrosoftProvider) isEmailVerified(rawClaims map[string]any, tenantID string) bool {
	tenant := p.cfg.Tenant
	if tenant == "" {
		tenant = "common"
	}

	// 1. Single-tenant mode (not common, organizations, or consumers)
	if tenant != "common" && tenant != "organizations" && tenant != "consumers" {
		return true
	}

	// 2. Personal consumer account (Microsoft verifies email on registration)
	if tenant == "consumers" || tenantID == MicrosoftConsumerTenantGUID {
		return true
	}

	// 3. Trusted tenant whitelist match
	if len(p.trustedTenants) > 0 {
		if _, ok := p.trustedTenants[tenantID]; ok {
			return true
		}
	}

	// 4. Microsoft domain ownership attestation claim (xms_edov == "1")
	if edov, ok := rawClaims["xms_edov"].(string); ok && edov == "1" {
		return true
	}

	// Untrusted external tenant without domain verification: fail closed
	return false
}

// FetchUserInfo retrieves user details using IDToken claims or the /userinfo endpoint.
func (p *MicrosoftProvider) FetchUserInfo(ctx context.Context, token *OAuthToken) (*OAuthUser, error) {
	if token == nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token is required", nil)
	}

	// Prefer verifying and parsing the IDToken if available
	if token.IDToken != "" {
		claims, err := p.VerifyIDToken(ctx, token.IDToken, "")
		if err != nil {
			return nil, err
		}

		user := &OAuthUser{
			ProviderID:    "microsoft",
			Email:         strings.ToLower(claims.Email),
			EmailVerified: claims.EmailVerified,
			Name:          claims.Name,
			RawClaims: map[string]any{
				"sub":  claims.Subject,
				"tid":  claims.TenantID,
				"oid":  claims.OID,
				"iss":  claims.Issuer,
				"aud":  claims.Audience,
				"name": claims.Name,
			},
		}

		// ProviderUserID: OID if present, fallback to Subject
		if claims.OID != "" {
			user.ProviderUserID = claims.OID
		} else {
			user.ProviderUserID = claims.Subject
		}

		// Fallback email: PreferredUsername
		if user.Email == "" && strings.Contains(claims.PreferredUsername, "@") {
			user.Email = strings.ToLower(claims.PreferredUsername)
		}

		return user, nil
	}

	// If IDToken is absent, fallback to Microsoft Graph /oidc/userinfo or /me
	if token.AccessToken == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "token has neither id_token nor access_token", nil)
	}

	userinfoEndpoint := "https://graph.microsoft.com/oidc/userinfo"
	raw, err := getJSON(ctx, p.client, userinfoEndpoint, token.AccessToken)
	if err != nil {
		return nil, err
	}

	sub, _ := raw["sub"].(string)
	if sub == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "userinfo missing sub claim", nil)
	}

	email, _ := raw["email"].(string)
	name, _ := raw["name"].(string)
	picture, _ := raw["picture"].(string)

	return &OAuthUser{
		ProviderID:     "microsoft",
		ProviderUserID: sub,
		Email:          strings.ToLower(email),
		EmailVerified:  false, // Userinfo alone cannot attest nOauth domain ownership
		Name:           name,
		AvatarURL:      picture,
		RawClaims:      raw,
	}, nil
}

type jsonNumber interface {
	Int64() (int64, error)
}
