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
	jwksURL        string
	jwksMgr        *JWKSManager
	jwksRetriever  JWKSKeyRetriever
	userinfoURL    string
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
		if t = normalizeTenant(t); t != "" {
			trusted[t] = struct{}{}
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
		userinfoURL:    "https://graph.microsoft.com/oidc/userinfo",
		trustedTenants: trusted,
	}
}

// normalizeTenant canonicalises a tenant GUID or domain for comparison.
func normalizeTenant(tenant string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(tenant), "."))
}

// issuerTenant returns the tenant segment of a Microsoft v2 issuer.
func issuerTenant(issuer string) string {
	const prefix = "https://login.microsoftonline.com/"
	if !strings.HasPrefix(issuer, prefix) {
		return ""
	}
	segment := strings.TrimPrefix(issuer, prefix)
	if i := strings.IndexByte(segment, '/'); i >= 0 {
		segment = segment[:i]
	}
	return segment
}

// tenantTrusted reports whether the allowlist accepts the verified tenant.
// Identifiers compare verbatim and case-insensitively, so entries may be
// GUIDs or tenant domains; the issuer segment covers domain-form authorities.
// An empty allowlist keeps multi-tenant mode.
func (p *MicrosoftProvider) tenantTrusted(tenantID, issuer string) bool {
	if len(p.trustedTenants) == 0 {
		return true
	}
	for _, id := range []string{tenantID, issuerTenant(issuer)} {
		if id == "" {
			continue
		}
		if _, ok := p.trustedTenants[normalizeTenant(id)]; ok {
			return true
		}
	}
	return false
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

	applyAuthCodeOptions(q, opts)

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

	// oid and sub are the only stable identity keys; a token carrying neither
	// would key every such login onto an empty provider_user_id.
	if claims.OID == "" && claims.Subject == "" {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "id_token missing both oid and sub claims", nil)
	}

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
	case jsonNumber:
		if n, err := iatVal.Int64(); err == nil {
			claims.IssuedAt = n
		}
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

	// Clock skew upper bound on IssuedAt (cannot be issued > 60s in future)
	if claims.IssuedAt > (now + 60) {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "id_token issued in the future", nil)
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

	// The allowlist bounds which external tenants may hold accounts here.
	// Attestation never overrides it: an unlisted tenant is untrusted even
	// when it presents xms_edov.
	if !p.tenantTrusted(claims.TenantID, claims.Issuer) {
		claims.EmailVerified = false
		rawClaims["untrusted_tenant"] = true
	}

	if isUntrusted, _ := rawClaims["untrusted_tenant"].(bool); isUntrusted {
		claims.UntrustedTenant = true
	}

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
			return errors.New(errors.CodeOAuthTenantInvalid, fmt.Sprintf("invalid issuer %q for specific tenant %q, expected %q", issuer, tenant, expected), nil)
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

	// 1. Single-tenant mode (not common, organizations, or consumers). The
	// authority pins one tenant, but verification is inherited only when the
	// token actually names that tenant; the caller has validated the issuer.
	if tenant != "common" && tenant != "organizations" && tenant != "consumers" {
		return normalizeTenant(tenantID) == normalizeTenant(tenant)
	}

	// 2. Personal consumer account (Microsoft verifies email on registration)
	if tenant == "consumers" || tenantID == MicrosoftConsumerTenantGUID {
		return true
	}

	// Trusted-tenant whitelist attests tenant identity only, never the email
	// value: tenant admins can claim foreign-domain addresses, so fall
	// through to xms_edov attestation below and fail closed otherwise.

	// 3. Microsoft domain ownership attestation claim. The token
	// decoder yields bool, string, or numeric shapes depending on the
	// issuer; accept every attested form, default-deny anything else.
	switch edov := rawClaims["xms_edov"].(type) {
	case bool:
		if edov {
			return true
		}
	case string:
		// "true" is accepted alongside "1": both encodings are MS-signed, so
		// this only affects availability, never the trust model below.
		if trimmed := strings.TrimSpace(edov); trimmed == "1" || trimmed == "true" {
			return true
		}
	case float64:
		if edov == 1 {
			return true
		}
	case int:
		if edov == 1 {
			return true
		}
	case int64:
		if edov == 1 {
			return true
		}
	case jsonNumber:
		if n, err := edov.Int64(); err == nil && n == 1 {
			return true
		}
	}

	// Untrusted external tenant without domain verification: fail closed
	if rawClaims != nil {
		rawClaims["untrusted_tenant"] = true
	}
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
		if claims.UntrustedTenant {
			user.RawClaims["untrusted_tenant"] = true
		}
		if claims.PreferredUsername != "" {
			user.RawClaims["preferred_username"] = claims.PreferredUsername
		}

		// ProviderUserID: OID if present, fallback to Subject
		user.ProviderUserID = providerUserID(claims.OID, claims.Subject)

		// Fallback from admin-mutable UPN never verifies the address.
		if user.Email == "" && strings.Contains(claims.PreferredUsername, "@") {
			user.Email = strings.ToLower(claims.PreferredUsername)
			user.EmailVerified = false
		}

		return user, nil
	}

	// If IDToken is absent, fallback to Microsoft Graph /oidc/userinfo or /me
	if token.AccessToken == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "token has neither id_token nor access_token", nil)
	}

	userinfoEndpoint := p.userinfoURL
	raw, err := getJSON(ctx, p.client, userinfoEndpoint, token.AccessToken)
	if err != nil {
		return nil, err
	}

	oid, _ := raw["oid"].(string)
	sub, _ := raw["sub"].(string)
	if oid == "" && sub == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "userinfo missing both oid and sub claims", nil)
	}

	email, _ := raw["email"].(string)
	name, _ := raw["name"].(string)
	picture, _ := raw["picture"].(string)

	return &OAuthUser{
		ProviderID:     "microsoft",
		ProviderUserID: providerUserID(oid, sub),
		Email:          strings.ToLower(email),
		EmailVerified:  false, // Userinfo alone cannot attest nOauth domain ownership
		Name:           name,
		AvatarURL:      picture,
		RawClaims:      raw,
	}, nil
}

// providerUserID keys the identity on oid, the immutable directory object id,
// and falls back to sub only when the token omits oid. Both token paths must
// resolve the same principal to the same key.
func providerUserID(oid, sub string) string {
	if oid != "" {
		return oid
	}
	return sub
}

type jsonNumber interface {
	Int64() (int64, error)
}
