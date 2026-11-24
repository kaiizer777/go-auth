package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// MicrosoftConsumerTenantGUID is the canonical Microsoft tenant GUID for personal consumer accounts.
const MicrosoftConsumerTenantGUID = "9188040d-6c67-4c5b-b112-36a304b66dad"

const microsoftDiscoveryBaseURL = "https://login.microsoftonline.com"

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

	// discoveryBaseURL roots domain→tenant-GUID lookups; tests point it at a
	// loopback server. resolveMu guards the caches below.
	discoveryBaseURL string
	resolveMu        sync.Mutex
	tenantGUID       string
	resolvedTrusted  map[string]string
}

// NewMicrosoftProvider constructs a Microsoft Entra ID adapter.
func NewMicrosoftProvider(cfg config.MicrosoftConfig, opts ...EndpointOption) *MicrosoftProvider {
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
	ep := resolveEndpoints(EndpointOverride{
		AuthorizeURL: fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenant),
		TokenURL:     fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant),
		JWKSURL:      fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenant),
		UserInfoURL:  "https://graph.microsoft.com/oidc/userinfo",
	}, opts)

	trusted := make(map[string]struct{}, len(cfg.TrustedTenants))
	for _, t := range cfg.TrustedTenants {
		if t = normalizeTenant(t); t != "" {
			trusted[t] = struct{}{}
		}
	}

	mgr := NewJWKSManager(ep.JWKSURL, client, cfg.JWKSCacheTTL)

	return &MicrosoftProvider{
		cfg:              cfg,
		client:           client,
		authURL:          ep.AuthorizeURL,
		tokenURL:         ep.TokenURL,
		jwksURL:          ep.JWKSURL,
		jwksMgr:          mgr,
		jwksRetriever:    mgr,
		userinfoURL:      ep.UserInfoURL,
		trustedTenants:   trusted,
		discoveryBaseURL: microsoftDiscoveryBaseURL,
	}
}

// normalizeTenant canonicalises a tenant GUID or domain for comparison.
func normalizeTenant(tenant string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(tenant), "."))
}

var tenantGUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// isTenantDomain reports whether a normalized authority is a domain name
// rather than a named authority or tenant GUID.
func isTenantDomain(tenant string) bool {
	return strings.Contains(tenant, ".")
}

// issuerTenant returns the tenant segment of an issuer URL. The host is not
// pinned here: callers validate the issuer itself, and this also has to read
// the GUID from a loopback discovery origin in tests.
func issuerTenant(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	segment, _, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
	return segment
}

// tenantAuthority resolves the configured authority to the tenant GUID form
// Microsoft emits in iss and tid. Entra tokens always name the tenant GUID,
// even when the authority was configured as a domain, so a domain is looked up
// through its v2 discovery issuer once and cached. Resolution failures are
// returned and never cached, so a transient outage does not brick logins.
func (p *MicrosoftProvider) tenantAuthority(ctx context.Context) (string, error) {
	authority := normalizeTenant(p.cfg.Tenant)
	if authority == "" {
		authority = "common"
	}
	if !isTenantDomain(authority) {
		return authority, nil
	}
	p.resolveMu.Lock()
	defer p.resolveMu.Unlock()
	if p.tenantGUID != "" {
		return p.tenantGUID, nil
	}
	guid, err := p.fetchTenantGUID(ctx, authority)
	if err != nil {
		return "", err
	}
	p.tenantGUID = guid
	return guid, nil
}

// fetchTenantGUID reads the tenant GUID from a domain's v2 discovery issuer.
func (p *MicrosoftProvider) fetchTenantGUID(ctx context.Context, domain string) (string, error) {
	base := strings.TrimSuffix(p.discoveryBaseURL, "/")
	if base == "" {
		base = microsoftDiscoveryBaseURL
	}
	discoveryURL := fmt.Sprintf("%s/%s/v2.0/.well-known/openid-configuration", base, domain)
	doc, err := FetchOIDCDiscovery(ctx, p.client, discoveryURL)
	if err != nil {
		return "", errors.New(errors.CodeOAuthProviderError,
			fmt.Sprintf("microsoft tenant domain %q could not be resolved to a tenant id", domain), err)
	}
	guid := normalizeTenant(issuerTenant(doc.Issuer))
	if !tenantGUIDPattern.MatchString(guid) {
		return "", errors.New(errors.CodeOAuthProviderError,
			fmt.Sprintf("microsoft tenant domain %q resolved to non-GUID issuer %q", domain, doc.Issuer), nil)
	}
	return guid, nil
}

// resolveTrustedDomain resolves and caches a domain-form allowlist entry.
func (p *MicrosoftProvider) resolveTrustedDomain(ctx context.Context, domain string) (string, error) {
	p.resolveMu.Lock()
	defer p.resolveMu.Unlock()
	if guid, ok := p.resolvedTrusted[domain]; ok {
		return guid, nil
	}
	guid, err := p.fetchTenantGUID(ctx, domain)
	if err != nil {
		return "", err
	}
	if p.resolvedTrusted == nil {
		p.resolvedTrusted = make(map[string]string)
	}
	p.resolvedTrusted[domain] = guid
	return guid, nil
}

// tenantTrusted reports whether the allowlist accepts the verified tenant.
// Entries may be GUIDs or domains; a domain entry is resolved to its GUID so
// it matches the GUID the token actually carries. An empty allowlist keeps
// multi-tenant mode. An unresolvable domain entry fails closed and surfaces
// the resolution error instead of silently rejecting the tenant.
func (p *MicrosoftProvider) tenantTrusted(ctx context.Context, tenantID, issuer string) (bool, error) {
	if len(p.trustedTenants) == 0 {
		return true, nil
	}
	ids := []string{normalizeTenant(tenantID), normalizeTenant(issuerTenant(issuer))}
	for entry := range p.trustedTenants {
		for _, id := range ids {
			if id != "" && entry == id {
				return true, nil
			}
		}
		if !isTenantDomain(entry) {
			continue
		}
		guid, err := p.resolveTrustedDomain(ctx, entry)
		if err != nil {
			return false, err
		}
		for _, id := range ids {
			if id != "" && id == guid {
				return true, nil
			}
		}
	}
	return false, nil
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

	authority, err := p.tenantAuthority(ctx)
	if err != nil {
		return nil, err
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
	if err := p.verifyIssuer(authority, claims.Issuer, claims.TenantID); err != nil {
		return nil, err
	}

	// "nOauth" anti-account-takeover defense: compute EmailVerified
	claims.EmailVerified = p.isEmailVerified(authority, rawClaims, claims.TenantID)

	// The allowlist bounds which external tenants may hold accounts here.
	// Attestation never overrides it: an unlisted tenant is untrusted even
	// when it presents xms_edov.
	trusted, err := p.tenantTrusted(ctx, claims.TenantID, claims.Issuer)
	if err != nil {
		return nil, err
	}
	if !trusted {
		claims.EmailVerified = false
		rawClaims["untrusted_tenant"] = true
	}

	if isUntrusted, _ := rawClaims["untrusted_tenant"].(bool); isUntrusted {
		claims.UntrustedTenant = true
	}

	return claims, nil
}

// verifyIssuer validates that the token issuer matches the configured authority
// mode. authority is the tenant GUID a domain-form configuration resolved to.
func (p *MicrosoftProvider) verifyIssuer(authority, issuer, tenantID string) error {
	switch authority {
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
		// Specific tenant, already resolved to the GUID form Microsoft emits.
		expected := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", authority)
		if issuer != expected {
			return errors.New(errors.CodeOAuthTenantInvalid, fmt.Sprintf("invalid issuer %q for specific tenant %q, expected %q", issuer, p.cfg.Tenant, expected), nil)
		}
	}

	return nil
}

// isEmailVerified implements Microsoft's "nOauth" anti-takeover verification gate.
// authority is the resolved tenant GUID a domain-form configuration named.
func (p *MicrosoftProvider) isEmailVerified(authority string, rawClaims map[string]any, tenantID string) bool {
	// 1. Single-tenant mode (not common, organizations, or consumers). The
	// authority pins one tenant, but verification is inherited only when the
	// token actually names that tenant; the caller has validated the issuer.
	if authority != "common" && authority != "organizations" && authority != "consumers" {
		return normalizeTenant(tenantID) == authority
	}

	// 2. Personal consumer account (Microsoft verifies email on registration)
	if authority == "consumers" || tenantID == MicrosoftConsumerTenantGUID {
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

	// The userinfo response carries no signed issuer, so only the tenant claim
	// can be evaluated here; an allowlist miss fails closed on the same marker
	// the ID-token path sets.
	tid, _ := raw["tid"].(string)
	trusted, err := p.tenantTrusted(ctx, tid, "")
	if err != nil {
		return nil, err
	}
	if !trusted {
		raw["untrusted_tenant"] = true
	}

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
