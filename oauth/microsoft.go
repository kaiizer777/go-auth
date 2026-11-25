package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// MicrosoftConsumerTenantGUID is the canonical Microsoft tenant GUID for personal consumer accounts.
const MicrosoftConsumerTenantGUID = "9188040d-6c67-4c5b-b112-36a304b66dad"

const microsoftDiscoveryBaseURL = "https://login.microsoftonline.com"

const (
	// tenantResolutionTimeout bounds one tenant-discovery lookup: a slow or dead
	// endpoint fails the login that triggered it instead of stalling the next.
	tenantResolutionTimeout = 5 * time.Second
	// tenantResolutionCooldown negatively caches a failed lookup so a broken
	// domain fails fast rather than paying the timeout on every login.
	tenantResolutionCooldown = 30 * time.Second
)

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

	// discoveryBaseURL roots domain→tenant-GUID lookups. resolveMu guards the
	// caches below and is never held across I/O: lookups run inside
	// resolveFlight so concurrent logins for one domain share a request.
	discoveryBaseURL string
	resolveTimeout   time.Duration
	resolveMu        sync.Mutex
	resolveFlight    singleflight.Group
	resolvedGUIDs    map[string]string
	resolveFailures  map[string]resolutionFailure
}

// resolutionFailure is a negatively cached lookup failure and the time its
// cooldown expires.
type resolutionFailure struct {
	retryAt time.Time
	err     error
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
		DiscoveryURL: microsoftDiscoveryBaseURL,
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
		discoveryBaseURL: ep.DiscoveryURL,
		resolveTimeout:   tenantResolutionTimeout,
		resolvedGUIDs:    make(map[string]string),
		resolveFailures:  make(map[string]resolutionFailure),
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
// through its v2 discovery issuer once and cached.
func (p *MicrosoftProvider) tenantAuthority(ctx context.Context) (string, error) {
	authority := normalizeTenant(p.cfg.Tenant)
	if authority == "" {
		authority = "common"
	}
	if !isTenantDomain(authority) {
		return authority, nil
	}
	return p.resolveDomain(ctx, authority)
}

// resolveDomain maps a domain-form tenant or allowlist entry to the GUID
// Microsoft emits in iss and tid. Concurrent lookups for one domain share a
// single discovery request, successes are cached for the process lifetime, and
// failures are negatively cached for tenantResolutionCooldown so a broken
// domain fails fast instead of paying the timeout on every login.
func (p *MicrosoftProvider) resolveDomain(ctx context.Context, domain string) (string, error) {
	p.resolveMu.Lock()
	if guid, ok := p.resolvedGUIDs[domain]; ok {
		p.resolveMu.Unlock()
		return guid, nil
	}
	if failure, ok := p.resolveFailures[domain]; ok {
		if time.Now().Before(failure.retryAt) {
			p.resolveMu.Unlock()
			return "", failure.err
		}
		delete(p.resolveFailures, domain)
	}
	p.resolveMu.Unlock()

	v, err, _ := p.resolveFlight.Do(domain, func() (any, error) {
		p.resolveMu.Lock()
		if guid, ok := p.resolvedGUIDs[domain]; ok {
			p.resolveMu.Unlock()
			return guid, nil
		}
		p.resolveMu.Unlock()

		// Detach from the triggering request so a canceled login does not fail
		// the logins that joined this flight; the bound still caps the lookup.
		lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.resolveTimeout)
		defer cancel()
		guid, ferr := p.fetchTenantGUID(lookupCtx, domain)
		p.resolveMu.Lock()
		defer p.resolveMu.Unlock()
		if ferr != nil {
			p.resolveFailures[domain] = resolutionFailure{retryAt: time.Now().Add(tenantResolutionCooldown), err: ferr}
			return nil, ferr
		}
		p.resolvedGUIDs[domain] = guid
		return guid, nil
	})
	if err != nil {
		return "", err
	}
	guid, _ := v.(string)
	return guid, nil
}

// fetchTenantGUID reads the tenant GUID from a domain's v2 discovery issuer.
// A 404 means the configured domain names no usable authority, so that is an
// operator configuration defect. Transport failures and 5xx stay operational:
// a transient outage must not be reported as bad configuration.
func (p *MicrosoftProvider) fetchTenantGUID(ctx context.Context, domain string) (string, error) {
	base := strings.TrimSuffix(p.discoveryBaseURL, "/")
	if base == "" {
		base = microsoftDiscoveryBaseURL
	}
	discoveryURL := fmt.Sprintf("%s/%s/v2.0/.well-known/openid-configuration", base, domain)
	doc, err := FetchOIDCDiscovery(ctx, p.client, discoveryURL)
	if err != nil {
		var statusErr *discoveryStatusError
		if errors.As(err, &statusErr) && statusErr.status == http.StatusNotFound {
			return "", errors.New(errors.CodeInvalidConfig,
				fmt.Sprintf("microsoft tenant domain %q could not be resolved to a tenant id", domain), err)
		}
		return "", err
	}
	guid := normalizeTenant(issuerTenant(doc.Issuer))
	if !tenantGUIDPattern.MatchString(guid) {
		// The issuer is server-controlled: keep it in the cause, never in the
		// client-visible message.
		return "", errors.New(errors.CodeInvalidConfig,
			fmt.Sprintf("microsoft tenant domain %q did not resolve to a tenant id", domain),
			errors.New(errors.CodeInvalidConfig, "issuer "+doc.Issuer+" is not a tenant GUID", nil))
	}
	return guid, nil
}

// tenantTrusted reports whether the allowlist accepts the verified tenant.
// Entries may be GUIDs or domains; a domain entry is resolved to its GUID so
// it matches the GUID the token actually carries. An empty allowlist denies
// all tenants (fail-closed).
//
// Entries are walked in sorted order, so the outcome never depends on map
// iteration order. Only a domain entry can require discovery, and a resolution
// failure is held back instead of failing the login: a stale entry that is not
// the token's authority must not decide a login another entry already admits.
// When no entry admits the tenant, the first failure still fails closed rather
// than silently marking the tenant untrusted.
func (p *MicrosoftProvider) tenantTrusted(ctx context.Context, tenantID, issuer string) (bool, error) {
	if len(p.trustedTenants) == 0 {
		return false, nil
	}
	ids := []string{normalizeTenant(tenantID), normalizeTenant(issuerTenant(issuer))}
	matches := func(candidate string) bool {
		for _, id := range ids {
			if id != "" && candidate == id {
				return true
			}
		}
		return false
	}

	entries := make([]string, 0, len(p.trustedTenants))
	for entry := range p.trustedTenants {
		entries = append(entries, entry)
	}
	slices.Sort(entries)

	// Direct matches settle without touching discovery, so a broken domain
	// entry cannot fail a login the token's own GUID already authorises.
	var domains []string
	for _, entry := range entries {
		if matches(entry) {
			return true, nil
		}
		if isTenantDomain(entry) {
			domains = append(domains, entry)
		}
	}

	var resolveErr error
	for _, domain := range domains {
		guid, err := p.resolveDomain(ctx, domain)
		if err != nil {
			if resolveErr == nil {
				resolveErr = err
			}
			continue
		}
		if matches(guid) {
			return true, nil
		}
	}
	if resolveErr != nil {
		return false, resolveErr
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

	// "nOauth" anti-account-takeover defense: EmailVerified reflects only
	// whether the provider attested the address, never tenant admission.
	claims.EmailVerified = p.isEmailVerified(authority, rawClaims, claims.TenantID)

	// The allowlist bounds which external tenants may hold accounts here.
	// Attestation never overrides it: an unlisted tenant is untrusted even
	// when it presents xms_edov. Admission and attestation are independent, so
	// an admitted tenant without attestation stays a valid unverified identity.
	trusted, err := p.tenantTrusted(ctx, claims.TenantID, claims.Issuer)
	if err != nil {
		return nil, err
	}
	claims.UntrustedTenant = !trusted

	return claims, nil
}

// verifyIssuer validates that the token issuer matches the configured authority
// mode. authority is the tenant GUID a domain-form configuration resolved to.
func (p *MicrosoftProvider) verifyIssuer(authority, issuer, tenantID string) error {
	switch authority {
	case "consumers":
		expected := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", MicrosoftConsumerTenantGUID)
		if issuer != expected {
			return issuerRejection(errors.CodeOAuthIDTokenInvalid, "id_token issuer does not match the consumers authority", issuer, expected)
		}
		if normalizeTenant(tenantID) != MicrosoftConsumerTenantGUID {
			return errors.New(errors.CodeOAuthIDTokenInvalid, "consumers authority mode requires the consumer tid", nil)
		}
	case "organizations":
		if tid := normalizeTenant(tenantID); tid == "" || tid == MicrosoftConsumerTenantGUID {
			return errors.New(errors.CodeOAuthIDTokenInvalid, "organizations authority mode rejects consumer accounts or missing tid", nil)
		}
		expected := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
		if issuer != expected {
			return issuerRejection(errors.CodeOAuthIDTokenInvalid, "id_token issuer does not match the organizations authority", issuer, expected)
		}
	case "common":
		if tenantID == "" {
			return errors.New(errors.CodeOAuthIDTokenInvalid, "common authority mode requires non-empty tid in id_token", nil)
		}
		expected := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
		if issuer != expected {
			return issuerRejection(errors.CodeOAuthIDTokenInvalid, "id_token issuer does not match the token tenant", issuer, expected)
		}
	default:
		// Specific tenant, already resolved to the GUID form Microsoft emits.
		expected := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", authority)
		if issuer != expected {
			return issuerRejection(errors.CodeOAuthTenantInvalid, "id_token issuer does not match the configured tenant", issuer, expected)
		}
	}

	return nil
}

// issuerRejection builds the client-facing issuer rejection with a generic
// message: the token's issuer and the authority expected for it are server-side
// facts and ride the cause, which only reaches server-side logs.
func issuerRejection(code errors.Code, message, issuer, expected string) error {
	return errors.New(code, message,
		errors.New(code, fmt.Sprintf("issuer %q does not match expected %q", issuer, expected), nil))
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
	if authority == "consumers" || normalizeTenant(tenantID) == MicrosoftConsumerTenantGUID {
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

		// ProviderUserID: sub is the key both token paths share, oid the fallback
		user.ProviderUserID = identityKey(claims.Subject, claims.OID)

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

	// /oidc/userinfo carries no tenant and no signed issuer, so an authority
	// narrower than common or an allowlist cannot be enforced on this path.
	// Fail closed with a configuration error instead of trusting the token.
	if p.tenantScoped() {
		return nil, errors.New(errors.CodeInvalidConfig,
			"microsoft userinfo cannot validate the token tenant without a verified id_token", nil)
	}

	userinfoEndpoint := p.userinfoURL
	raw, err := getJSON(ctx, p.client, userinfoEndpoint, token.AccessToken)
	if err != nil {
		return nil, err
	}

	sub, _ := raw["sub"].(string)
	oid, _ := raw["oid"].(string)
	if sub == "" && oid == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "userinfo returned no subject identifier", nil)
	}

	email, _ := raw["email"].(string)
	name, _ := raw["name"].(string)
	picture, _ := raw["picture"].(string)

	return &OAuthUser{
		ProviderID:     "microsoft",
		ProviderUserID: identityKey(sub, oid),
		Email:          strings.ToLower(email),
		EmailVerified:  false, // Userinfo alone cannot attest nOauth domain ownership
		Name:           name,
		AvatarURL:      picture,
		RawClaims:      raw,
	}, nil
}

// tenantScoped reports whether the deployment constrains tenants beyond
// Microsoft's multi-tenant "common" authority.
func (p *MicrosoftProvider) tenantScoped() bool {
	if len(p.trustedTenants) > 0 {
		return true
	}
	authority := normalizeTenant(p.cfg.Tenant)
	return authority != "" && authority != "common"
}

// identityKey keys the principal on sub, the claim both the id_token and
// /oidc/userinfo return, and falls back to oid only when sub is absent. Keying
// on oid first splits one principal into two provider_user_id values: the
// userinfo payload never carries oid.
func identityKey(sub, oid string) string {
	if sub != "" {
		return sub
	}
	return oid
}
