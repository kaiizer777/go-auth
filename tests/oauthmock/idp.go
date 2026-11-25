package oauthmock

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// IdPs below emulate each provider's HTTP surface (authorize, token, userinfo,
// JWKS) so tests can drive the real adapter instead of a Provider stub: point
// the adapter at Server with oauth.WithEndpoints. The authorize leg validates
// the adapter's PKCE S256 request, and rejects a redirect_uri or scope the
// client did not register, then records the grant; the token leg redeems the
// code once against that challenge and rejects a token request that does not
// replay both, so a broken authorize URL, a dropped verifier, or a mismatched
// redirect fails the journey rather than passing through a mock.

// DefaultRedirectURI is the callback the IdPs have on file when a test does not
// register the adapter's configured redirect URI.
const DefaultRedirectURI = "http://app.example/callback"

// registeredRedirect returns the first non-empty override, or the default.
func registeredRedirect(override []string) string {
	if len(override) > 0 && override[0] != "" {
		return override[0]
	}
	return DefaultRedirectURI
}

const msAccessToken = "ms-idp-access-token"

// msForeignTenant is the tenant a bad-issuer token names; it is never the
// tenant the adapter under test is configured for.
const msForeignTenant = "99999999-9999-9999-9999-999999999999"

// IDTokenFault corrupts one aspect of a minted id_token so a test can prove the
// adapter rejects it. The zero value mints a valid token.
type IDTokenFault string

const (
	FaultNone         IDTokenFault = ""
	FaultBadIssuer    IDTokenFault = "bad_issuer"
	FaultBadAudience  IDTokenFault = "bad_audience"
	FaultBadSignature IDTokenFault = "bad_signature"
)

// MicrosoftIdP emulates Entra ID authorize, token, JWKS, and userinfo.
type MicrosoftIdP struct {
	Server *httptest.Server

	ClientID     string
	ClientSecret string
	TenantID     string
	OID          string
	Subject      string
	Email        string
	Name         string
	// OmitIDToken drops id_token from the token response, forcing the adapter
	// onto its /userinfo fallback.
	OmitIDToken bool
	// Fault breaks one id_token property. At most one aspect is corrupted so
	// the rejection is attributable to it.
	Fault IDTokenFault

	// edov is the xms_edov domain-ownership attestation claim. Tokens are
	// unattested by default: an attested default would hide the difference
	// between tenant admission and address attestation.
	edov string

	codes *authorizeCodes
	priv  *rsa.PrivateKey
	kid   string
	n     string
	e     string
}

// AttestDomain opts the IdP into the xms_edov attestation, which is what the
// adapter treats as proof that the tenant owns the address domain.
func (i *MicrosoftIdP) AttestDomain() { i.edov = "1" }

// NewMicrosoftIdP starts a Microsoft-shaped IdP with consumer-safe defaults.
// redirectURI is the callback the provider has on file; it defaults to
// DefaultRedirectURI when omitted.
func NewMicrosoftIdP(redirectURI ...string) (*MicrosoftIdP, error) {
	priv, n, e, err := GenerateRSAKey()
	if err != nil {
		return nil, fmt.Errorf("generate microsoft idp key: %w", err)
	}
	idp := &MicrosoftIdP{
		ClientID:     "ms-idp-client-id",
		ClientSecret: "ms-idp-client-secret",
		TenantID:     "11111111-1111-1111-1111-111111111111",
		OID:          "ms-idp-oid-1",
		Subject:      "ms-idp-sub-1",
		Email:        "ms-user@example.com",
		Name:         "Microsoft IDP User",
		codes:        newAuthorizeCodes(),
		priv:         priv,
		kid:          "ms-idp-key-1",
		n:            n,
		e:            e,
	}
	idp.codes.registerClient(
		registeredRedirect(redirectURI),
		[]string{"openid", "profile", "email", "offline_access"},
		[]string{"openid", "email"},
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		idp.codes.authorize(w, r, idp.ClientID)
	})
	mux.HandleFunc("/token", idp.token)
	mux.HandleFunc("/keys", idp.keys)
	mux.HandleFunc("/userinfo", idp.userinfo)
	idp.Server = httptest.NewServer(mux)
	return idp, nil
}

// Close shuts the IdP down.
func (i *MicrosoftIdP) Close() { i.Server.Close() }

func (i *MicrosoftIdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" ||
		r.PostForm.Get("client_id") != i.ClientID ||
		r.PostForm.Get("client_secret") != i.ClientSecret {
		writeOAuthError(w, "invalid_client")
		return
	}
	ac, ok := i.codes.complete(r.PostForm)
	if !ok {
		writeOAuthError(w, "invalid_grant")
		return
	}
	issuer := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", i.TenantID)
	if i.Fault == FaultBadIssuer {
		issuer = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", msForeignTenant)
	}
	audience := i.ClientID
	if i.Fault == FaultBadAudience {
		audience = "ms-idp-other-client-id"
	}
	claims := map[string]any{
		"iss":                issuer,
		"aud":                audience,
		"sub":                i.Subject,
		"oid":                i.OID,
		"tid":                i.TenantID,
		"email":              i.Email,
		"preferred_username": i.Email,
		"name":               i.Name,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Unix(),
	}
	if i.edov != "" {
		claims["xms_edov"] = i.edov
	}
	if ac.nonce != "" {
		claims["nonce"] = ac.nonce
	}
	idToken, err := SignRS256JWT(i.priv, i.kid, claims)
	if err != nil {
		http.Error(w, "sign id_token", http.StatusInternalServerError)
		return
	}
	if i.Fault == FaultBadSignature {
		if idToken, err = corruptSignature(idToken); err != nil {
			http.Error(w, "corrupt id_token signature", http.StatusInternalServerError)
			return
		}
	}
	resp := map[string]any{
		"token_type":    "Bearer",
		"access_token":  msAccessToken,
		"expires_in":    3600,
		"refresh_token": "ms-idp-refresh-token",
	}
	if !i.OmitIDToken {
		resp["id_token"] = idToken
	}
	writeJSON(w, grantedScope(resp, ac))
}

// corruptSignature flips one signature byte. The header and claims stay intact,
// so signature verification is the only check that can reject the token.
func corruptSignature(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed jwt with %d parts", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("decode jwt signature: %w", err)
	}
	if len(sig) == 0 {
		return "", fmt.Errorf("jwt signature is empty")
	}
	sig[0] ^= 0xff
	return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (i *MicrosoftIdP) keys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"keys": []any{BuildJWK(i.kid, i.n, i.e)}})
}

// userinfo returns the documented Microsoft Graph /oidc/userinfo shape: no
// oid, no tid. The ID token carries those; this endpoint does not.
func (i *MicrosoftIdP) userinfo(w http.ResponseWriter, r *http.Request) {
	if bearerToken(r) != msAccessToken {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{
		"sub":         i.Subject,
		"name":        i.Name,
		"family_name": "MSTestUser",
		"given_name":  "IDP",
		"email":       i.Email,
		"picture":     "",
	})
}

const facebookGraphVersion = "v19.0"

// DebugToken is the /debug_token verdict. The zero AppID reports this app's own
// ID; naming another app is how the confused-deputy rejection is exercised.
type DebugToken struct {
	AppID   string
	IsValid bool
}

// FacebookIdP emulates the Graph authorize, token, debug_token, and /me surface.
type FacebookIdP struct {
	Server *httptest.Server

	AppID     string
	AppSecret string
	UserID    string
	Email     string
	Name      string
	AvatarURL string
	// Debug shapes the /debug_token verdict. The adapter must reject a token
	// that /debug_token does not attribute to its own app.
	Debug DebugToken

	codes *authorizeCodes
}

// NewFacebookIdP starts a Graph-shaped IdP with an email-returning profile.
// redirectURI is the callback the provider has on file; it defaults to
// DefaultRedirectURI when omitted.
func NewFacebookIdP(redirectURI ...string) *FacebookIdP {
	idp := &FacebookIdP{
		AppID:     "fb-idp-app-id",
		AppSecret: "fb-idp-app-secret",
		UserID:    "fb-idp-user-1",
		Email:     "fb-user@example.com",
		Name:      "Facebook IDP User",
		AvatarURL: "https://cdn.example.com/fb-avatar.png",
		Debug:     DebugToken{IsValid: true},
		codes:     newAuthorizeCodes(),
	}
	idp.codes.registerClient(
		registeredRedirect(redirectURI),
		[]string{"email", "public_profile"},
		[]string{"email"},
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/"+facebookGraphVersion+"/dialog/oauth", func(w http.ResponseWriter, r *http.Request) {
		idp.codes.authorize(w, r, idp.AppID)
	})
	mux.HandleFunc("/"+facebookGraphVersion+"/oauth/access_token", idp.token)
	mux.HandleFunc("/debug_token", idp.debugToken)
	mux.HandleFunc("/"+facebookGraphVersion+"/me", idp.me)
	idp.Server = httptest.NewServer(mux)
	return idp
}

// Close shuts the IdP down.
func (i *FacebookIdP) Close() { i.Server.Close() }

func (i *FacebookIdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" ||
		r.PostForm.Get("client_id") != i.AppID ||
		r.PostForm.Get("client_secret") != i.AppSecret {
		writeOAuthError(w, "invalid_client")
		return
	}
	if _, ok := i.codes.complete(r.PostForm); !ok {
		writeOAuthError(w, "invalid_grant")
		return
	}
	writeJSON(w, map[string]any{
		"access_token": i.userToken(),
		"token_type":   "bearer",
		"expires_in":   5184000,
	})
}

// debugToken enforces the Confused Deputy defense: the app token and its
// appsecret_proof must be the ones this app can produce.
func (i *FacebookIdP) debugToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	appToken := i.AppID + "|" + i.AppSecret
	if r.PostForm.Get("input_token") != i.userToken() ||
		r.PostForm.Get("access_token") != appToken ||
		r.PostForm.Get("appsecret_proof") != hmacHex(i.AppSecret, appToken) {
		writeOAuthError(w, "invalid_token")
		return
	}
	appID := i.Debug.AppID
	if appID == "" {
		appID = i.AppID
	}
	writeJSON(w, map[string]any{"data": map[string]any{
		"app_id":   appID,
		"type":     "USER",
		"is_valid": i.Debug.IsValid,
		"user_id":  i.UserID,
	}})
}

func (i *FacebookIdP) me(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" || token != i.userToken() {
		writeOAuthError(w, "invalid_token")
		return
	}
	// graph requires the proof in either the query or the X-AppSecret-Proof
	// header; the adapter sends the header, never the URL.
	proof := r.Header.Get("X-AppSecret-Proof")
	if proof == "" {
		proof = r.URL.Query().Get("appsecret_proof")
	}
	if proof != hmacHex(i.AppSecret, token) {
		writeOAuthError(w, "invalid appsecret_proof")
		return
	}
	writeJSON(w, map[string]any{
		"id":    i.UserID,
		"name":  i.Name,
		"email": i.Email,
		"picture": map[string]any{
			"data": map[string]any{"url": i.AvatarURL},
		},
	})
}

func (i *FacebookIdP) userToken() string { return "fb-idp-user-token-" + i.UserID }

// DiscordIdP emulates the Discord authorize, token, and /users/@me surface.
type DiscordIdP struct {
	Server *httptest.Server

	ClientID     string
	ClientSecret string
	UserID       string
	Username     string
	Email        string
	Verified     bool
	Avatar       string

	codes *authorizeCodes
}

// NewDiscordIdP starts a Discord-shaped IdP with a verified email profile.
// redirectURI is the callback the provider has on file; it defaults to
// DefaultRedirectURI when omitted.
func NewDiscordIdP(redirectURI ...string) *DiscordIdP {
	idp := &DiscordIdP{
		ClientID:     "discord-idp-client-id",
		ClientSecret: "discord-idp-client-secret",
		UserID:       "803511102246789120",
		Username:     "discord_idp_user",
		Email:        "discord-user@example.com",
		Verified:     true,
		Avatar:       "a_idp_avatar_hash",
		codes:        newAuthorizeCodes(),
	}
	idp.codes.registerClient(
		registeredRedirect(redirectURI),
		[]string{"identify", "email"},
		[]string{"email"},
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		idp.codes.authorize(w, r, idp.ClientID)
	})
	mux.HandleFunc("/api/v10/oauth2/token", idp.token)
	mux.HandleFunc("/api/v10/users/@me", idp.me)
	idp.Server = httptest.NewServer(mux)
	return idp
}

// Close shuts the IdP down.
func (i *DiscordIdP) Close() { i.Server.Close() }

func (i *DiscordIdP) accessToken() string { return "discord-idp-access-token" }

func (i *DiscordIdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" ||
		r.PostForm.Get("client_id") != i.ClientID ||
		r.PostForm.Get("client_secret") != i.ClientSecret {
		writeOAuthError(w, "invalid_client")
		return
	}
	ac, ok := i.codes.complete(r.PostForm)
	if !ok {
		writeOAuthError(w, "invalid_grant")
		return
	}
	writeJSON(w, grantedScope(map[string]any{
		"access_token":  i.accessToken(),
		"token_type":    "Bearer",
		"expires_in":    604800,
		"refresh_token": "discord-idp-refresh-token",
	}, ac))
}

func (i *DiscordIdP) me(w http.ResponseWriter, r *http.Request) {
	if bearerToken(r) != i.accessToken() {
		writeOAuthError(w, "invalid_token")
		return
	}
	writeJSON(w, map[string]any{
		"id":            i.UserID,
		"username":      i.Username,
		"discriminator": "0",
		"verified":      i.Verified,
		"avatar":        i.Avatar,
		"email":         i.Email,
	})
}

// XIdP emulates the X authorize, token, and /2/users/me surface. The profile
// carries no email, matching the API without the email scope.
type XIdP struct {
	Server *httptest.Server

	ClientID     string
	ClientSecret string
	UserID       string
	Username     string
	Avatar       string

	codes *authorizeCodes
}

// NewXIdP starts an X-shaped IdP.
// redirectURI is the callback the provider has on file; it defaults to
// DefaultRedirectURI when omitted.
func NewXIdP(redirectURI ...string) *XIdP {
	idp := &XIdP{
		ClientID:     "x-idp-client-id",
		ClientSecret: "x-idp-client-secret",
		UserID:       "x-idp-user-1",
		Username:     "x_idp_user",
		Avatar:       "https://pbs.twimg.com/idp_normal.jpg",
		codes:        newAuthorizeCodes(),
	}
	idp.codes.registerClient(
		registeredRedirect(redirectURI),
		[]string{"users.read", "tweet.read", "offline.access"},
		[]string{"users.read"},
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/i/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		idp.codes.authorize(w, r, idp.ClientID)
	})
	mux.HandleFunc("/2/oauth2/token", idp.token)
	mux.HandleFunc("/2/users/me", idp.me)
	idp.Server = httptest.NewServer(mux)
	return idp
}

// Close shuts the IdP down.
func (i *XIdP) Close() { i.Server.Close() }

func (i *XIdP) accessToken() string { return "x-idp-access-token" }

func (i *XIdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	// RFC 6749 §2.3.1: Basic auth with query-escaped credentials and no
	// client_id in the body.
	want := "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(i.ClientID)+":"+url.QueryEscape(i.ClientSecret)))
	if r.Header.Get("Authorization") != want || r.PostForm.Get("client_id") != "" {
		writeOAuthError(w, "invalid_client")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeOAuthError(w, "invalid_grant")
		return
	}
	ac, ok := i.codes.complete(r.PostForm)
	if !ok {
		writeOAuthError(w, "invalid_grant")
		return
	}
	writeJSON(w, grantedScope(map[string]any{
		"token_type":    "bearer",
		"access_token":  i.accessToken(),
		"expires_in":    7200,
		"refresh_token": "x-idp-refresh-token",
	}, ac))
}

func (i *XIdP) me(w http.ResponseWriter, r *http.Request) {
	if bearerToken(r) != i.accessToken() {
		writeOAuthError(w, "invalid_token")
		return
	}
	writeJSON(w, map[string]any{"data": map[string]any{
		"id":                i.UserID,
		"name":              i.Username,
		"username":          i.Username,
		"profile_image_url": i.Avatar,
		"verified":          true,
	}})
}

// authorizeCode is the PKCE challenge and OIDC nonce bound to an issued code,
// plus the redirect_uri and scope the authorize leg granted.
type authorizeCode struct {
	challenge   string
	nonce       string
	redirectURI string
	scope       string
}

// authorizeCodes issues single-use authorization codes bound to the PKCE
// challenge observed at authorize time.
type authorizeCodes struct {
	mu    sync.Mutex
	codes map[string]authorizeCode

	// The single client this IdP serves. An empty redirectURI rejects every
	// authorize request, so a forgotten registration fails closed.
	redirectURI    string
	supported      map[string]struct{}
	requiredScopes []string
}

func newAuthorizeCodes() *authorizeCodes {
	return &authorizeCodes{codes: make(map[string]authorizeCode)}
}

// registerClient pins the callback and scope set the provider has on file.
// Authorize grants at most this set, and required scopes must be requested.
func (c *authorizeCodes) registerClient(redirectURI string, supported, required []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.redirectURI = redirectURI
	c.supported = make(map[string]struct{}, len(supported))
	for _, s := range supported {
		c.supported[s] = struct{}{}
	}
	c.requiredScopes = append([]string(nil), required...)
}

// redirectTarget validates the request's redirect_uri against the client's
// registration and returns the registered callback rebuilt from its validated
// components. A relative, opaque, or non-http(s) target is rejected, as is any
// scheme, host, or path the client did not register; the request value never
// reaches http.Redirect.
func (c *authorizeCodes) redirectTarget(requested string) (*url.URL, bool) {
	registered, err := url.Parse(c.redirectURI)
	if err != nil || !absoluteHTTP(registered) {
		return nil, false
	}
	target, err := url.Parse(requested)
	if err != nil || !absoluteHTTP(target) {
		return nil, false
	}
	if target.Scheme != registered.Scheme ||
		target.User.String() != registered.User.String() ||
		target.Host != registered.Host ||
		target.Path != registered.Path ||
		target.RawQuery != registered.RawQuery ||
		target.Fragment != registered.Fragment {
		return nil, false
	}
	return registered, true
}

// absoluteHTTP rejects opaque, relative, and non-http(s) redirect values.
func absoluteHTTP(u *url.URL) bool {
	if u == nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}

// authorize validates the adapter's authorize request, records its challenge
// and nonce, and redirects back to redirect_uri with a code.
func (c *authorizeCodes) authorize(w http.ResponseWriter, r *http.Request, clientID string) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != clientID {
		http.Error(w, "invalid authorize request", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "PKCE S256 required", http.StatusBadRequest)
		return
	}
	redirectRaw := q.Get("redirect_uri")

	c.mu.Lock()
	redirect, ok := c.redirectTarget(redirectRaw)
	if !ok {
		c.mu.Unlock()
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	requested := strings.Fields(q.Get("scope"))
	for _, s := range requested {
		if _, ok := c.supported[s]; !ok {
			c.mu.Unlock()
			http.Error(w, "unsupported scope", http.StatusBadRequest)
			return
		}
	}
	for _, s := range c.requiredScopes {
		if !slices.Contains(requested, s) {
			c.mu.Unlock()
			http.Error(w, "required scope missing", http.StatusBadRequest)
			return
		}
	}
	code, err := freshCode()
	if err != nil {
		c.mu.Unlock()
		http.Error(w, "generate code", http.StatusInternalServerError)
		return
	}
	c.codes[code] = authorizeCode{
		challenge:   q.Get("code_challenge"),
		nonce:       q.Get("nonce"),
		redirectURI: redirectRaw,
		scope:       q.Get("scope"),
	}
	c.mu.Unlock()

	vals := redirect.Query()
	vals.Set("code", code)
	vals.Set("state", q.Get("state"))
	redirect.RawQuery = vals.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// redeem consumes code and reports whether verifier hashes to its challenge.
func (c *authorizeCodes) redeem(code, verifier string) (authorizeCode, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ac, ok := c.codes[code]
	if !ok {
		return authorizeCode{}, false
	}
	delete(c.codes, code)
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != ac.challenge {
		return authorizeCode{}, false
	}
	return ac, true
}

// complete redeems code and enforces that the token request replays what the
// authorize leg issued. RFC 6749 §4.1.3 binds both: redirect_uri must match the
// authorize request, and a scope, when the client repeats it, must not differ
// from what was granted.
func (c *authorizeCodes) complete(form url.Values) (authorizeCode, bool) {
	ac, ok := c.redeem(form.Get("code"), form.Get("code_verifier"))
	if !ok {
		return authorizeCode{}, false
	}
	if form.Get("redirect_uri") != ac.redirectURI {
		return authorizeCode{}, false
	}
	if scope := form.Get("scope"); scope != "" && scope != ac.scope {
		return authorizeCode{}, false
	}
	return ac, true
}

// grantedScope reports the scope the authorize leg actually issued instead of
// echoing a scope the client never asked for.
func grantedScope(payload map[string]any, ac authorizeCode) map[string]any {
	if ac.scope != "" {
		payload["scope"] = ac.scope
	}
	return payload
}

func freshCode() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func hmacHex(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimPrefix(h, prefix)
}
