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
	"strings"
	"sync"
	"time"
)

// IdPs below emulate each provider's HTTP surface (authorize, token, userinfo,
// JWKS) so tests can drive the real adapter instead of a Provider stub: point
// the adapter at Server with oauth.WithEndpoints. The authorize leg validates
// the adapter's PKCE S256 request and the token leg redeems the code once
// against that challenge, so a broken authorize URL or a dropped verifier
// fails the journey rather than passing through a mock.

const msAccessToken = "ms-idp-access-token"

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
	// EDov is the xms_edov domain-ownership attestation; "1" marks the
	// address domain as verified by the tenant.
	EDov string

	codes *authorizeCodes
	priv  *rsa.PrivateKey
	kid   string
	n     string
	e     string
}

// NewMicrosoftIdP starts a Microsoft-shaped IdP with consumer-safe defaults.
func NewMicrosoftIdP() (*MicrosoftIdP, error) {
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
		EDov:         "1",
		codes:        newAuthorizeCodes(),
		priv:         priv,
		kid:          "ms-idp-key-1",
		n:            n,
		e:            e,
	}
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
	ac, ok := i.codes.redeem(r.PostForm.Get("code"), r.PostForm.Get("code_verifier"))
	if !ok {
		writeOAuthError(w, "invalid_grant")
		return
	}
	claims := map[string]any{
		"iss":                fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", i.TenantID),
		"aud":                i.ClientID,
		"sub":                i.Subject,
		"oid":                i.OID,
		"tid":                i.TenantID,
		"email":              i.Email,
		"preferred_username": i.Email,
		"name":               i.Name,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Unix(),
	}
	if i.EDov != "" {
		claims["xms_edov"] = i.EDov
	}
	if ac.nonce != "" {
		claims["nonce"] = ac.nonce
	}
	idToken, err := SignRS256JWT(i.priv, i.kid, claims)
	if err != nil {
		http.Error(w, "sign id_token", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"token_type":    "Bearer",
		"access_token":  msAccessToken,
		"id_token":      idToken,
		"expires_in":    3600,
		"refresh_token": "ms-idp-refresh-token",
	})
}

func (i *MicrosoftIdP) keys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"keys": []any{BuildJWK(i.kid, i.n, i.e)}})
}

func (i *MicrosoftIdP) userinfo(w http.ResponseWriter, r *http.Request) {
	if bearerToken(r) != msAccessToken {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{
		"sub":   i.Subject,
		"oid":   i.OID,
		"tid":   i.TenantID,
		"email": i.Email,
		"name":  i.Name,
	})
}

const facebookGraphVersion = "v19.0"

// FacebookIdP emulates the Graph authorize, token, debug_token, and /me surface.
type FacebookIdP struct {
	Server *httptest.Server

	AppID     string
	AppSecret string
	UserID    string
	Email     string
	Name      string
	AvatarURL string

	codes *authorizeCodes
}

// NewFacebookIdP starts a Graph-shaped IdP with an email-returning profile.
func NewFacebookIdP() *FacebookIdP {
	idp := &FacebookIdP{
		AppID:     "fb-idp-app-id",
		AppSecret: "fb-idp-app-secret",
		UserID:    "fb-idp-user-1",
		Email:     "fb-user@example.com",
		Name:      "Facebook IDP User",
		AvatarURL: "https://cdn.example.com/fb-avatar.png",
		codes:     newAuthorizeCodes(),
	}
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
	if _, ok := i.codes.redeem(r.PostForm.Get("code"), r.PostForm.Get("code_verifier")); !ok {
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
	writeJSON(w, map[string]any{"data": map[string]any{
		"app_id":   i.AppID,
		"type":     "USER",
		"is_valid": true,
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
func NewDiscordIdP() *DiscordIdP {
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
	if _, ok := i.codes.redeem(r.PostForm.Get("code"), r.PostForm.Get("code_verifier")); !ok {
		writeOAuthError(w, "invalid_grant")
		return
	}
	writeJSON(w, map[string]any{
		"access_token":  i.accessToken(),
		"token_type":    "Bearer",
		"expires_in":    604800,
		"refresh_token": "discord-idp-refresh-token",
		"scope":         "identify email",
	})
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
func NewXIdP() *XIdP {
	idp := &XIdP{
		ClientID:     "x-idp-client-id",
		ClientSecret: "x-idp-client-secret",
		UserID:       "x-idp-user-1",
		Username:     "x_idp_user",
		Avatar:       "https://pbs.twimg.com/idp_normal.jpg",
		codes:        newAuthorizeCodes(),
	}
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
	if _, ok := i.codes.redeem(r.PostForm.Get("code"), r.PostForm.Get("code_verifier")); !ok {
		writeOAuthError(w, "invalid_grant")
		return
	}
	writeJSON(w, map[string]any{
		"token_type":    "bearer",
		"access_token":  i.accessToken(),
		"expires_in":    7200,
		"refresh_token": "x-idp-refresh-token",
		"scope":         "users.read",
	})
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

// authorizeCode is the PKCE challenge and OIDC nonce bound to an issued code.
type authorizeCode struct {
	challenge string
	nonce     string
}

// authorizeCodes issues single-use authorization codes bound to the PKCE
// challenge observed at authorize time.
type authorizeCodes struct {
	mu    sync.Mutex
	codes map[string]authorizeCode
}

func newAuthorizeCodes() *authorizeCodes {
	return &authorizeCodes{codes: make(map[string]authorizeCode)}
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
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || redirect.Scheme == "" || redirect.Host == "" {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	code, err := freshCode()
	if err != nil {
		http.Error(w, "generate code", http.StatusInternalServerError)
		return
	}
	c.mu.Lock()
	c.codes[code] = authorizeCode{challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
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
