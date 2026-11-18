package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

const (
	appleAuthEndpoint  = "https://appleid.apple.com/auth/authorize"
	appleTokenEndpoint = "https://appleid.apple.com/auth/token"
	appleJWKSEndpoint  = "https://appleid.apple.com/auth/keys"
	appleIssuer        = "https://appleid.apple.com"
	appleJWKSTTL       = 24 * time.Hour
)

// AppleProvider implements Sign in with Apple (form_post + RS256 id_token).
type AppleProvider struct {
	cfg      config.ProviderConfig
	client   *http.Client
	authURL  string
	tokenURL string
	jwksURL  string

	mu          sync.RWMutex
	jwks        map[string]*rsa.PublicKey
	jwksExpires time.Time
}

// NewAppleProvider builds an Apple provider with production endpoints.
func NewAppleProvider(cfg config.ProviderConfig) *AppleProvider {
	return &AppleProvider{
		cfg:      cfg,
		client:   newHTTPClient(),
		authURL:  appleAuthEndpoint,
		tokenURL: appleTokenEndpoint,
		jwksURL:  appleJWKSEndpoint,
	}
}

// ID returns the canonical provider slug.
func (p *AppleProvider) ID() string { return "apple" }

// AuthURL builds the Apple authorization URL with form_post response mode and PKCE S256.
func (p *AppleProvider) AuthURL(state, codeChallenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("response_mode", "form_post")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", scopesOrDefault(p.cfg.Scopes, "name", "email"))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	return p.authURL + "?" + q.Encode()
}

// clientSecret returns the static secret or a freshly minted ES256 JWT.
func (p *AppleProvider) clientSecret() (string, error) {
	if p.cfg.ClientSecret != "" {
		return p.cfg.ClientSecret, nil
	}
	return appleClientSecretJWT(p.cfg.TeamID, p.cfg.KeyID, p.cfg.ClientID, p.cfg.PrivateKey, time.Now())
}

// ExchangeCode trades the authorization code plus PKCE verifier for tokens.
func (p *AppleProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	secret, err := p.clientSecret()
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", secret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", p.cfg.RedirectURL)
	form.Set("code_verifier", codeVerifier)
	return postTokenForm(ctx, p.client, p.tokenURL, form.Encode())
}

// FetchUserInfo verifies the id_token signature and claims, then normalizes them.
func (p *AppleProvider) FetchUserInfo(ctx context.Context, tokens *TokenResponse) (*UserInfo, error) {
	if tokens == nil || tokens.IDToken == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned empty id token", nil)
	}
	claims, err := p.verifyIDToken(ctx, tokens.IDToken)
	if err != nil {
		return nil, err
	}
	return &UserInfo{
		ProviderID:     "apple",
		ProviderUserID: claims.sub,
		Email:          claims.email,
		EmailVerified:  claims.verified,
	}, nil
}

// appleClientSecretJWT mints a 5-minute ES256 client-secret JWT using stdlib only.
func appleClientSecretJWT(teamID, keyID, clientID, privateKeyPEM string, now time.Time) (string, error) {
	fail := func(err error) (string, error) {
		return "", errors.New(errors.CodeOAuthProviderError, "oauth client secret signing failed", err)
	}
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return fail(nil)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fail(err)
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return fail(nil)
	}
	// ES256 is P-256 with a 64-byte signature. A P-384 key passes the type
	// check but mints a 96-byte signature labeled ES256 that can never verify.
	if ecKey.Curve != elliptic.P256() {
		return "", errors.New(errors.CodeInvalidConfig, "oauth apple private key must use P-256 for ES256", nil)
	}
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": keyID})
	if err != nil {
		return fail(err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss": teamID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"aud": appleIssuer,
		"sub": clientID,
	})
	if err != nil {
		return fail(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sigASN1, err := ecKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return fail(err)
	}
	var rs struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sigASN1, &rs); err != nil {
		return fail(err)
	}
	size := (ecKey.Curve.Params().BitSize + 7) / 8
	rb, sb := rs.R.Bytes(), rs.S.Bytes()
	if len(rb) > size || len(sb) > size {
		return fail(nil)
	}
	sig := make([]byte, 2*size)
	copy(sig[size-len(rb):size], rb)
	copy(sig[2*size-len(sb):], sb)
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

type appleClaims struct {
	sub      string
	email    string
	verified bool
}

// verifyIDToken checks the RS256 signature via JWKS and enforces strict claims.
func (p *AppleProvider) verifyIDToken(ctx context.Context, idToken string) (*appleClaims, error) {
	fail := func(err error) (*appleClaims, error) {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth id token verification failed", err)
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return fail(nil)
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fail(err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return fail(err)
	}
	if header.Alg != "RS256" || header.Kid == "" {
		return fail(nil)
	}
	key, err := p.jwksKey(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fail(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return fail(err)
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fail(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return fail(err)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return fail(nil)
	}
	if iss, _ := claims["iss"].(string); iss != appleIssuer {
		return fail(nil)
	}
	if !appleAudMatches(claims["aud"], p.cfg.ClientID) {
		return fail(nil)
	}
	exp, ok := claims["exp"].(float64)
	if !ok || int64(exp) <= time.Now().Unix() {
		return fail(nil)
	}
	email, _ := claims["email"].(string)
	return &appleClaims{sub: sub, email: email, verified: appleVerifiedFlag(claims["email_verified"])}, nil
}

// appleAudMatches accepts a string aud or a string-array aud containing clientID.
func appleAudMatches(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// appleVerifiedFlag normalizes boolean true or string "true".
func appleVerifiedFlag(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	default:
		return false
	}
}

// jwksKey returns the cached key, refreshing once on unknown kid or stale cache.
func (p *AppleProvider) jwksKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	p.mu.RLock()
	key, ok := p.jwks[kid]
	fresh := time.Now().Before(p.jwksExpires)
	p.mu.RUnlock()
	if ok && fresh {
		return key, nil
	}
	if err := p.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if key, ok := p.jwks[kid]; ok {
		return key, nil
	}
	return nil, errors.New(errors.CodeOAuthProviderError, "oauth id token verification failed", nil)
}

// refreshJWKS reloads Apple's public keys with a 24h TTL.
func (p *AppleProvider) refreshJWKS(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, oauthHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.jwksURL, nil)
	if err != nil {
		return errors.New(errors.CodeOAuthProviderError, "oauth jwks fetch failed", err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.New(errors.CodeOAuthProviderError, "oauth jwks fetch failed", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, oauthBodyLimit))
		return errors.New(errors.CodeOAuthProviderError, fmt.Sprintf("oauth provider responded with status %d", resp.StatusCode), nil)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, oauthBodyLimit)).Decode(&doc); err != nil {
		return errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		if k.Kid == "" || len(nb) == 0 || len(eb) == 0 {
			continue
		}
		e := int(new(big.Int).SetBytes(eb).Int64())
		if e <= 0 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	}
	p.mu.Lock()
	p.jwks = keys
	p.jwksExpires = time.Now().Add(appleJWKSTTL)
	p.mu.Unlock()
	return nil
}
