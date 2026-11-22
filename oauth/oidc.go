package oauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/kaiizer777/go-auth/errors"
)

const (
	defaultOIDCDiscoveryTTL = 24 * time.Hour
	defaultJWKSTTL          = 24 * time.Hour
	minRSAModulusBits       = 2048
	maxRSAExponent          = 1<<31 - 1
)

// OIDCDiscovery represents parsed metadata from /.well-known/openid-configuration.
type OIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// JWKKey represents a single RSA JSON Web Key.
type JWKKey struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	Alg string   `json:"alg"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c,omitempty"`
}

// JWKDoc represents a JSON Web Key Set document.
type JWKDoc struct {
	Keys []JWKKey `json:"keys"`
}

// JWKSKeyRetriever retrieves an RSA public key by kid.
type JWKSKeyRetriever interface {
	GetKey(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// JWKSManager manages dynamic caching, singleflight deduplication, and rollover refresh for JWKS.
type JWKSManager struct {
	jwksURL string
	client  *http.Client
	ttl     time.Duration

	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	expires time.Time
	gen     uint64
	sf      singleflight.Group
}

// NewJWKSManager constructs a thread-safe JWKS manager.
func NewJWKSManager(jwksURL string, client *http.Client, ttl time.Duration) *JWKSManager {
	if client == nil {
		client = newHTTPClient()
	}
	if ttl <= 0 {
		ttl = defaultJWKSTTL
	}
	return &JWKSManager{
		jwksURL: jwksURL,
		client:  client,
		ttl:     ttl,
		keys:    make(map[string]*rsa.PublicKey),
	}
}

// GetKey retrieves the RSA public key for kid, refreshing if missing or expired.
func (m *JWKSManager) GetKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	m.mu.RLock()
	key, ok := m.keys[kid]
	fresh := time.Now().Before(m.expires)
	m.mu.RUnlock()
	if ok && fresh {
		return key, nil
	}

	// Singleflight deduplication across concurrent cache misses
	_, err, _ := m.sf.Do("jwks_refresh", func() (any, error) {
		m.mu.RLock()
		_, ok := m.keys[kid]
		fresh := time.Now().Before(m.expires)
		m.mu.RUnlock()
		if ok && fresh {
			return nil, nil
		}
		return nil, m.refresh(ctx)
	})
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	if key, ok := m.keys[kid]; ok {
		m.mu.RUnlock()
		return key, nil
	}
	m.mu.RUnlock()

	// If missing after joiner flight, refresh once directly to handle key rollover published during flight
	if err := m.refresh(ctx); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if key, ok := m.keys[kid]; ok {
		return key, nil
	}
	return nil, errors.New(errors.CodeOAuthIDTokenInvalid, fmt.Sprintf("signing key with kid %q not found in jwks", kid), nil)
}

func (m *JWKSManager) refresh(ctx context.Context) error {
	m.mu.RLock()
	startGen := m.gen
	m.mu.RUnlock()

	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), oauthHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, m.jwksURL, nil)
	if err != nil {
		return errors.New(errors.CodeOAuthProviderError, "oauth jwks request failed", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return errors.New(errors.CodeOAuthProviderError, "oauth jwks fetch failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, oauthBodyLimit))
		return errors.New(errors.CodeOAuthProviderError, fmt.Sprintf("oauth provider jwks responded with status %d", resp.StatusCode), nil)
	}

	var doc JWKDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, oauthBodyLimit)).Decode(&doc); err != nil {
		return errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid jwks response", err)
	}

	parsedKeys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kid == "" {
			continue
		}
		pubKey, ok := parseRSAPublicKey(k.N, k.E)
		if ok {
			parsedKeys[k.Kid] = pubKey
		}
	}

	if len(parsedKeys) == 0 {
		return errors.New(errors.CodeOAuthProviderError, "oauth provider returned jwks with no valid rsa keys", nil)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gen != startGen {
		return nil
	}
	m.keys = parsedKeys
	m.expires = time.Now().Add(m.ttl)
	m.gen++
	return nil
}

// parseRSAPublicKey converts base64url-encoded modulus (n) and exponent (e) to *rsa.PublicKey.
func parseRSAPublicKey(nRaw, eRaw string) (*rsa.PublicKey, bool) {
	nb, err := base64.RawURLEncoding.DecodeString(nRaw)
	if err != nil || len(nb) == 0 {
		return nil, false
	}
	n := new(big.Int).SetBytes(nb)
	if n.BitLen() < minRSAModulusBits {
		return nil, false
	}

	eb, err := base64.RawURLEncoding.DecodeString(eRaw)
	if err != nil || len(eb) == 0 {
		return nil, false
	}
	e := new(big.Int).SetBytes(eb)
	if e.Cmp(big.NewInt(2)) < 0 || e.Cmp(big.NewInt(maxRSAExponent)) > 0 {
		return nil, false
	}

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, true
}

// FetchOIDCDiscovery fetches and parses the OpenID Connect discovery document.
func FetchOIDCDiscovery(ctx context.Context, client *http.Client, discoveryURL string) (*OIDCDiscovery, error) {
	if client == nil {
		client = newHTTPClient()
	}
	ctx, cancel := context.WithTimeout(ctx, oauthHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "failed to build oidc discovery request", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oidc discovery request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, oauthBodyLimit))
		return nil, errors.New(errors.CodeOAuthProviderError, fmt.Sprintf("oidc discovery endpoint responded with status %d", resp.StatusCode), nil)
	}

	var disc OIDCDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, oauthBodyLimit)).Decode(&disc); err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "invalid oidc discovery response", err)
	}
	if disc.AuthorizationEndpoint == "" || disc.TokenEndpoint == "" || disc.JWKSURI == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "oidc discovery document missing required endpoints", nil)
	}
	return &disc, nil
}

// VerifyRS256JWT cryptographically validates an RS256 JWT using keys from keyRetriever and returns the decoded payload map.
func VerifyRS256JWT(ctx context.Context, rawJWT string, keyRetriever JWKSKeyRetriever) (map[string]any, error) {
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "malformed jwt token structure", nil)
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "invalid jwt header encoding", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "invalid jwt header json", err)
	}
	if header.Alg != "RS256" {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, fmt.Sprintf("unsupported jwt alg %q, expected RS256", header.Alg), nil)
	}
	if header.Kid == "" {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "jwt header missing kid", nil)
	}

	pubKey, err := keyRetriever.GetKey(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "invalid jwt signature encoding", err)
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "jwt signature verification failed", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "invalid jwt payload encoding", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "invalid jwt payload json", err)
	}

	return claims, nil
}
