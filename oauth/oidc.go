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
	"net"
	"net/http"
	"net/url"
	"regexp"
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
	// jwksStaleGracePeriod caps how long expired keys stay usable when refresh fails.
	jwksStaleGracePeriod = time.Hour
	// unknownKidCooldown caps negative caching for kids still missing after a refresh.
	unknownKidCooldown = time.Minute
	// unknownKidMaxNegEntries bounds the per-kid negative cache; unknown kids
	// are attacker-controlled so the map must not grow without limit.
	unknownKidMaxNegEntries = 128
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
	Kty    string   `json:"kty"`
	Use    string   `json:"use"`
	Kid    string   `json:"kid"`
	Alg    string   `json:"alg"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	Issuer string   `json:"issuer,omitempty"` // optional issuer/tenant scope advertised per key
	X5c    []string `json:"x5c,omitempty"`
}

// JWKDoc represents a JSON Web Key Set document.
type JWKDoc struct {
	Keys []JWKKey `json:"keys"`
}

// JWKSKey is a signing key together with the issuer scope advertised by its JWKS entry.
type JWKSKey struct {
	Key    *rsa.PublicKey
	Issuer string
}

// JWKSKeyRetriever retrieves a signing key and its issuer scope by kid.
type JWKSKeyRetriever interface {
	GetKey(ctx context.Context, kid string) (JWKSKey, error)
}

// JWKSManager manages dynamic caching, singleflight deduplication, and rollover refresh for JWKS.
type JWKSManager struct {
	jwksURL string
	client  *http.Client
	ttl     time.Duration

	mu      sync.RWMutex
	keys    map[string]JWKSKey
	expires time.Time
	gen     uint64
	sf      singleflight.Group
	// misses negatively caches kids confirmed missing after a refresh,
	// keyed per kid so one unknown kid never suppresses fetch for another
	// (e.g. a genuine rotation). Guarded by mu.
	misses map[string]time.Time
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
		keys:    make(map[string]JWKSKey),
		misses:  make(map[string]time.Time),
	}
}

// GetKey retrieves the signing key for kid, refreshing if missing or expired.
// A failed refresh serves last-known-good keys within jwksStaleGracePeriod;
// kids confirmed missing are negatively cached for unknownKidCooldown.
func (m *JWKSManager) GetKey(ctx context.Context, kid string) (JWKSKey, error) {
	m.mu.RLock()
	key, ok := m.keys[kid]
	fresh := time.Now().Before(m.expires)
	missExp, neg := m.misses[kid]
	m.mu.RUnlock()
	if ok && fresh {
		return key, nil
	}
	if !ok && neg && time.Now().Before(missExp) {
		return JWKSKey{}, errUnknownKid(kid)
	}

	// Singleflight deduplication across concurrent cache misses.
	if _, err := m.refreshFlight("jwks_refresh", kid, ctx); err != nil {
		return m.staleOrError(kid, err)
	}
	// Only the committed document may authorize a kid. A superseded fetch is
	// discarded even when it lists the kid: a later flight already published
	// the current set, and a kid absent from it must not authenticate.
	if key, ok := m.cachedKey(kid); ok {
		m.clearMiss(kid)
		return key, nil
	}

	// The kid may have rotated in after this flight's fetch, so confirm against
	// one rollover fetch before recording a miss.
	if _, err := m.refreshFlight("jwks_rollover_refresh", kid, ctx); err != nil {
		if key, ok := m.cachedKey(kid); ok {
			m.clearMiss(kid)
			return key, nil
		}
		// A fresh committed set that lacks the kid is an auth failure, not a
		// provider outage; only a stale set can be a server-side error.
		if m.cacheFresh() {
			m.recordMiss(kid)
			return JWKSKey{}, errUnknownKid(kid)
		}
		return m.staleOrError(kid, err)
	}
	if key, ok := m.cachedKey(kid); ok {
		m.clearMiss(kid)
		return key, nil
	}
	m.recordMiss(kid)
	return JWKSKey{}, errUnknownKid(kid)
}

// errUnknownKid is an authentication failure: the token names a kid the
// provider's current signing set does not contain.
func errUnknownKid(kid string) error {
	return errors.New(errors.CodeOAuthIDTokenInvalid, fmt.Sprintf("signing key with kid %q not found in jwks", kid), nil)
}

// cacheFresh reports whether the committed key set is still within its TTL.
func (m *JWKSManager) cacheFresh() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return time.Now().Before(m.expires)
}

// staleOrError serves the last-known-good key while it is still inside the
// stale grace period, so a transient JWKS outage degrades to older keys
// instead of locking out every login. Beyond the grace period the refresh
// error is returned.
func (m *JWKSManager) staleOrError(kid string, refreshErr error) (JWKSKey, error) {
	m.mu.RLock()
	key, ok := m.keys[kid]
	expired := m.expires
	m.mu.RUnlock()
	if ok && time.Now().Before(expired.Add(jwksStaleGracePeriod)) {
		return key, nil
	}
	return JWKSKey{}, refreshErr
}

// clearMiss drops a negative-cache entry once the kid resolves again.
func (m *JWKSManager) clearMiss(kid string) {
	m.mu.Lock()
	delete(m.misses, kid)
	m.mu.Unlock()
}

// recordMiss negatively caches a kid confirmed missing after a full refresh
// cycle, so repeated lookups for attacker-controlled kids do not each cost
// two upstream fetches. The map is bounded and expired entries are swept,
// because unknown kids must not grow it without limit.
func (m *JWKSManager) recordMiss(kid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.misses == nil {
		m.misses = make(map[string]time.Time)
	}
	now := time.Now()
	for k, exp := range m.misses {
		if !now.Before(exp) {
			delete(m.misses, k)
		}
	}
	if len(m.misses) >= unknownKidMaxNegEntries {
		for k := range m.misses {
			delete(m.misses, k)
			break
		}
	}
	m.misses[kid] = now.Add(unknownKidCooldown)
}

func (m *JWKSManager) cachedKey(kid string) (JWKSKey, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Call sites run after a refreshFlight, so a stale entry is not expected
	// today; enforcing the bound keeps the freshness invariant local to the read.
	if !time.Now().Before(m.expires) {
		return JWKSKey{}, false
	}
	key, ok := m.keys[kid]
	return key, ok
}

// refreshFlight runs one deduplicated refresh unless the key is already cached and fresh.
// The fetched set is returned even when another flight committed first.
func (m *JWKSManager) refreshFlight(name, kid string, ctx context.Context) (map[string]JWKSKey, error) {
	v, err, _ := m.sf.Do(name, func() (any, error) {
		m.mu.RLock()
		_, ok := m.keys[kid]
		fresh := time.Now().Before(m.expires)
		m.mu.RUnlock()
		if ok && fresh {
			return nil, nil
		}
		return m.refresh(ctx)
	})
	if err != nil {
		return nil, err
	}
	fetched, _ := v.(map[string]JWKSKey)
	return fetched, nil
}

func (m *JWKSManager) refresh(ctx context.Context) (map[string]JWKSKey, error) {
	m.mu.RLock()
	startGen := m.gen
	m.mu.RUnlock()

	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), oauthHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, m.jwksURL, nil)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth jwks request failed", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth jwks fetch failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, oauthBodyLimit))
		return nil, errors.New(errors.CodeOAuthProviderError, fmt.Sprintf("oauth provider jwks responded with status %d", resp.StatusCode), nil)
	}

	var doc JWKDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, oauthBodyLimit)).Decode(&doc); err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid jwks response", err)
	}

	parsedKeys := make(map[string]JWKSKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kid == "" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pubKey, ok := parseRSAPublicKey(k.N, k.E)
		if ok {
			parsedKeys[k.Kid] = JWKSKey{Key: pubKey, Issuer: k.Issuer}
		}
	}

	if len(parsedKeys) == 0 {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned jwks with no valid rsa keys", nil)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// gen flags that another flight committed since the snapshot. It is not an
	// ordering guarantee, so a superseded response is never written over the cache;
	// the caller that fetched it decides whether it satisfies its own request.
	if m.gen == startGen {
		m.keys = parsedKeys
		m.expires = time.Now().Add(m.ttl)
		m.gen++
		for kid := range parsedKeys {
			delete(m.misses, kid)
		}
	}
	return parsedKeys, nil
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
	if err := validateDiscoveryDocument(discoveryURL, &disc); err != nil {
		return nil, err
	}
	return &disc, nil
}

// validateDiscoveryDocument pins a discovery document to its origin: issuer
// must match the discovery URL origin and jwks_uri must be https, except for
// loopback hosts where plain http test servers live.
func validateDiscoveryDocument(discoveryURL string, disc *OIDCDiscovery) error {
	du, err := url.Parse(discoveryURL)
	if err != nil || du.Scheme == "" || du.Host == "" {
		return errors.New(errors.CodeOAuthProviderError, "invalid oidc discovery url", err)
	}
	if disc.Issuer == "" {
		return errors.New(errors.CodeOAuthProviderError, "oidc discovery document missing issuer", nil)
	}
	iss, err := url.Parse(disc.Issuer)
	if err != nil || iss.Scheme == "" || iss.Host == "" {
		return errors.New(errors.CodeOAuthProviderError, "oidc discovery document has invalid issuer", err)
	}
	if !strings.EqualFold(iss.Scheme, du.Scheme) || !strings.EqualFold(iss.Host, du.Host) {
		return errors.New(errors.CodeOAuthProviderError, "oidc discovery issuer does not match discovery url origin", nil)
	}
	ju, err := url.Parse(disc.JWKSURI)
	if err != nil || ju.Scheme == "" || ju.Host == "" {
		return errors.New(errors.CodeOAuthProviderError, "oidc discovery document has invalid jwks_uri", err)
	}
	if ju.Scheme != "https" && !isLoopbackHTTP(ju) {
		return errors.New(errors.CodeOAuthProviderError, "oidc discovery jwks_uri must use https", nil)
	}
	return nil
}

func isLoopbackHTTP(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// VerifyRS256JWT verifies the RS256 signature of rawJWT and returns its claims.
// Signature-only: it does NOT validate exp, aud, iss, or nonce. Callers must
// validate claims for their authority; see MicrosoftProvider.VerifyIDToken.
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
	if pubKey.Key == nil {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, fmt.Sprintf("signing key with kid %q has no key material", header.Kid), nil)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New(errors.CodeOAuthIDTokenInvalid, "invalid jwt signature encoding", err)
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pubKey.Key, crypto.SHA256, digest[:], sigBytes); err != nil {
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

	if err := verifyKeyIssuer(pubKey, claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// issuerTenantPlaceholder matches Microsoft's templated per-key issuer, e.g. "{tenantid}".
var issuerTenantPlaceholder = regexp.MustCompile(`(?i)\{tenantid\}`)

// verifyKeyIssuer enforces the key↔issuer binding advertised by the JWKS document.
// It runs only after the signature verified, so the token's iss is authenticated.
//
// Comparison rule:
//  1. An empty key issuer means the document does not scope the key: accept.
//  2. A templated key issuer resolves "{tenantid}" with the token's tid claim. Any
//     placeholder that stays unresolved cannot be evaluated, so the binding is
//     skipped rather than guessed — a template must not cause false rejections.
//  3. A concrete key issuer must equal the token's iss exactly; an absent iss on a
//     concrete-issuer key is rejected, never silently accepted.
func verifyKeyIssuer(key JWKSKey, claims map[string]any) error {
	if key.Issuer == "" {
		return nil
	}

	expected := key.Issuer
	if strings.Contains(expected, "{") {
		tid, _ := claims["tid"].(string)
		if tid == "" {
			return nil
		}
		expected = issuerTenantPlaceholder.ReplaceAllString(expected, tid)
		if strings.Contains(expected, "{") {
			return nil
		}
	}

	iss, _ := claims["iss"].(string)
	if iss != expected {
		return errors.New(errors.CodeOAuthIDTokenInvalid, fmt.Sprintf("id_token issuer %q does not match signing key issuer %q", iss, expected), nil)
	}
	return nil
}
