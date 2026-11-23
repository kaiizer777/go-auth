package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// OAuthStatePayload bundles the state token with the PKCE verifier for callback validation.
type OAuthStatePayload struct {
	Token        string    `json:"t"`
	ProviderID   string    `json:"p"`
	CodeVerifier string    `json:"v"`
	RedirectURL  string    `json:"r"`
	UserID       string    `json:"u,omitempty"`
	ExpiresAt    time.Time `json:"e"`
}

// stateTokenBytes is the CSPRNG entropy size for state tokens.
const stateTokenBytes = 32

// stateTokenLen is the issued token width. ValidateState compares against the
// cookie's own token, not this value, so signed test fixtures stay valid.
var stateTokenLen = base64.RawURLEncoding.EncodedLen(stateTokenBytes)

// ErrOAuthEntropyReadFailed surfaces CSPRNG failures as a domain 500
// so Part 3 handlers matching on domain codes never see a bare stdlib error.
var ErrOAuthEntropyReadFailed = errors.New(errors.CodeInternalError, "failed to generate oauth entropy", nil)

// consumedStates records state tokens that completed validation, keyed by
// token with the payload expiry. Package-level so every Service instance in
// this process shares one replay record; entries expire with the state TTL
// and are swept lazily on access. Replicas do not share this record: pair a
// configured StateSecret with sticky routing or an external store.
var consumedStates = struct {
	sync.Mutex
	seen map[string]time.Time
}{seen: map[string]time.Time{}}

// consumedStateSweepThreshold bounds the cost of the lazy expiry sweep: below it
// the map is small enough that a full scan per callback buys nothing.
const consumedStateSweepThreshold = 1024

// consumeStateToken records token as used through exp. False means the token
// completed validation before and has not expired: the callback is a replay.
func consumeStateToken(token string, exp time.Time) bool {
	now := time.Now()
	consumedStates.Lock()
	defer consumedStates.Unlock()
	if len(consumedStates.seen) >= consumedStateSweepThreshold {
		for tok, tokExp := range consumedStates.seen {
			if !now.Before(tokExp) {
				delete(consumedStates.seen, tok)
			}
		}
	}
	// The current token is always evaluated even when the sweep was skipped,
	// so an expired entry is never a replay.
	if prev, ok := consumedStates.seen[token]; ok && now.Before(prev) {
		return false
	}
	consumedStates.seen[token] = exp
	return true
}

// ensureOAuthConfig returns cfg or defaults when nil, normalizing state cookie fields
// so writers that bypass Config.Validate still emit a safe cookie.
func ensureOAuthConfig(cfg *config.Config) *config.Config {
	if cfg == nil {
		defaultCfg := config.DefaultConfig()
		return &defaultCfg
	}
	cp := *cfg
	if cp.OAuth.StateCookieName == "" {
		cp.OAuth.StateCookieName = "oauth_state"
	}
	if cp.OAuth.StateCookiePath == "" {
		cp.OAuth.StateCookiePath = "/"
	}
	if cp.OAuth.StateTTL <= 0 {
		cp.OAuth.StateTTL = 10 * time.Minute
	}
	if cp.OAuth.StateCookieSameSite == 0 {
		cp.OAuth.StateCookieSameSite = http.SameSiteLaxMode
	}
	return &cp
}

// isFormPostProvider reports providers whose authorization response arrives
// as a cross-site POST. Apple forces response_mode=form_post; it is the only
// such provider, so the check is a single slug until another one appears.
func isFormPostProvider(providerID string) bool { return providerID == "apple" }

// stateCookiePolicy resolves Secure + SameSite for a provider. GET flows keep
// the configured base policy (Lax default); form_post flows escalate to
// None+Secure because browsers withhold Lax on cross-site POST. None forces
// Secure even when SessionCookieSecure is false: browsers reject None without
// Secure outright, and Apple mandates HTTPS redirect URLs in production.
func stateCookiePolicy(cfg *config.Config, providerID string) (secure bool, sameSite http.SameSite) {
	sameSite = cfg.OAuth.StateCookieSameSite
	if isFormPostProvider(providerID) {
		sameSite = http.SameSiteNoneMode
	}
	secure = cfg.SessionCookieSecure
	if sameSite == http.SameSiteNoneMode {
		secure = true
	}
	return secure, sameSite
}

// stateSigningKey resolves the HMAC key. Empty is fail-closed: a per-process
// fallback key cannot verify state issued by another replica or before a
// restart, failing in-flight logins at random with no startup warning.
func stateSigningKey(secret string) ([]byte, error) {
	if secret == "" {
		return nil, errors.ErrOAuthStateSecretRequired
	}
	return []byte(secret), nil
}

func signStatePayload(payload OAuthStatePayload, key []byte) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func verifyStateSignature(signed string, key []byte) (OAuthStatePayload, error) {
	var payload OAuthStatePayload
	parts := strings.Split(signed, ".")
	if len(parts) != 2 {
		return payload, errors.ErrOAuthStateInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return payload, errors.ErrOAuthStateInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return payload, errors.ErrOAuthStateInvalid
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	if subtle.ConstantTimeCompare(mac.Sum(nil), sig) != 1 {
		return payload, errors.ErrOAuthStateInvalid
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, errors.ErrOAuthStateInvalid
	}
	return payload, nil
}

// SetStateCookieWithUser generates a state token, signs the payload including an optional active user ID,
// sets the state cookie, and returns the raw state value for the provider authorization URL.
func SetStateCookieWithUser(w http.ResponseWriter, cfg *config.Config, providerID, codeVerifier, redirectURL, userID string) (string, error) {
	cfg = ensureOAuthConfig(cfg)
	token := make([]byte, stateTokenBytes)
	if _, err := io.ReadFull(rand.Reader, token); err != nil {
		return "", ErrOAuthEntropyReadFailed
	}
	state := base64.RawURLEncoding.EncodeToString(token)
	payload := OAuthStatePayload{
		Token:        state,
		ProviderID:   providerID,
		CodeVerifier: codeVerifier,
		RedirectURL:  redirectURL,
		UserID:       userID,
		ExpiresAt:    time.Now().Add(cfg.OAuth.StateTTL),
	}
	key, err := stateSigningKey(cfg.OAuth.StateSecret)
	if err != nil {
		return "", err
	}
	signed, err := signStatePayload(payload, key)
	if err != nil {
		return "", err
	}
	secure, sameSite := stateCookiePolicy(cfg, providerID)
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.OAuth.StateCookieName,
		Value:    signed,
		Path:     cfg.OAuth.StateCookiePath,
		MaxAge:   int(cfg.OAuth.StateTTL.Seconds()),
		Expires:  payload.ExpiresAt,
		HttpOnly: true, // mandatory: JS must never inspect verifier or state token
		Secure:   secure,
		SameSite: sameSite,
	})
	return state, nil
}

// SetStateCookie generates a state token, signs the payload, sets the state cookie,
// and returns the raw state value for the provider authorization URL.
func SetStateCookie(w http.ResponseWriter, cfg *config.Config, providerID, codeVerifier, redirectURL string) (string, error) {
	return SetStateCookieWithUser(w, cfg, providerID, codeVerifier, redirectURL, "")
}

// ValidateState checks the state parameter against the signed state cookie.
// The cookie is cleared only when it belongs to this callback: on success
// (including a replayed success, which the same token owns), or when it is
// owned-but-dead (corrupt value, expired payload). A token mismatch or
// foreign provider ID leaves the cookie intact, so a stale callback from an
// older login never destroys a newer login's cookie. Consumption fires only
// on a fully validated token, never on mismatch or foreign-provider values.
// Validation failures return 403 OAUTH_STATE_INVALID without distinguishing
// the cause; a missing secret propagates as a 500 server misconfiguration.
func ValidateState(w http.ResponseWriter, r *http.Request, cfg *config.Config, providerID, stateParam string) (*OAuthStatePayload, error) {
	cfg = ensureOAuthConfig(cfg)
	cookie, cookieErr := r.Cookie(cfg.OAuth.StateCookieName)
	if cookieErr != nil {
		return nil, errors.ErrOAuthStateInvalid
	}
	key, err := stateSigningKey(cfg.OAuth.StateSecret)
	if err != nil {
		return nil, err
	}
	payload, err := verifyStateSignature(cookie.Value, key)
	if err != nil {
		// Unverifiable value can never be a live login; sweep it.
		ClearStateCookie(w, cfg, providerID)
		return nil, errors.ErrOAuthStateInvalid
	}
	if len(stateParam) != len(payload.Token) {
		// A length mismatch is a token mismatch: no cookie clearing, and no
		// allocation sized by the caller-controlled parameter.
		return nil, errors.ErrOAuthStateInvalid
	}
	if subtle.ConstantTimeCompare([]byte(stateParam), []byte(payload.Token)) != 1 {
		return nil, errors.ErrOAuthStateInvalid
	}
	if time.Now().After(payload.ExpiresAt) {
		ClearStateCookie(w, cfg, providerID)
		return nil, errors.ErrOAuthStateInvalid
	}
	if payload.ProviderID == "" || payload.ProviderID != providerID {
		return nil, errors.ErrOAuthStateInvalid
	}
	ClearStateCookie(w, cfg, providerID)
	if !consumeStateToken(payload.Token, payload.ExpiresAt) {
		return nil, errors.ErrOAuthStateInvalid
	}
	return &payload, nil
}

// ClearStateCookie invalidates the state cookie immediately. providerID keeps
// the deletion attributes (Secure/SameSite) matched to the issued cookie.
// MaxAge=-1 means "delete now". MaxAge=0 would mean "session cookie" — never use 0 for deletion.
func ClearStateCookie(w http.ResponseWriter, cfg *config.Config, providerID string) {
	cfg = ensureOAuthConfig(cfg)
	secure, sameSite := stateCookiePolicy(cfg, providerID)
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.OAuth.StateCookieName,
		Value:    "",
		Path:     cfg.OAuth.StateCookiePath,
		MaxAge:   -1, // -1 = delete immediately; 0 = session cookie (wrong for invalidation)
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
}
