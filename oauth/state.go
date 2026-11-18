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
	ExpiresAt    time.Time `json:"e"`
}

// stateTokenBytes is the CSPRNG entropy size for state tokens.
const stateTokenBytes = 32

// ErrOAuthEntropyReadFailed surfaces CSPRNG failures as a domain 500
// so Part 3 handlers matching on domain codes never see a bare stdlib error.
var ErrOAuthEntropyReadFailed = errors.New(errors.CodeInternalError, "failed to generate oauth entropy", nil)

// fallbackStateKey is a process-scoped HMAC key used when StateSecret is empty.
// It is generated once via CSPRNG and never logged.
var (
	fallbackStateKey     []byte
	fallbackStateKeyErr  error
	fallbackStateKeyOnce sync.Once
)

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
	return &cp
}

// stateSigningKey resolves the HMAC key: configured StateSecret, else a process-scoped CSPRNG key.
func stateSigningKey(secret string) ([]byte, error) {
	if secret != "" {
		return []byte(secret), nil
	}
	fallbackStateKeyOnce.Do(func() {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			fallbackStateKeyErr = ErrOAuthEntropyReadFailed
			return
		}
		fallbackStateKey = key
	})
	if fallbackStateKeyErr != nil {
		return nil, fallbackStateKeyErr
	}
	return fallbackStateKey, nil
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

// SetStateCookie generates a state token, signs the payload, sets the state cookie,
// and returns the raw state value for the provider authorization URL.
func SetStateCookie(w http.ResponseWriter, cfg *config.Config, providerID, codeVerifier, redirectURL string) (string, error) {
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
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.OAuth.StateCookieName,
		Value:    signed,
		Path:     cfg.OAuth.StateCookiePath,
		MaxAge:   int(cfg.OAuth.StateTTL.Seconds()),
		Expires:  payload.ExpiresAt,
		HttpOnly: true,                    // mandatory: JS must never inspect verifier or state token
		Secure:   cfg.SessionCookieSecure, // mirrors session cookie transport policy
		SameSite: http.SameSiteLaxMode,    // mandatory: top-level GET redirect from provider
	})
	return state, nil
}

// ValidateState checks the state parameter against the signed state cookie.
// The cookie is cleared immediately (single-use) regardless of the outcome.
// Any failure returns 403 OAUTH_STATE_INVALID without distinguishing the cause.
func ValidateState(w http.ResponseWriter, r *http.Request, cfg *config.Config, providerID, stateParam string) (*OAuthStatePayload, error) {
	cfg = ensureOAuthConfig(cfg)
	cookie, cookieErr := r.Cookie(cfg.OAuth.StateCookieName)
	ClearStateCookie(w, cfg)
	if cookieErr != nil {
		return nil, errors.ErrOAuthStateInvalid
	}
	key, err := stateSigningKey(cfg.OAuth.StateSecret)
	if err != nil {
		return nil, errors.ErrOAuthStateInvalid
	}
	payload, err := verifyStateSignature(cookie.Value, key)
	if err != nil {
		return nil, errors.ErrOAuthStateInvalid
	}
	if subtle.ConstantTimeCompare([]byte(stateParam), []byte(payload.Token)) != 1 {
		return nil, errors.ErrOAuthStateInvalid
	}
	if time.Now().After(payload.ExpiresAt) {
		return nil, errors.ErrOAuthStateInvalid
	}
	if payload.ProviderID == "" || payload.ProviderID != providerID {
		return nil, errors.ErrOAuthStateInvalid
	}
	return &payload, nil
}

// ClearStateCookie invalidates the state cookie immediately.
// MaxAge=-1 means "delete now". MaxAge=0 would mean "session cookie" — never use 0 for deletion.
func ClearStateCookie(w http.ResponseWriter, cfg *config.Config) {
	cfg = ensureOAuthConfig(cfg)
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.OAuth.StateCookieName,
		Value:    "",
		Path:     cfg.OAuth.StateCookiePath,
		MaxAge:   -1, // -1 = delete immediately; 0 = session cookie (wrong for invalidation)
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		Secure:   cfg.SessionCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
