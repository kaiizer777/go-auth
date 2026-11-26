package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// XProvider implements OAuth 2.0 authentication for X (formerly Twitter) API v2.
type XProvider struct {
	cfg         config.XConfig
	client      *http.Client
	authURL     string
	tokenURL    string
	userInfoURL string
}

var _ Provider = (*XProvider)(nil)

// NewXProvider constructs a new X (Twitter) OAuth 2.0 provider adapter.
func NewXProvider(cfg config.XConfig, opts ...EndpointOption) *XProvider {
	// Login needs only users.read (/2/users/me); tweet.read and
	// offline.access are opt-in via config when the feature needs them.
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"users.read"}
	}
	ep := resolveEndpoints(EndpointOverride{
		AuthorizeURL: "https://twitter.com/i/oauth2/authorize",
		TokenURL:     "https://api.twitter.com/2/oauth2/token",
		UserInfoURL:  "https://api.twitter.com/2/users/me",
	}, opts)
	return &XProvider{
		cfg:         cfg,
		client:      newHTTPClient(),
		authURL:     ep.AuthorizeURL,
		tokenURL:    ep.TokenURL,
		userInfoURL: ep.UserInfoURL,
	}
}

// ID returns the canonical provider slug.
func (p *XProvider) ID() string {
	return "x"
}

// AuthURL builds the X authorization URL with default options.
func (p *XProvider) AuthURL(state, codeChallenge string) string {
	return p.AuthCodeURL(state, codeChallenge)
}

// AuthCodeURL constructs the authorization URL with PKCE challenge, state, and scopes.
func (p *XProvider) AuthCodeURL(state, codeChallenge string, opts ...AuthCodeOption) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURI)
	q.Set("scope", scopesOrDefault(p.cfg.Scopes, "users.read"))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	applyAuthCodeOptions(q, opts)

	return p.authURL + "?" + q.Encode()
}

// RFC 9110 sets no upper bound on a retry hint, but it reaches the client as a
// Retry-After header, so a hostile or misconfigured upstream must not escape it.
const (
	minRetryAfterSeconds = 1
	maxRetryAfterSeconds = 24 * 60 * 60
)

// parseRetryAfterHeader resolves the retry delay in seconds. A valid
// Retry-After (delay-seconds or HTTP-date per RFC 9110) wins over the
// x-rate-limit-reset epoch. Zero means neither source was usable.
func parseRetryAfterHeader(header http.Header) int {
	if header == nil {
		return 0
	}
	if sec, ok := parseRetryAfterValue(strings.TrimSpace(header.Get("Retry-After"))); ok {
		return sec
	}
	if rst := strings.TrimSpace(header.Get("x-rate-limit-reset")); rst != "" {
		if resetUnix, err := strconv.ParseInt(rst, 10, 64); err == nil {
			return clampRetryAfterSeconds(resetUnix - time.Now().Unix())
		}
	}
	return 0
}

// parseRetryAfterValue parses both RFC 9110 forms and clamps the result.
func parseRetryAfterValue(raw string) (int, bool) {
	// RFC 9110 delay-seconds = 1*DIGIT, so a negative value is invalid input:
	// treat it as garbage and let the caller fall back to the reset epoch.
	if raw == "" || strings.HasPrefix(raw, "-") {
		return 0, false
	}
	sec, err := strconv.ParseInt(raw, 10, 64)
	if err == nil {
		return clampRetryAfterSeconds(sec), true
	}
	if numErr, ok := err.(*strconv.NumError); ok && numErr.Err == strconv.ErrRange {
		// Magnitude beyond int64 still clamps; negatives were rejected above.
		return maxRetryAfterSeconds, true
	}
	if at, err := http.ParseTime(raw); err == nil {
		return clampRetryAfterSeconds(int64(time.Until(at) / time.Second)), true
	}
	return 0, false
}

// clampRetryAfterSeconds bounds sec to [minRetryAfterSeconds, maxRetryAfterSeconds].
func clampRetryAfterSeconds(sec int64) int {
	if sec < minRetryAfterSeconds {
		return minRetryAfterSeconds
	}
	if sec > maxRetryAfterSeconds {
		return maxRetryAfterSeconds
	}
	return int(sec)
}

func xRateLimitError(retryAfterSec int) error {
	return &RateLimitError{RetryAfter: retryAfterSec, Err: errors.ErrOAuthRateLimitExceeded}
}

// xProblemDetails is the RFC 7807 failure body X returns.
type xProblemDetails struct {
	Type   string            `json:"type"`
	Title  string            `json:"title"`
	Detail string            `json:"detail"`
	Status int               `json:"status"`
	Errors []json.RawMessage `json:"errors"`
}

// xProblemError is one entry of an RFC 7807 errors array.
type xProblemError struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Detail  string `json:"detail"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

// xMaxProblemErrors caps how many errors[] entries reach the cause so a hostile body cannot inflate it without limit.
const xMaxProblemErrors = 8

// problemErrors decodes errors[] one entry at a time, so a single malformed
// entry drops only itself instead of the whole problem document.
func (p xProblemDetails) problemErrors() []xProblemError {
	if len(p.Errors) == 0 {
		return nil
	}
	errs := make([]xProblemError, 0, len(p.Errors))
	for _, raw := range p.Errors {
		var e xProblemError
		if err := json.Unmarshal(raw, &e); err != nil {
			continue
		}
		errs = append(errs, e)
	}
	return errs
}

// xProblemCause flattens every non-empty provider diagnostic into one cause
// string. Upstream text stays server-side; the caller-facing message is generic.
func xProblemCause(problem xProblemDetails, errs []xProblemError) string {
	var b strings.Builder
	add := func(label, value string) {
		if value == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		b.WriteString(label)
		b.WriteString(": ")
		b.WriteString(value)
	}
	add("upstream type", problem.Type)
	add("upstream title", problem.Title)
	add("upstream detail", problem.Detail)
	for i, e := range errs {
		if i == xMaxProblemErrors {
			break
		}
		add("upstream error type", e.Type)
		add("upstream error title", e.Title)
		add("upstream error message", e.Message)
		add("upstream error detail", e.Detail)
	}
	return b.String()
}

func isXRateLimited(status int, title string) bool {
	return status == http.StatusTooManyRequests || strings.EqualFold(title, "Too Many Requests")
}

// parseXErrorWithHeader inspects HTTP status, body, and response headers for rate limit details or RFC 7807 problem details.
func parseXErrorWithHeader(statusCode int, body []byte, header http.Header) error {
	retryAfterSec := parseRetryAfterHeader(header)

	if statusCode == http.StatusTooManyRequests {
		return xRateLimitError(retryAfterSec)
	}

	var problem xProblemDetails
	if err := json.Unmarshal(body, &problem); err == nil {
		if isXRateLimited(problem.Status, problem.Title) {
			return xRateLimitError(retryAfterSec)
		}
		problemErrs := problem.problemErrors()
		for _, e := range problemErrs {
			if isXRateLimited(e.Status, e.Title) {
				return xRateLimitError(retryAfterSec)
			}
		}
		// Upstream-controlled text must never become the caller-facing message:
		// WriteJSON renders only Message on the wire, while the cause stays
		// server-side for logs.
		if cause := xProblemCause(problem, problemErrs); cause != "" {
			return errors.New(errors.CodeOAuthProviderError, "oauth provider request failed",
				errors.New(errors.CodeOAuthProviderError, cause, nil))
		}
	}

	return errors.New(errors.CodeOAuthProviderError, fmt.Sprintf("oauth provider responded with status %d", statusCode), nil)
}

// ExchangeCode exchanges an authorization code and PKCE code verifier for tokens via POST /2/oauth2/token.
// It authenticates using HTTP Basic Auth per RFC 6749 §2.3.1. client_id MUST NOT be in the body.
func (p *XProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*OAuthToken, error) {
	ctx, cancel := context.WithTimeout(ctx, oauthHTTPTimeout)
	defer cancel()

	form := url.Values{}
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", p.cfg.RedirectURI)
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token request failed", err)
	}

	// RFC 6749 §2.3.1 Client Authentication via Basic Auth:
	// Authorization: Basic base64(url.QueryEscape(ClientID) + ":" + url.QueryEscape(ClientSecret))
	credentials := url.QueryEscape(p.cfg.ClientID) + ":" + url.QueryEscape(p.cfg.ClientSecret)
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(credentials))
	req.Header.Set("Authorization", "Basic "+encodedAuth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, oauthBodyLimit))
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "failed to read response body", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, parseXErrorWithHeader(resp.StatusCode, bodyBytes, resp.Header)
	}

	var raw map[string]any
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", err)
	}
	if msg, _ := raw["error"].(string); msg != "" {
		// Same invariant as parseXErrorWithHeader: upstream text never becomes
		// the caller-facing message, so it rides the cause for server-side logs.
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token exchange failed",
			errors.New(errors.CodeOAuthProviderError, "upstream error: "+msg, nil))
	}

	return tokenFromRaw(raw), nil
}

// FetchUserInfo retrieves and normalizes user profile information from /2/users/me.
// Sets Email = "" and EmailVerified = false per the missing email invariant.
func (p *XProvider) FetchUserInfo(ctx context.Context, tokens *OAuthToken) (*OAuthUser, error) {
	if tokens == nil || tokens.AccessToken == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "access token required", nil)
	}

	ctx, cancel := context.WithTimeout(ctx, oauthHTTPTimeout)
	defer cancel()

	u, err := url.Parse(p.userInfoURL)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "invalid userinfo url", err)
	}
	q := u.Query()
	q.Set("user.fields", "id,name,username,profile_image_url,verified")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth userinfo request failed", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth userinfo request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, oauthBodyLimit))
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "failed to read response body", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, parseXErrorWithHeader(resp.StatusCode, bodyBytes, resp.Header)
	}

	var payload struct {
		Data struct {
			ID              string `json:"id"`
			Name            string `json:"name"`
			Username        string `json:"username"`
			ProfileImageURL string `json:"profile_image_url"`
			Verified        bool   `json:"verified"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", err)
	}

	if strings.TrimSpace(payload.Data.ID) == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "x user id missing", nil)
	}

	name := payload.Data.Name
	if strings.TrimSpace(name) == "" {
		name = payload.Data.Username
	}

	var rawClaims map[string]any
	_ = json.Unmarshal(bodyBytes, &rawClaims)

	return &OAuthUser{
		ProviderID:     "x",
		ProviderUserID: payload.Data.ID,
		Email:          "",
		EmailVerified:  false,
		Name:           name,
		AvatarURL:      payload.Data.ProfileImageURL,
		RawClaims:      rawClaims,
	}, nil
}
