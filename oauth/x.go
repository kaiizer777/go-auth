package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
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

var _ TokenRefresher = (*XProvider)(nil)

// NewXProvider constructs a new X (Twitter) OAuth 2.0 provider adapter.
func NewXProvider(cfg config.XConfig, opts ...EndpointOption) *XProvider {
	// Login baseline: /2/users/me is scoped with both users.read and tweet.read,
	// plus offline.access so the code exchange can issue a refresh token.
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"tweet.read", "users.read", "offline.access"}
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
	q.Set("scope", scopesOrDefault(p.cfg.Scopes, "tweet.read", "users.read", "offline.access"))
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
	if sec, ok := parseDelaySeconds(raw); ok {
		return sec, true
	}
	if at, err := http.ParseTime(raw); err == nil {
		return clampRetryAfterSeconds(int64(time.Until(at) / time.Second)), true
	}
	return 0, false
}

// parseDelaySeconds accepts delay-seconds (1*DIGIT) only. ParseInt reports an
// over-int64 prefix as ErrRange before it reaches a non-digit suffix, so the
// charset must be checked here: "99999999999999999999seconds" is invalid input,
// not an oversized hint.
func parseDelaySeconds(raw string) (int, bool) {
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	sec, err := strconv.ParseInt(raw, 10, 64)
	if err == nil {
		return clampRetryAfterSeconds(sec), true
	}
	// All digits: only a magnitude beyond int64 can fail, and that still clamps.
	// ErrSyntax would mean non-digits slipped past the scan above, so it falls
	// through as unusable input.
	if numErr, ok := err.(*strconv.NumError); ok && numErr.Err == strconv.ErrRange {
		return maxRetryAfterSeconds, true
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
		// null and {} decode cleanly but carry no diagnostic, so they must not
		// consume the xMaxProblemErrors budget that real entries need.
		if e == (xProblemError{}) {
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

// tokenErrorPolicy is the caller-specific error policy for postTokenRequest.
type tokenErrorPolicy struct {
	// grantRejected classifies an upstream `error` value as a rejected grant.
	// Returning nil means the value is not a grant rejection; the code exchange
	// passes a nil func because it cannot tell the service to re-login.
	grantRejected func(errorValue string) error
	// failureMsg labels the caller-facing error for an unclassified error body.
	failureMsg string
}

// classifyGrantError reports the grant rejection for errorValue, if the policy
// recognises one.
func (pol tokenErrorPolicy) classifyGrantError(errorValue string) error {
	if pol.grantRejected == nil || errorValue == "" {
		return nil
	}
	return pol.grantRejected(errorValue)
}

// postTokenRequest POSTs a form to the token endpoint, authenticates with HTTP
// Basic per RFC 6749 §2.3.1 (client_id MUST NOT be in the body), and decodes the
// bounded JSON response. Shared by the code exchange and the refresh grant so
// request building, auth, body handling, and error mapping stay in one place.
func (p *XProvider) postTokenRequest(ctx context.Context, form url.Values, pol tokenErrorPolicy) (*OAuthToken, error) {
	ctx, cancel := context.WithTimeout(ctx, oauthHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token request failed", err)
	}

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
		// RFC 6749 §5.2 reports a rejected grant in an `error` field, so a dead
		// refresh token must not collapse into a generic provider error.
		if msg := xErrorValue(bodyBytes); msg != "" {
			if err := pol.classifyGrantError(msg); err != nil {
				return nil, err
			}
		}
		return nil, parseXErrorWithHeader(resp.StatusCode, bodyBytes, resp.Header)
	}

	var raw map[string]any
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", err)
	}
	if msg, _ := raw["error"].(string); msg != "" {
		if err := pol.classifyGrantError(msg); err != nil {
			return nil, err
		}
		// Same invariant as parseXErrorWithHeader: upstream text never becomes
		// the caller-facing message, so it rides the cause for server-side logs.
		return nil, errors.New(errors.CodeOAuthProviderError, pol.failureMsg,
			errors.New(errors.CodeOAuthProviderError, "upstream error: "+msg, nil))
	}
	// X can also report a failed grant as a 2xx RFC 7807 problem document.
	// It has no error field, so map it like the non-2xx path does.
	if isXProblemResponse(resp.Header, raw) {
		return nil, parseXErrorWithHeader(resp.StatusCode, bodyBytes, resp.Header)
	}

	tok := tokenFromRaw(raw)
	if tok.AccessToken == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth provider returned no access token", nil)
	}
	return tok, nil
}

// xErrorValue extracts the RFC 6749 §5.2 `error` value from a token error body.
// A body that is not a JSON object carries no usable value.
func xErrorValue(body []byte) string {
	var raw map[string]any
	if json.Unmarshal(body, &raw) != nil {
		return ""
	}
	msg, _ := raw["error"].(string)
	return msg
}

// ExchangeCode exchanges an authorization code and PKCE code verifier for tokens via POST /2/oauth2/token.
// It authenticates using HTTP Basic Auth per RFC 6749 §2.3.1. client_id MUST NOT be in the body.
func (p *XProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*OAuthToken, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", p.cfg.RedirectURI)
	form.Set("code_verifier", codeVerifier)

	return p.postTokenRequest(ctx, form, tokenErrorPolicy{failureMsg: "oauth token exchange failed"})
}

// refreshGrantError classifies X's `error` value for a refresh request. Only
// invalid_grant means the presented token is dead, and only that code lets the
// service clear a stored grant (RFC 6749 §5.2). invalid_request describes the
// request — our parameters or an upstream contract change — and invalid_client a
// deployment credential, so neither may destroy every user's stored token.
func refreshGrantError(errorValue string) error {
	if errorValue == "invalid_grant" {
		return errors.ErrOAuthGrantRejected
	}
	return nil
}

// RefreshToken renews a token pair via POST /2/oauth2/token.
// X rotates the refresh token on every use and invalidates the presented one, so
// the response value is authoritative; the presented token survives only when the
// response omits a replacement.
func (p *XProvider) RefreshToken(ctx context.Context, refreshToken string) (*OAuthToken, error) {
	if refreshToken == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "refresh token required", nil)
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	tok, err := p.postTokenRequest(ctx, form, tokenErrorPolicy{
		grantRejected: refreshGrantError,
		failureMsg:    "oauth token refresh failed",
	})
	if err != nil {
		return nil, err
	}
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}
	return tok, nil
}

// isXProblemResponse reports whether a token response is an RFC 7807 problem
// document: labelled application/problem+json, or carrying no access token
// and the problem fields X uses (type, title, detail, errors).
func isXProblemResponse(header http.Header, raw map[string]any) bool {
	if mediaType, _, err := mime.ParseMediaType(header.Get("Content-Type")); err == nil &&
		mediaType == "application/problem+json" {
		return true
	}
	if _, ok := raw["access_token"]; ok {
		return false
	}
	for _, key := range []string{"type", "title", "detail"} {
		if s, _ := raw[key].(string); s != "" {
			return true
		}
	}
	errs, _ := raw["errors"].([]any)
	return len(errs) > 0
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
