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
func NewXProvider(cfg config.XConfig) *XProvider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"tweet.read", "users.read", "offline.access"}
	}
	return &XProvider{
		cfg:         cfg,
		client:      newHTTPClient(),
		authURL:     "https://twitter.com/i/oauth2/authorize",
		tokenURL:    "https://api.twitter.com/2/oauth2/token",
		userInfoURL: "https://api.twitter.com/2/users/me",
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

	for _, opt := range opts {
		if opt.Key != "" {
			q.Set(opt.Key, opt.Value)
		}
	}

	return p.authURL + "?" + q.Encode()
}

// parseXErrorWithHeader inspects HTTP status, body, and response headers for rate limit details or RFC 7807 problem details.
func parseXErrorWithHeader(statusCode int, body []byte, header http.Header) error {
	var retryAfterSec int
	if header != nil {
		if ra := header.Get("Retry-After"); ra != "" {
			if sec, err := strconv.Atoi(strings.TrimSpace(ra)); err == nil && sec > 0 {
				retryAfterSec = sec
			}
		}
		if retryAfterSec == 0 {
			if rst := header.Get("x-rate-limit-reset"); rst != "" {
				if resetUnix, err := strconv.ParseInt(strings.TrimSpace(rst), 10, 64); err == nil {
					diff := int(resetUnix - time.Now().Unix())
					if diff > 0 {
						retryAfterSec = diff
					} else {
						retryAfterSec = 1
					}
				}
			}
		}
	}

	if statusCode == http.StatusTooManyRequests {
		if retryAfterSec > 0 {
			return &RateLimitError{RetryAfter: retryAfterSec, Err: errors.ErrOAuthRateLimitExceeded}
		}
		return errors.ErrOAuthRateLimitExceeded
	}

	var problem struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
		Type   string `json:"type"`
		Status int    `json:"status"`
		Errors []struct {
			Title   string `json:"title"`
			Detail  string `json:"detail"`
			Message string `json:"message"`
			Status  int    `json:"status"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &problem); err == nil {
		if problem.Status == http.StatusTooManyRequests || strings.EqualFold(problem.Title, "Too Many Requests") {
			if retryAfterSec > 0 {
				return &RateLimitError{RetryAfter: retryAfterSec, Err: errors.ErrOAuthRateLimitExceeded}
			}
			return errors.ErrOAuthRateLimitExceeded
		}
		for _, e := range problem.Errors {
			if e.Status == http.StatusTooManyRequests || strings.EqualFold(e.Title, "Too Many Requests") {
				if retryAfterSec > 0 {
					return &RateLimitError{RetryAfter: retryAfterSec, Err: errors.ErrOAuthRateLimitExceeded}
				}
				return errors.ErrOAuthRateLimitExceeded
			}
		}
		if problem.Detail != "" {
			return errors.New(errors.CodeOAuthProviderError, problem.Detail, nil)
		}
		if problem.Title != "" {
			return errors.New(errors.CodeOAuthProviderError, problem.Title, nil)
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
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token exchange failed: "+msg, nil)
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
