// Package oauthmock fronts httptest token/userinfo servers (plus a JWKS
// server for apple) while implementing oauth.Provider. The token server
// binds the verifier to the challenge observed at authorize time and
// enforces single-use codes, so PKCE-tamper and replay paths fail exactly
// like a real provider with invalid_grant.
package oauthmock

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	apperrors "github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/oauth"
)

// Mock scripts provider responses for OAuth flow tests.
type Mock struct {
	id     string
	client *http.Client

	tokenSrv *httptest.Server
	userSrv  *httptest.Server
	jwksSrv  *httptest.Server

	mu              sync.Mutex
	gotVerifier     string
	verifierCalls   int
	seenCodes       map[string]bool
	challenges      map[string]struct{}
	requireVerifier string
	profile         *oauth.UserInfo

	// SingleUseCodes rejects an auth code on second use (replay tests).
	SingleUseCodes bool
	// CorruptVerifier tampers the verifier on the wire (PKCE tests).
	CorruptVerifier bool

	AccessToken  string
	RefreshToken string
	IDToken      string
	ClientSecret string
}

// New returns a Mock serving fixed tokens and the given profile.
func New(id, sub, email string, verified bool) *Mock {
	m := &Mock{
		id:           id,
		client:       &http.Client{Timeout: 10 * time.Second},
		seenCodes:    map[string]bool{},
		challenges:   map[string]struct{}{},
		AccessToken:  "mock-at-" + id + "-7f3a9c1e",
		RefreshToken: "mock-rt-" + id + "-7f3a9c1e",
		IDToken:      "mock-id-" + id + "-7f3a9c1e",
		ClientSecret: "mock-client-secret-7f3a9c1e",
		profile: &oauth.UserInfo{
			ProviderID: id, ProviderUserID: sub,
			Email: email, EmailVerified: verified, Name: "OAuth User",
		},
	}
	m.tokenSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code, verifier := r.PostForm.Get("code"), r.PostForm.Get("code_verifier")
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.SingleUseCodes {
			if m.seenCodes[code] {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			m.seenCodes[code] = true
		}
		// S256 binding: the verifier must match a challenge observed at
		// authorize time. No recorded challenge means no authorize happened,
		// which a real provider also rejects.
		sum := sha256.Sum256([]byte(verifier))
		if _, ok := m.challenges[base64.RawURLEncoding.EncodeToString(sum[:])]; !ok {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		if m.requireVerifier != "" && verifier != m.requireVerifier {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		if code == "" || verifier == "" {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": m.AccessToken, "refresh_token": m.RefreshToken,
			"id_token": m.IDToken, "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	m.userSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		p := *m.profile
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": p.ProviderUserID, "email": p.Email,
			"email_verified": p.EmailVerified, "name": p.Name,
		})
	}))
	if id == "apple" {
		m.jwksSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"keys":[{"kty":"RSA","kid":"mock-key-1","use":"sig","n":"xGQ","e":"AQAB"}]}`)
		}))
	}
	return m
}

// Close shuts down the mock provider servers.
func (m *Mock) Close() {
	m.tokenSrv.Close()
	m.userSrv.Close()
	if m.jwksSrv != nil {
		m.jwksSrv.Close()
	}
}

// ID returns the provider slug.
func (m *Mock) ID() string { return m.id }

// AuthURL returns a fake provider authorization URL and records the
// code_challenge, so the token server can bind the verifier like a real
// provider (S256 check) instead of accepting any well-formed verifier.
func (m *Mock) AuthURL(state, codeChallenge string) string {
	m.mu.Lock()
	m.challenges[codeChallenge] = struct{}{}
	m.mu.Unlock()
	return "https://provider." + m.id + ".example/auth?state=" + state + "&code_challenge=" + codeChallenge
}

// AuthCodeURL returns a fake provider authorization URL, recording the challenge.
func (m *Mock) AuthCodeURL(state, codeChallenge string, _ ...oauth.AuthCodeOption) string {
	return m.AuthURL(state, codeChallenge)
}

// ExchangeCode posts the code/verifier to the mock token server.
func (m *Mock) ExchangeCode(ctx context.Context, code, verifier string) (*oauth.TokenResponse, error) {
	sent := verifier
	if m.CorruptVerifier {
		sent += "-tampered"
	}
	m.mu.Lock()
	m.gotVerifier, m.verifierCalls = sent, m.verifierCalls+1
	m.mu.Unlock()
	form := url.Values{
		"code": {code}, "code_verifier": {sent}, "client_secret": {m.ClientSecret},
	}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.tokenSrv.URL, strings.NewReader(form))
	if err != nil {
		return nil, apperrors.New(apperrors.CodeOAuthProviderError, "oauth token request failed", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeOAuthProviderError, "oauth token request failed", err)
	}
	defer drainBody(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, apperrors.New(apperrors.CodeOAuthProviderError, "oauth token exchange failed", nil)
	}
	var raw map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&raw); err != nil {
		return nil, apperrors.New(apperrors.CodeOAuthProviderError, "oauth provider returned invalid response", err)
	}
	return &oauth.TokenResponse{
		AccessToken: m.AccessToken, RefreshToken: m.RefreshToken, IDToken: m.IDToken, Raw: raw,
	}, nil
}

// FetchUserInfo round-trips the mock JWKS (apple) and userinfo servers. The
// verdict binds to the wire email_verified value ORed with the profile flag.
func (m *Mock) FetchUserInfo(ctx context.Context, tokens *oauth.TokenResponse) (*oauth.UserInfo, error) {
	if m.jwksSrv != nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.jwksSrv.URL, nil)
		if err != nil {
			return nil, apperrors.New(apperrors.CodeOAuthProviderError, "oauth jwks request failed", err)
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return nil, apperrors.New(apperrors.CodeOAuthProviderError, "oauth jwks request failed", err)
		}
		drainBody(resp)
		if resp.StatusCode != http.StatusOK {
			return nil, apperrors.New(apperrors.CodeOAuthProviderError, "oauth jwks unavailable", nil)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.userSrv.URL, nil)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeOAuthProviderError, "oauth userinfo request failed", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeOAuthProviderError, "oauth userinfo request failed", err)
	}
	defer drainBody(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, apperrors.New(apperrors.CodeOAuthProviderError, "oauth userinfo request failed", nil)
	}
	var raw struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&raw); err != nil {
		return nil, apperrors.New(apperrors.CodeOAuthProviderError, "oauth provider returned invalid response", err)
	}
	verified := false
	switch v := raw.EmailVerified.(type) {
	case bool:
		verified = v
	case string:
		verified = v == "true"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return &oauth.UserInfo{
		ProviderID: m.id, ProviderUserID: raw.Sub,
		Email: raw.Email, EmailVerified: verified || m.profile.EmailVerified,
		Name: raw.Name,
	}, nil
}

// ObservedVerifier returns the last wire verifier and the exchange call count.
func (m *Mock) ObservedVerifier() (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gotVerifier, m.verifierCalls
}

// SetRequireVerifier pins the verifier the token server accepts.
func (m *Mock) SetRequireVerifier(v string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requireVerifier = v
}

// drainBody discards and closes a mock provider response body.
func drainBody(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}
