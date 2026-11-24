package oauthmock

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const idpTestVerifier = "idp-test-verifier-0123456789-0123456789-abcdef"

// idpAuthorize plays the browser against an IdP authorize endpoint and returns
// the single-use code it redirected back with.
func idpAuthorize(t *testing.T, authorizeURL, clientID string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(idpTestVerifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"http://app.example/callback"},
		"state":                 {"st"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(authorizeURL + "?" + q.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d; want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize redirect: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("authorize redirect missing code")
	}
	return code
}

func idpPostForm(t *testing.T, endpoint string, form url.Values, header map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestMicrosoftIdPRejectsBadVerifierAndSecret(t *testing.T) {
	t.Parallel()
	idp, err := NewMicrosoftIdP()
	if err != nil {
		t.Fatalf("NewMicrosoftIdP: %v", err)
	}
	t.Cleanup(idp.Close)

	tokenURL := idp.Server.URL + "/token"
	base := func(code string) url.Values {
		return url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {idp.ClientID},
			"client_secret": {idp.ClientSecret},
			"code":          {code},
			"code_verifier": {idpTestVerifier},
		}
	}

	if got := idpPostForm(t, tokenURL, base(idpAuthorize(t, idp.Server.URL+"/authorize", idp.ClientID)), nil); got != http.StatusOK {
		t.Fatalf("valid exchange status = %d; want 200", got)
	}

	badVerifier := base(idpAuthorize(t, idp.Server.URL+"/authorize", idp.ClientID))
	badVerifier.Set("code_verifier", "not-the-verifier")
	if got := idpPostForm(t, tokenURL, badVerifier, nil); got != http.StatusBadRequest {
		t.Fatalf("mismatched verifier status = %d; want 400", got)
	}

	badSecret := base(idpAuthorize(t, idp.Server.URL+"/authorize", idp.ClientID))
	badSecret.Set("client_secret", "wrong")
	if got := idpPostForm(t, tokenURL, badSecret, nil); got != http.StatusBadRequest {
		t.Fatalf("wrong client secret status = %d; want 400", got)
	}
}

func TestFacebookIdPRequiresAppSecretProof(t *testing.T) {
	t.Parallel()
	idp := NewFacebookIdP()
	t.Cleanup(idp.Close)

	code := idpAuthorize(t, idp.Server.URL+"/"+facebookGraphVersion+"/dialog/oauth", idp.AppID)
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {idp.AppID},
		"client_secret": {idp.AppSecret},
		"code":          {code},
		"code_verifier": {idpTestVerifier},
	}
	if got := idpPostForm(t, idp.Server.URL+"/"+facebookGraphVersion+"/oauth/access_token", tokenForm, nil); got != http.StatusOK {
		t.Fatalf("token status = %d; want 200", got)
	}

	appToken := idp.AppID + "|" + idp.AppSecret
	debugForm := url.Values{
		"input_token":     {idp.userToken()},
		"access_token":    {appToken},
		"appsecret_proof": {hmacHex(idp.AppSecret, appToken)},
	}
	if got := idpPostForm(t, idp.Server.URL+"/debug_token", debugForm, nil); got != http.StatusOK {
		t.Fatalf("debug_token status = %d; want 200", got)
	}
	debugForm.Set("appsecret_proof", "forged")
	if got := idpPostForm(t, idp.Server.URL+"/debug_token", debugForm, nil); got != http.StatusBadRequest {
		t.Fatalf("forged debug_token proof status = %d; want 400", got)
	}

	meURL := idp.Server.URL + "/" + facebookGraphVersion + "/me"
	meReq, err := http.NewRequest(http.MethodGet, meURL, nil)
	if err != nil {
		t.Fatalf("build me request: %v", err)
	}
	meReq.Header.Set("Authorization", "Bearer "+idp.userToken())
	resp, err := http.DefaultClient.Do(meReq)
	if err != nil {
		t.Fatalf("me without proof: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("me without proof status = %d; want 400", resp.StatusCode)
	}
}

func TestXIdPRequiresBasicAuthAndNoBodyClientID(t *testing.T) {
	t.Parallel()
	idp := NewXIdP()
	t.Cleanup(idp.Close)

	tokenURL := idp.Server.URL + "/2/oauth2/token"
	basic := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(idp.ClientID)+":"+url.QueryEscape(idp.ClientSecret)))}
	form := func(code string) url.Values {
		return url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"code_verifier": {idpTestVerifier},
		}
	}

	if got := idpPostForm(t, tokenURL, form(idpAuthorize(t, idp.Server.URL+"/i/oauth2/authorize", idp.ClientID)), basic); got != http.StatusOK {
		t.Fatalf("valid exchange status = %d; want 200", got)
	}

	withClientID := form(idpAuthorize(t, idp.Server.URL+"/i/oauth2/authorize", idp.ClientID))
	withClientID.Set("client_id", idp.ClientID)
	if got := idpPostForm(t, tokenURL, withClientID, basic); got != http.StatusBadRequest {
		t.Fatalf("client_id in body status = %d; want 400", got)
	}

	noBasic := form(idpAuthorize(t, idp.Server.URL+"/i/oauth2/authorize", idp.ClientID))
	if got := idpPostForm(t, tokenURL, noBasic, nil); got != http.StatusBadRequest {
		t.Fatalf("missing basic auth status = %d; want 400", got)
	}
}

func TestDiscordIdPRejectsWrongBearer(t *testing.T) {
	t.Parallel()
	idp := NewDiscordIdP()
	t.Cleanup(idp.Close)

	req, err := http.NewRequest(http.MethodGet, idp.Server.URL+"/api/v10/users/@me", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer not-the-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong bearer status = %d; want 400", resp.StatusCode)
	}
}
