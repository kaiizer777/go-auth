package oauthmock

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const idpTestVerifier = "idp-test-verifier-0123456789-0123456789-abcdef"

const idpTestRedirect = "http://app.example/callback"

// idpAuthorize plays the browser against an IdP authorize endpoint and returns
// the single-use code it redirected back with.
func idpAuthorize(t *testing.T, authorizeURL, clientID string) string {
	t.Helper()
	return idpAuthorizeScope(t, authorizeURL, clientID, "openid profile email offline_access")
}

// idpAuthorizeScope is idpAuthorize with an explicit scope request.
func idpAuthorizeScope(t *testing.T, authorizeURL, clientID, scope string) string {
	t.Helper()
	resp := idpAuthorizeRequest(t, authorizeURL, clientID, idpTestRedirect, scope)
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

// idpAuthorizeRequest issues one authorize request with an explicit redirect
// and scope, returning the un-followed response so callers can assert the
// provider's verdict.
func idpAuthorizeRequest(t *testing.T, authorizeURL, clientID, redirectURI, scope string) *http.Response {
	t.Helper()
	sum := sha256.Sum256([]byte(idpTestVerifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scope},
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
	return resp
}

func TestIdPRejectsUnregisteredRedirectURI(t *testing.T) {
	t.Parallel()
	idp, err := NewMicrosoftIdP()
	if err != nil {
		t.Fatalf("NewMicrosoftIdP: %v", err)
	}
	t.Cleanup(idp.Close)

	resp := idpAuthorizeRequest(t, idp.Server.URL+"/authorize", idp.ClientID,
		"http://attacker.example/callback", "openid profile email offline_access")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unregistered redirect_uri status = %d; want 400", resp.StatusCode)
	}
}

func TestIdPRejectsScopeMissingEmail(t *testing.T) {
	t.Parallel()
	idp, err := NewMicrosoftIdP()
	if err != nil {
		t.Fatalf("NewMicrosoftIdP: %v", err)
	}
	t.Cleanup(idp.Close)

	resp := idpAuthorizeRequest(t, idp.Server.URL+"/authorize", idp.ClientID,
		idpTestRedirect, "openid profile")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("scope without email status = %d; want 400", resp.StatusCode)
	}
}

func TestIdPRejectsScopeMissingOpenID(t *testing.T) {
	t.Parallel()
	idp, err := NewMicrosoftIdP()
	if err != nil {
		t.Fatalf("NewMicrosoftIdP: %v", err)
	}
	t.Cleanup(idp.Close)

	resp := idpAuthorizeRequest(t, idp.Server.URL+"/authorize", idp.ClientID,
		idpTestRedirect, "email profile")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("scope without openid status = %d; want 400", resp.StatusCode)
	}
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
			"redirect_uri":  {idpTestRedirect},
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

	code := idpAuthorizeScope(t, idp.Server.URL+"/"+facebookGraphVersion+"/dialog/oauth", idp.AppID, "email public_profile")
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {idp.AppID},
		"client_secret": {idp.AppSecret},
		"code":          {code},
		"redirect_uri":  {idpTestRedirect},
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
			"redirect_uri":  {idpTestRedirect},
			"code_verifier": {idpTestVerifier},
		}
	}

	if got := idpPostForm(t, tokenURL, form(idpAuthorizeScope(t, idp.Server.URL+"/i/oauth2/authorize", idp.ClientID, "users.read")), basic); got != http.StatusOK {
		t.Fatalf("valid exchange status = %d; want 200", got)
	}

	withClientID := form(idpAuthorizeScope(t, idp.Server.URL+"/i/oauth2/authorize", idp.ClientID, "users.read"))
	withClientID.Set("client_id", idp.ClientID)
	if got := idpPostForm(t, tokenURL, withClientID, basic); got != http.StatusBadRequest {
		t.Fatalf("client_id in body status = %d; want 400", got)
	}

	wrongSecret := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(idp.ClientID)+":"+url.QueryEscape("wrong-client-secret")))}
	if got := idpPostForm(t, tokenURL, form(idpAuthorizeScope(t, idp.Server.URL+"/i/oauth2/authorize", idp.ClientID, "users.read")), wrongSecret); got != http.StatusBadRequest {
		t.Fatalf("wrong client secret status = %d; want 400", got)
	}

	noBasic := form(idpAuthorizeScope(t, idp.Server.URL+"/i/oauth2/authorize", idp.ClientID, "users.read"))
	if got := idpPostForm(t, tokenURL, noBasic, nil); got != http.StatusBadRequest {
		t.Fatalf("missing basic auth status = %d; want 400", got)
	}
}

// xBasicAuth is the RFC 6749 §2.3.1 credential pair the X token endpoint wants.
func xBasicAuth(idp *XIdP) map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(idp.ClientID)+":"+url.QueryEscape(idp.ClientSecret)))}
}

// xExchangeCode redeems one authorize code for the requested scope.
func xExchangeCode(t *testing.T, idp *XIdP, scope string) (int, map[string]any) {
	t.Helper()
	code := idpAuthorizeScope(t, idp.Server.URL+"/i/oauth2/authorize", idp.ClientID, scope)
	return idpPostFormJSON(t, idp.Server.URL+"/2/oauth2/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {idpTestRedirect},
		"code_verifier": {idpTestVerifier},
	}, xBasicAuth(idp))
}

func TestXIdPRefreshTokenRequiresOfflineAccess(t *testing.T) {
	t.Parallel()
	idp := NewXIdP()
	t.Cleanup(idp.Close)

	if status, body := xExchangeCode(t, idp, "users.read"); status != http.StatusOK || body["refresh_token"] != nil {
		t.Fatalf("users.read exchange = %d %v; want 200 without refresh_token", status, body)
	}
	if status, body := xExchangeCode(t, idp, "users.read offline.access"); status != http.StatusOK || body["refresh_token"] != "x-idp-refresh-token" {
		t.Fatalf("offline.access exchange = %d %v; want 200 with the X fixture refresh token", status, body)
	}
}

func TestXIdPRefreshGrantRotatesAndRejectsReplay(t *testing.T) {
	t.Parallel()
	idp := NewXIdP()
	t.Cleanup(idp.Close)

	_, pair := xExchangeCode(t, idp, "users.read offline.access")
	refreshForm := func(token string) url.Values {
		return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}
	}

	status, rotated := idpPostFormJSON(t, idp.Server.URL+"/2/oauth2/token", refreshForm("x-idp-refresh-token"), xBasicAuth(idp))
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d; want 200", status)
	}
	next, _ := rotated["refresh_token"].(string)
	if next == "" || next == pair["refresh_token"] {
		t.Fatalf("refresh_token = %v; want a rotated value", rotated["refresh_token"])
	}
	if rotated["access_token"] == pair["access_token"] {
		t.Fatal("refresh issued the exchange's access token; want a distinguishable one")
	}

	status, replayed := idpPostFormJSON(t, idp.Server.URL+"/2/oauth2/token", refreshForm("x-idp-refresh-token"), xBasicAuth(idp))
	if status != http.StatusBadRequest || replayed["error"] != "invalid_grant" {
		t.Fatalf("replay = %d %v; want 400 invalid_grant", status, replayed)
	}

	if got := idp.RefreshCalls.Load(); got != 2 {
		t.Fatalf("refresh calls = %d; want 2", got)
	}

	// me() accepts only the newest access token, which is what makes a refresh
	// that kept the stale one fail end to end.
	oldAccess, _ := pair["access_token"].(string)
	newAccess, _ := rotated["access_token"].(string)
	if status := xMeStatus(t, idp, oldAccess); status != http.StatusBadRequest {
		t.Fatalf("me with the exchanged access token = %d; want 400 after rotation", status)
	}
	if status := xMeStatus(t, idp, newAccess); status != http.StatusOK {
		t.Fatalf("me with the refreshed access token = %d; want 200", status)
	}

	status, body := idpPostFormJSON(t, idp.Server.URL+"/2/oauth2/token", refreshForm(next), nil)
	if status != http.StatusBadRequest || body["error"] != "invalid_client" {
		t.Fatalf("refresh without basic auth = %d %v; want 400 invalid_client", status, body)
	}
	if got := idp.RefreshCalls.Load(); got != 2 {
		t.Fatalf("refresh calls after unauthenticated attempt = %d; want 2", got)
	}
}

// TestXIdPMeRequiresBearer pins the pre-grant failure mode: me() compares the
// presented bearer against its own empty access token, so without this guard an
// unauthenticated request matched.
func TestXIdPMeRequiresBearer(t *testing.T) {
	t.Parallel()
	idp := NewXIdP()
	t.Cleanup(idp.Close)

	if status := xMeStatus(t, idp, ""); status != http.StatusUnauthorized {
		t.Fatalf("me without a bearer = %d; want 401", status)
	}
	if status := xMeStatus(t, idp, "x-idp-access-token-0"); status != http.StatusBadRequest {
		t.Fatalf("me with an unissued bearer = %d; want 400", status)
	}
}

// xMeStatus calls the X IdP profile endpoint with one bearer token.
func xMeStatus(t *testing.T, idp *XIdP, accessToken string) int {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, idp.Server.URL+"/2/users/me", nil)
	if err != nil {
		t.Fatalf("build me request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestScopeGrantedMatchesWholeElements(t *testing.T) {
	t.Parallel()
	for scope, want := range map[string]bool{
		"users.read offline.access":      true,
		"offline.access":                 true,
		"users.read xoffline.access":     false,
		"users.read offline.access.read": false,
		"users.readoffline.access":       false,
		"":                               false,
	} {
		if got := scopeGranted(scope, "offline.access"); got != want {
			t.Fatalf("scopeGranted(%q) = %v; want %v", scope, got, want)
		}
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

// idpPostJSON posts a form and decodes the JSON body.
func idpPostJSON(t *testing.T, endpoint string, form url.Values) map[string]any {
	t.Helper()
	_, body := idpPostFormJSON(t, endpoint, form, nil)
	return body
}

// idpPostFormJSON posts a form with optional headers, returning the status and
// the decoded JSON body so callers can assert an error response.
func idpPostFormJSON(t *testing.T, endpoint string, form url.Values, header map[string]string) (int, map[string]any) {
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
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode %s response: %v", endpoint, err)
	}
	return resp.StatusCode, body
}

func TestMicrosoftIdPTokenLegBindsRedirectAndScope(t *testing.T) {
	t.Parallel()
	idp, err := NewMicrosoftIdP()
	if err != nil {
		t.Fatalf("NewMicrosoftIdP: %v", err)
	}
	t.Cleanup(idp.Close)

	form := func(code string) url.Values {
		return url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {idp.ClientID},
			"client_secret": {idp.ClientSecret},
			"code":          {code},
			"redirect_uri":  {idpTestRedirect},
			"code_verifier": {idpTestVerifier},
		}
	}
	authorize := func() string {
		return idpAuthorizeScope(t, idp.Server.URL+"/authorize", idp.ClientID, "openid profile email")
	}
	tokenURL := idp.Server.URL + "/token"

	body := idpPostJSON(t, tokenURL, form(authorize()))
	if scope, _ := body["scope"].(string); scope != "openid profile email" {
		t.Fatalf("token scope = %q; want the granted %q", body["scope"], "openid profile email")
	}

	wrongRedirect := form(authorize())
	wrongRedirect.Set("redirect_uri", "http://attacker.example/callback")
	if got := idpPostForm(t, tokenURL, wrongRedirect, nil); got != http.StatusBadRequest {
		t.Fatalf("mismatched redirect_uri status = %d; want 400", got)
	}

	wrongScope := form(authorize())
	wrongScope.Set("scope", "openid profile offline_access")
	if got := idpPostForm(t, tokenURL, wrongScope, nil); got != http.StatusBadRequest {
		t.Fatalf("mismatched scope status = %d; want 400", got)
	}
}

func TestMicrosoftIdPTokenResponseKnobs(t *testing.T) {
	t.Parallel()

	claims := func(t *testing.T, idp *MicrosoftIdP) map[string]any {
		t.Helper()
		code := idpAuthorize(t, idp.Server.URL+"/authorize", idp.ClientID)
		body := idpPostJSON(t, idp.Server.URL+"/token", url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {idp.ClientID},
			"client_secret": {idp.ClientSecret},
			"code":          {code},
			"redirect_uri":  {idpTestRedirect},
			"code_verifier": {idpTestVerifier},
		})
		raw, _ := body["id_token"].(string)
		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			t.Fatalf("id_token = %q; want three jwt parts", raw)
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("decode id_token claims: %v", err)
		}
		var got map[string]any
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatalf("unmarshal id_token claims: %v", err)
		}
		return got
	}

	t.Run("unattested by default, attested on opt-in", func(t *testing.T) {
		idp, err := NewMicrosoftIdP()
		if err != nil {
			t.Fatalf("NewMicrosoftIdP: %v", err)
		}
		t.Cleanup(idp.Close)

		if _, ok := claims(t, idp)["xms_edov"]; ok {
			t.Fatal("default token must not carry xms_edov")
		}
		idp.AttestDomain()
		if edov, _ := claims(t, idp)["xms_edov"].(string); edov != "1" {
			t.Fatalf("xms_edov = %q; want %q after AttestDomain", edov, "1")
		}
	})

	t.Run("omit id_token", func(t *testing.T) {
		idp, err := NewMicrosoftIdP()
		if err != nil {
			t.Fatalf("NewMicrosoftIdP: %v", err)
		}
		t.Cleanup(idp.Close)
		idp.OmitIDToken = true

		body := idpPostJSON(t, idp.Server.URL+"/token", url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {idp.ClientID},
			"client_secret": {idp.ClientSecret},
			"code":          {idpAuthorize(t, idp.Server.URL+"/authorize", idp.ClientID)},
			"redirect_uri":  {idpTestRedirect},
			"code_verifier": {idpTestVerifier},
		})
		if _, ok := body["id_token"]; ok {
			t.Fatal("OmitIDToken must drop id_token from the token response")
		}
		if at, _ := body["access_token"].(string); at != msAccessToken {
			t.Fatalf("access_token = %q; want %q", at, msAccessToken)
		}
	})

	for _, tc := range []struct {
		fault IDTokenFault
		check func(t *testing.T, claims map[string]any)
	}{
		{
			fault: FaultBadIssuer,
			check: func(t *testing.T, c map[string]any) {
				t.Helper()
				if got, _ := c["iss"].(string); !strings.Contains(got, msForeignTenant) {
					t.Fatalf("iss = %q; want the foreign tenant %q", got, msForeignTenant)
				}
			},
		},
		{
			fault: FaultBadAudience,
			check: func(t *testing.T, c map[string]any) {
				t.Helper()
				if got, _ := c["aud"].(string); got == "ms-idp-client-id" {
					t.Fatal("aud must not name the configured client under FaultBadAudience")
				}
			},
		},
	} {
		t.Run(string(tc.fault), func(t *testing.T) {
			idp, err := NewMicrosoftIdP()
			if err != nil {
				t.Fatalf("NewMicrosoftIdP: %v", err)
			}
			t.Cleanup(idp.Close)
			idp.Fault = tc.fault

			tc.check(t, claims(t, idp))
		})
	}

	t.Run("bad signature", func(t *testing.T) {
		idp, err := NewMicrosoftIdP()
		if err != nil {
			t.Fatalf("NewMicrosoftIdP: %v", err)
		}
		t.Cleanup(idp.Close)
		idp.Fault = FaultBadSignature

		token, err := corruptSignature("a.b.c2ln")
		if err != nil {
			t.Fatalf("corruptSignature: %v", err)
		}
		if token == "a.b.c2ln" {
			t.Fatal("corruptSignature returned the input unchanged")
		}
		if claims(t, idp)["sub"] != idp.Subject {
			t.Fatal("FaultBadSignature must keep the claims intact")
		}
	})
}

func TestFacebookIdPDebugTokenVerdict(t *testing.T) {
	t.Parallel()
	idp := NewFacebookIdP()
	t.Cleanup(idp.Close)

	debugForm := func() url.Values {
		appToken := idp.AppID + "|" + idp.AppSecret
		return url.Values{
			"input_token":     {idp.userToken()},
			"access_token":    {appToken},
			"appsecret_proof": {hmacHex(idp.AppSecret, appToken)},
		}
	}
	verdict := func(t *testing.T) map[string]any {
		t.Helper()
		data, _ := idpPostJSON(t, idp.Server.URL+"/debug_token", debugForm())["data"].(map[string]any)
		if data == nil {
			t.Fatal("debug_token response missing data")
		}
		return data
	}

	if data := verdict(t); data["app_id"] != idp.AppID || data["is_valid"] != true {
		t.Fatalf("default verdict = %v; want app_id %q and is_valid true", data, idp.AppID)
	}
	idp.Debug.AppID = "fb-other-app-id"
	if data := verdict(t); data["app_id"] != "fb-other-app-id" {
		t.Fatalf("app_id = %v; want the configured foreign app", data["app_id"])
	}
	idp.Debug.IsValid = false
	if data := verdict(t); data["is_valid"] != false {
		t.Fatalf("is_valid = %v; want false", data["is_valid"])
	}
}
