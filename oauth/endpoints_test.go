package oauth

import (
	"testing"

	"github.com/kaiizer777/go-auth/config"
)

func TestEndpointOverrideReplacesEveryAdapterEndpoint(t *testing.T) {
	t.Parallel()
	ep := EndpointOverride{
		AuthorizeURL: "http://idp.test/authorize",
		TokenURL:     "http://idp.test/token",
		UserInfoURL:  "http://idp.test/userinfo",
		JWKSURL:      "http://idp.test/keys",
		DebugURL:     "http://idp.test/debug",
	}

	ms := NewMicrosoftProvider(config.MicrosoftConfig{}, WithEndpoints(ep))
	if ms.authURL != ep.AuthorizeURL || ms.tokenURL != ep.TokenURL ||
		ms.userinfoURL != ep.UserInfoURL || ms.jwksURL != ep.JWKSURL {
		t.Fatalf("microsoft endpoints = %q %q %q %q; want %+v",
			ms.authURL, ms.tokenURL, ms.userinfoURL, ms.jwksURL, ep)
	}

	fb := NewFacebookProvider(config.FacebookConfig{}, FacebookEndpoints(ep))
	if fb.authURL != ep.AuthorizeURL || fb.tokenURL != ep.TokenURL ||
		fb.userInfoURL != ep.UserInfoURL || fb.debugURL != ep.DebugURL {
		t.Fatalf("facebook endpoints = %q %q %q %q; want %+v",
			fb.authURL, fb.tokenURL, fb.userInfoURL, fb.debugURL, ep)
	}

	discord := NewDiscordProvider(config.DiscordConfig{}, WithEndpoints(ep))
	if discord.authURL != ep.AuthorizeURL || discord.tokenURL != ep.TokenURL || discord.userInfoURL != ep.UserInfoURL {
		t.Fatalf("discord endpoints = %q %q %q; want %+v",
			discord.authURL, discord.tokenURL, discord.userInfoURL, ep)
	}

	x := NewXProvider(config.XConfig{}, WithEndpoints(ep))
	if x.authURL != ep.AuthorizeURL || x.tokenURL != ep.TokenURL || x.userInfoURL != ep.UserInfoURL {
		t.Fatalf("x endpoints = %q %q %q; want %+v", x.authURL, x.tokenURL, x.userInfoURL, ep)
	}
}

func TestEndpointOverrideLeavesUnsetEndpointsAtProductionDefaults(t *testing.T) {
	t.Parallel()

	ms := NewMicrosoftProvider(config.MicrosoftConfig{Tenant: "contoso.onmicrosoft.com"},
		WithEndpoints(EndpointOverride{TokenURL: "http://idp.test/token"}))
	if ms.tokenURL != "http://idp.test/token" {
		t.Fatalf("microsoft tokenURL = %q; want override", ms.tokenURL)
	}
	if ms.authURL != "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize" {
		t.Fatalf("microsoft authURL = %q; want production default", ms.authURL)
	}
	if ms.jwksURL != "https://login.microsoftonline.com/contoso.onmicrosoft.com/discovery/v2.0/keys" {
		t.Fatalf("microsoft jwksURL = %q; want production default", ms.jwksURL)
	}
	if ms.userinfoURL != "https://graph.microsoft.com/oidc/userinfo" {
		t.Fatalf("microsoft userinfoURL = %q; want production default", ms.userinfoURL)
	}

	fb := NewFacebookProvider(config.FacebookConfig{})
	if fb.authURL != "https://www.facebook.com/v19.0/dialog/oauth" ||
		fb.tokenURL != "https://graph.facebook.com/v19.0/oauth/access_token" ||
		fb.debugURL != "https://graph.facebook.com/debug_token" ||
		fb.userInfoURL != "https://graph.facebook.com/v19.0/me" {
		t.Fatalf("facebook defaults = %q %q %q %q", fb.authURL, fb.tokenURL, fb.debugURL, fb.userInfoURL)
	}

	discord := NewDiscordProvider(config.DiscordConfig{})
	if discord.authURL != "https://discord.com/oauth2/authorize" ||
		discord.tokenURL != "https://discord.com/api/v10/oauth2/token" ||
		discord.userInfoURL != "https://discord.com/api/v10/users/@me" {
		t.Fatalf("discord defaults = %q %q %q", discord.authURL, discord.tokenURL, discord.userInfoURL)
	}

	x := NewXProvider(config.XConfig{})
	if x.authURL != "https://twitter.com/i/oauth2/authorize" ||
		x.tokenURL != "https://api.twitter.com/2/oauth2/token" ||
		x.userInfoURL != "https://api.twitter.com/2/users/me" {
		t.Fatalf("x defaults = %q %q %q", x.authURL, x.tokenURL, x.userInfoURL)
	}
}
