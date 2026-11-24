package oauthmock

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestMockOAuthServers(t *testing.T) {
	s, err := NewMockServers()
	if err != nil {
		t.Fatalf("failed to create mock servers: %v", err)
	}
	defer s.Close()

	if s.MicrosoftServer == nil || s.XServer == nil || s.FacebookServer == nil || s.DiscordServer == nil {
		t.Fatal("expected all 4 mock servers initialized")
	}

	msCfg := s.MicrosoftConfig()
	if msCfg.ClientID == "" {
		t.Fatal("expected valid ms config")
	}

	xCfg := s.XConfig()
	if xCfg.ClientID == "" {
		t.Fatal("expected valid x config")
	}

	fbCfg := s.FacebookConfig()
	if fbCfg.AppID == "" {
		t.Fatal("expected valid fb config")
	}

	discordCfg := s.DiscordConfig()
	if discordCfg.ClientID == "" {
		t.Fatal("expected valid discord config")
	}
}

func TestMockMicrosoftJWKSAdvertisesIssuer(t *testing.T) {
	s, err := NewMockServers()
	if err != nil {
		t.Fatalf("failed to create mock servers: %v", err)
	}
	defer s.Close()

	const issuer = "https://login.microsoftonline.com/{tenantid}/v2.0"
	s.MSKeyIssuer = issuer

	resp, err := http.Get(s.MicrosoftServer.URL + "/keys")
	if err != nil {
		t.Fatalf("fetch jwks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var doc struct {
		Keys []struct {
			Kid    string `json:"kid"`
			Issuer string `json:"issuer"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(doc.Keys) == 0 {
		t.Fatal("expected at least one jwk")
	}
	for _, k := range doc.Keys {
		if k.Issuer != issuer {
			t.Fatalf("kid %q issuer = %q; want %q", k.Kid, k.Issuer, issuer)
		}
	}
}
