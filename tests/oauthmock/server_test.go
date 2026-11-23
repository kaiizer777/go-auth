package oauthmock

import (
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
