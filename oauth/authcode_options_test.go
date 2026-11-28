package oauth

import (
	"net/url"
	"testing"

	"github.com/kaiizer777/go-auth/config"
)

func TestAuthCodeURLReservedParamsGuarded(t *testing.T) {
	t.Parallel()
	ids := []string{"google", "github", "apple", "microsoft", "facebook", "discord", "x"}
	for _, id := range ids {
		p, err := NewProvider(id, config.ProviderConfig{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "https://app.example.com/cb",
		})
		if err != nil {
			t.Fatalf("NewProvider(%q) = %v", id, err)
		}
		ac, ok := p.(AuthCodeURLProvider)
		if !ok {
			t.Fatalf("%s: provider does not implement AuthCodeURLProvider", id)
		}
		raw := ac.AuthCodeURL("real-state", "real-challenge",
			AuthCodeOption{Key: "state", Value: "evil"},
			AuthCodeOption{Key: "STATE", Value: "evil"},
			AuthCodeOption{Key: "redirect_uri", Value: "https://evil.example/"},
			AuthCodeOption{Key: "code_challenge", Value: "evil"},
			AuthCodeOption{Key: "code_challenge_method", Value: "plain"},
			AuthCodeOption{Key: "response_type", Value: "token"},
			AuthCodeOption{Key: "client_id", Value: "evil"},
			AuthCodeOption{Key: "code_challenge", Value: ""},
			PromptOption("consent"),
			NonceOption("n-123"),
			AuthCodeOption{Key: "custom", Value: "1"},
		)
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%s: parse AuthCodeURL: %v", id, err)
		}
		q := u.Query()
		if q.Get("state") != "real-state" {
			t.Errorf("%s: state = %q; want real-state", id, q.Get("state"))
		}
		if q.Get("code_challenge") != "real-challenge" {
			t.Errorf("%s: code_challenge = %q; want real-challenge", id, q.Get("code_challenge"))
		}
		if q.Get("code_challenge_method") != "S256" {
			t.Errorf("%s: code_challenge_method = %q; want S256", id, q.Get("code_challenge_method"))
		}
		// github never sends response_type; the guard only ensures evil "token" lands nowhere.
		if id != "github" && q.Get("response_type") != "code" {
			t.Errorf("%s: response_type = %q; want code", id, q.Get("response_type"))
		}
		if q.Get("response_type") == "token" {
			t.Errorf("%s: response_type overwritten by option", id)
		}
		if q.Get("redirect_uri") != "https://app.example.com/cb" {
			t.Errorf("%s: redirect_uri = %q; want service value", id, q.Get("redirect_uri"))
		}
		if q.Get("prompt") != "consent" || q.Get("nonce") != "n-123" || q.Get("custom") != "1" {
			t.Errorf("%s: additive opts lost: prompt=%q nonce=%q custom=%q", id, q.Get("prompt"), q.Get("nonce"), q.Get("custom"))
		}
		if q.Get("client_id") != "test-client" {
			t.Errorf("%s: client_id = %q; want test-client", id, q.Get("client_id"))
		}
	}
}
