package oauth

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/kaiizer777/go-auth/errors"
)

type dummyProvider struct {
	id string
}

func (d *dummyProvider) ID() string {
	return d.id
}

func (d *dummyProvider) AuthURL(state, codeChallenge string) string {
	return "https://example.com/auth"
}

func (d *dummyProvider) AuthCodeURL(state, codeChallenge string, opts ...AuthCodeOption) string {
	return "https://example.com/auth"
}

func (d *dummyProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*OAuthToken, error) {
	return &OAuthToken{AccessToken: "token-" + d.id}, nil
}

func (d *dummyProvider) FetchUserInfo(ctx context.Context, tokens *OAuthToken) (*OAuthUser, error) {
	return &OAuthUser{ProviderID: d.id, ProviderUserID: "uid-" + d.id}, nil
}

func TestProviderRegistry(t *testing.T) {
	t.Run("rejects nil provider", func(t *testing.T) {
		reg := NewRegistry()
		err := reg.Register(nil)
		if err == nil {
			t.Fatal("expected error registering nil provider, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidConfig {
			t.Fatalf("expected CodeInvalidConfig, got %v", err)
		}
	})

	t.Run("rejects empty or whitespace provider id", func(t *testing.T) {
		reg := NewRegistry()
		for _, invalidID := range []string{"", "   ", "\t\n"} {
			err := reg.Register(&dummyProvider{id: invalidID})
			if err == nil {
				t.Fatalf("expected error for empty/whitespace id %q, got nil", invalidID)
			}
			var appErr *errors.Error
			if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidConfig {
				t.Fatalf("expected CodeInvalidConfig, got %v", err)
			}
		}
	})

	t.Run("rejects duplicate provider registration", func(t *testing.T) {
		reg := NewRegistry()
		p := &dummyProvider{id: "google"}
		if err := reg.Register(p); err != nil {
			t.Fatalf("unexpected error registering first provider: %v", err)
		}
		err := reg.Register(p)
		if err == nil {
			t.Fatal("expected error on duplicate registration, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidConfig {
			t.Fatalf("expected CodeInvalidConfig, got %v", err)
		}
	})

	t.Run("register and get", func(t *testing.T) {
		reg := NewRegistry()
		p1 := &dummyProvider{id: "google"}
		p2 := &dummyProvider{id: "microsoft"}

		if err := reg.Register(p1); err != nil {
			t.Fatalf("unexpected register error: %v", err)
		}
		if err := reg.Register(p2); err != nil {
			t.Fatalf("unexpected register error: %v", err)
		}

		got1, err := reg.Get("google")
		if err != nil || got1.ID() != "google" {
			t.Fatalf("failed to get google: %v", err)
		}

		got2, err := reg.Get("microsoft")
		if err != nil || got2.ID() != "microsoft" {
			t.Fatalf("failed to get microsoft: %v", err)
		}

		_, err = reg.Get("unknown")
		if err == nil {
			t.Fatal("expected error getting unknown provider, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthProviderNotFound {
			t.Fatalf("expected CodeOAuthProviderNotFound, got %v", err)
		}

		list := reg.List()
		if len(list) != 2 {
			t.Fatalf("expected 2 items in list, got %d", len(list))
		}
		if list[0] != "google" || list[1] != "microsoft" {
			t.Fatalf("expected sorted list [google, microsoft], got %v", list)
		}
	})

	t.Run("thread-safe concurrent access", func(t *testing.T) {
		reg := NewRegistry()
		var wg sync.WaitGroup

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				p := &dummyProvider{id: fmt.Sprintf("provider-%d", id)}
				_ = reg.Register(p)
			}(i)
		}

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				_, _ = reg.Get(fmt.Sprintf("provider-%d", id))
				_ = reg.List()
			}(i)
		}

		wg.Wait()
		list := reg.List()
		if len(list) == 0 {
			t.Fatal("expected registered providers in list")
		}
	})

	t.Run("service wires dynamic registry lookup", func(t *testing.T) {
		reg := NewRegistry()
		_ = reg.Register(&dummyProvider{id: "google"})

		svc := NewServiceWithRegistry(nil, nil, reg, nil)
		s, ok := svc.(*service)
		if !ok {
			t.Fatalf("expected *service, got %T", svc)
		}

		p, err := s.providerFor("google")
		if err != nil || p == nil || p.ID() != "google" {
			t.Fatalf("expected google provider from registry, got %v, err=%v", p, err)
		}

		_, err = s.providerFor("x")
		if !errors.Is(err, errors.ErrOAuthProviderNotFound) {
			t.Fatalf("expected ErrOAuthProviderNotFound for unregistered x, got %v", err)
		}
	})
}
