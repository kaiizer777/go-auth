package oauth

import (
	"sync"

	"github.com/kaiizer777/go-auth/errors"
)

// Registry manages thread-safe registration and dynamic lookup of OAuth providers.
type Registry interface {
	// Register associates a provider with the registry using its canonical ID.
	Register(provider Provider) error

	// Get retrieves a registered provider by its unique slug.
	Get(providerID string) (Provider, error)

	// List returns a slice of all registered provider IDs.
	List() []string
}

type providerRegistry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry initializes an empty thread-safe provider registry.
func NewRegistry() Registry {
	return &providerRegistry{
		providers: make(map[string]Provider),
	}
}

func (r *providerRegistry) Register(p Provider) error {
	if p == nil {
		return errors.New(errors.CodeInvalidConfig, "cannot register nil oauth provider", nil)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.ID()] = p
	return nil
}

func (r *providerRegistry) Get(providerID string) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[providerID]
	if !ok {
		return nil, errors.New(errors.CodeOAuthProviderNotFound, "unsupported or unconfigured oauth provider: "+providerID, nil)
	}
	return p, nil
}

func (r *providerRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.providers))
	for k := range r.providers {
		keys = append(keys, k)
	}
	return keys
}
