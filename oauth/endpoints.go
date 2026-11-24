package oauth

// EndpointOverride replaces the provider endpoints an adapter talks to. An
// empty field keeps the adapter's production endpoint, so the zero value is a
// no-op. Tests point an adapter at a loopback IdP through this option; nothing
// else changes the adapter's identity, verification, or trust decisions.
type EndpointOverride struct {
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string
	JWKSURL      string
	DebugURL     string
	// DiscoveryURL is the origin domain→tenant lookups are rooted at.
	DiscoveryURL string
}

// EndpointOption customizes an adapter's endpoints before it is constructed.
type EndpointOption func(*EndpointOverride)

// WithEndpoints applies the non-empty overrides in o. Later options win per
// field, so callers can compose a base override with provider-specific ones.
func WithEndpoints(o EndpointOverride) EndpointOption {
	return func(dst *EndpointOverride) {
		applyEndpoints(dst, o)
	}
}

// applyEndpoints merges the non-empty fields of src into dst.
func applyEndpoints(dst *EndpointOverride, src EndpointOverride) {
	if src.AuthorizeURL != "" {
		dst.AuthorizeURL = src.AuthorizeURL
	}
	if src.TokenURL != "" {
		dst.TokenURL = src.TokenURL
	}
	if src.UserInfoURL != "" {
		dst.UserInfoURL = src.UserInfoURL
	}
	if src.JWKSURL != "" {
		dst.JWKSURL = src.JWKSURL
	}
	if src.DebugURL != "" {
		dst.DebugURL = src.DebugURL
	}
	if src.DiscoveryURL != "" {
		dst.DiscoveryURL = src.DiscoveryURL
	}
}

// resolveEndpoints applies opts over an adapter's production defaults.
func resolveEndpoints(defaults EndpointOverride, opts []EndpointOption) EndpointOverride {
	ep := defaults
	for _, opt := range opts {
		if opt != nil {
			opt(&ep)
		}
	}
	return ep
}
