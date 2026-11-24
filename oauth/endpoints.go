package oauth

// EndpointOverride replaces the provider endpoints an adapter talks to. An
// empty field keeps the adapter's production endpoint, so the zero value is a
// no-op. Tests point an adapter at a loopback IdP through this option.
//
// It is not trust-neutral. Overriding JWKSURL replaces the key set that signs
// every id_token the adapter accepts, and DiscoveryURL re-roots domain→tenant
// resolution, so anything that can reach these options can dictate identities.
// No config field feeds them and no production call site applies them (only
// WithEndpoints/FacebookEndpoints, all of which are test call sites), which is
// why the seam is safe to keep: it is unreachable from the public config path.
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
