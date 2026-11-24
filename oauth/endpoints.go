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
}

// EndpointOption customizes an adapter's endpoints before it is constructed.
type EndpointOption func(*EndpointOverride)

// WithEndpoints applies the non-empty overrides in o. Later options win per
// field, so callers can compose a base override with provider-specific ones.
func WithEndpoints(o EndpointOverride) EndpointOption {
	return func(dst *EndpointOverride) {
		if o.AuthorizeURL != "" {
			dst.AuthorizeURL = o.AuthorizeURL
		}
		if o.TokenURL != "" {
			dst.TokenURL = o.TokenURL
		}
		if o.UserInfoURL != "" {
			dst.UserInfoURL = o.UserInfoURL
		}
		if o.JWKSURL != "" {
			dst.JWKSURL = o.JWKSURL
		}
		if o.DebugURL != "" {
			dst.DebugURL = o.DebugURL
		}
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
