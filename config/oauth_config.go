package config

import (
	"fmt"
	"log/slog"
	"time"
)

// MicrosoftTenantType defines tenant scoping for Microsoft Entra ID.
type MicrosoftTenantType string

const (
	TenantCommon        MicrosoftTenantType = "common"
	TenantOrganizations MicrosoftTenantType = "organizations"
	TenantConsumers     MicrosoftTenantType = "consumers"
)

// MicrosoftConfig defines configuration for Microsoft Entra ID (Azure AD).
type MicrosoftConfig struct {
	ClientID       string        `json:"client_id"`
	ClientSecret   string        `json:"-"`                         // Redacted in logs
	Tenant         string        `json:"tenant"`                    // "common", "organizations", "consumers", or specific tenant GUID
	TrustedTenants []string      `json:"trusted_tenants,omitempty"` // Whitelisted tenant GUIDs for multi-tenant linking
	RedirectURI    string        `json:"redirect_uri"`
	Scopes         []string      `json:"scopes"`
	JWKSCacheTTL   time.Duration `json:"jwks_cache_ttl"` // Default: 24h
	// Enabled disables the provider when explicitly false. Absent means enabled.
	Enabled *bool `json:"enabled,omitempty"`
}

// LogValue implements slog.LogValuer to ensure ClientSecret is redacted in logs.
func (m MicrosoftConfig) LogValue() slog.Value {
	secretMasked := "[REDACTED]"
	if m.ClientSecret == "" {
		secretMasked = ""
	}
	return slog.GroupValue(
		slog.String("client_id", m.ClientID),
		slog.String("client_secret", secretMasked),
		slog.String("tenant", m.Tenant),
		slog.String("redirect_uri", m.RedirectURI),
		slog.Any("trusted_tenants", m.TrustedTenants),
		slog.Any("scopes", m.Scopes),
		slog.Duration("jwks_cache_ttl", m.JWKSCacheTTL),
	)
}

// String implements fmt.Stringer to ensure ClientSecret is masked when printed.
func (m MicrosoftConfig) String() string {
	secret := "[REDACTED]"
	if m.ClientSecret == "" {
		secret = ""
	}
	return fmt.Sprintf("MicrosoftConfig{ClientID: %s, ClientSecret: %s, Tenant: %s, RedirectURI: %s, Scopes: %v, JWKSCacheTTL: %v}",
		m.ClientID, secret, m.Tenant, m.RedirectURI, m.Scopes, m.JWKSCacheTTL)
}

// DiscordConfig defines configuration for Discord OAuth.
type DiscordConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"-"` // Redacted in logs
	RedirectURI  string   `json:"redirect_uri"`
	Scopes       []string `json:"scopes"`
	// Enabled disables the provider when explicitly false. Absent means enabled.
	Enabled *bool `json:"enabled,omitempty"`
}

// LogValue implements slog.LogValuer to ensure ClientSecret is redacted in logs.
func (d DiscordConfig) LogValue() slog.Value {
	secretMasked := "[REDACTED]"
	if d.ClientSecret == "" {
		secretMasked = ""
	}
	return slog.GroupValue(
		slog.String("client_id", d.ClientID),
		slog.String("client_secret", secretMasked),
		slog.String("redirect_uri", d.RedirectURI),
		slog.Any("scopes", d.Scopes),
	)
}

// String implements fmt.Stringer to ensure ClientSecret is masked when printed.
func (d DiscordConfig) String() string {
	secret := "[REDACTED]"
	if d.ClientSecret == "" {
		secret = ""
	}
	return fmt.Sprintf("DiscordConfig{ClientID: %s, ClientSecret: %s, RedirectURI: %s, Scopes: %v}",
		d.ClientID, secret, d.RedirectURI, d.Scopes)
}

// FacebookConfig defines configuration for Facebook Graph API.
type FacebookConfig struct {
	AppID        string   `json:"app_id"`
	AppSecret    string   `json:"-"` // Redacted in logs
	RedirectURI  string   `json:"redirect_uri"`
	Scopes       []string `json:"scopes"`
	GraphVersion string   `json:"graph_version"` // Default: "v19.0"
	// Enabled disables the provider when explicitly false. Absent means enabled.
	Enabled *bool `json:"enabled,omitempty"`
}

// LogValue implements slog.LogValuer to ensure AppSecret is redacted in logs.
func (f FacebookConfig) LogValue() slog.Value {
	secretMasked := "[REDACTED]"
	if f.AppSecret == "" {
		secretMasked = ""
	}
	return slog.GroupValue(
		slog.String("app_id", f.AppID),
		slog.String("app_secret", secretMasked),
		slog.String("redirect_uri", f.RedirectURI),
		slog.Any("scopes", f.Scopes),
		slog.String("graph_version", f.GraphVersion),
	)
}

// String implements fmt.Stringer to ensure AppSecret is masked when printed.
func (f FacebookConfig) String() string {
	secret := "[REDACTED]"
	if f.AppSecret == "" {
		secret = ""
	}
	return fmt.Sprintf("FacebookConfig{AppID: %s, AppSecret: %s, RedirectURI: %s, Scopes: %v, GraphVersion: %s}",
		f.AppID, secret, f.RedirectURI, f.Scopes, f.GraphVersion)
}

// XConfig defines configuration for X (formerly Twitter) OAuth 2.0.
type XConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"-"` // Redacted in logs
	RedirectURI  string   `json:"redirect_uri"`
	Scopes       []string `json:"scopes"`
	// Enabled disables the provider when explicitly false. Absent means enabled.
	Enabled *bool `json:"enabled,omitempty"`
}

// LogValue implements slog.LogValuer to ensure ClientSecret is redacted in logs.
func (x XConfig) LogValue() slog.Value {
	secretMasked := "[REDACTED]"
	if x.ClientSecret == "" {
		secretMasked = ""
	}
	return slog.GroupValue(
		slog.String("client_id", x.ClientID),
		slog.String("client_secret", secretMasked),
		slog.String("redirect_uri", x.RedirectURI),
		slog.Any("scopes", x.Scopes),
	)
}

// String implements fmt.Stringer to ensure ClientSecret is masked when printed.
func (x XConfig) String() string {
	secret := "[REDACTED]"
	if x.ClientSecret == "" {
		secret = ""
	}
	return fmt.Sprintf("XConfig{ClientID: %s, ClientSecret: %s, RedirectURI: %s, Scopes: %v}",
		x.ClientID, secret, x.RedirectURI, x.Scopes)
}

// resolveProviders folds the typed per-provider sections into Providers, then
// defaults the merged entries. Running on raw inputs keeps "unset" and
// "defaulted" distinguishable: an explicit typed field wins over the map entry,
// the map entry wins over a default, and a default is written only when the
// merged value is still unset.
func (o *OAuthConfig) resolveProviders() {
	if len(o.Providers) == 0 && o.Microsoft == nil && o.Facebook == nil && o.Discord == nil && o.X == nil {
		return
	}
	merged := make(map[string]ProviderConfig, len(o.Providers)+4)
	for id, p := range o.Providers {
		merged[id] = p
	}
	for id, tp := range o.typedProviders() {
		base, hasEntry := merged[id]
		merged[id] = mergeProviderConfig(base, hasEntry, tp)
	}
	for id, p := range merged {
		applyProviderDefaults(id, &p)
		merged[id] = p
	}
	o.Providers = merged
}

// anyProviderEnabled reports whether any configured provider would register.
// A typed section registers unless it is explicitly disabled; a map entry
// registers only when it is explicitly enabled.
func (o *OAuthConfig) anyProviderEnabled() bool {
	typed := o.typedProviders()
	for id, p := range o.Providers {
		t, hasTyped := typed[id]
		if resolveEnabled(true, p.Enabled, hasTyped, t.enabled) {
			return true
		}
		delete(typed, id)
	}
	for _, tp := range typed {
		if resolveEnabled(false, false, true, tp.enabled) {
			return true
		}
	}
	return false
}

// typedProvider is a typed section projected onto the neutral shape, plus the
// tri-state enable switch that shape cannot carry.
type typedProvider struct {
	cfg     ProviderConfig
	enabled *bool
}

// typedProviders projects the typed sections. ClientID is not filtered here:
// Config.Validate rejects a typed section without one.
func (o *OAuthConfig) typedProviders() map[string]typedProvider {
	typed := make(map[string]typedProvider, 4)
	if m := o.Microsoft; m != nil {
		typed["microsoft"] = typedProvider{
			enabled: m.Enabled,
			cfg: ProviderConfig{
				ClientID:       m.ClientID,
				ClientSecret:   m.ClientSecret,
				RedirectURL:    m.RedirectURI,
				Scopes:         m.Scopes,
				Tenant:         m.Tenant,
				TrustedTenants: m.TrustedTenants,
				JWKSCacheTTL:   m.JWKSCacheTTL,
			},
		}
	}
	if f := o.Facebook; f != nil {
		typed["facebook"] = typedProvider{
			enabled: f.Enabled,
			cfg: ProviderConfig{
				ClientID:     f.AppID,
				ClientSecret: f.AppSecret,
				RedirectURL:  f.RedirectURI,
				Scopes:       f.Scopes,
				GraphVersion: f.GraphVersion,
			},
		}
	}
	if d := o.Discord; d != nil {
		typed["discord"] = typedProvider{
			enabled: d.Enabled,
			cfg: ProviderConfig{
				ClientID:     d.ClientID,
				ClientSecret: d.ClientSecret,
				RedirectURL:  d.RedirectURI,
				Scopes:       d.Scopes,
			},
		}
	}
	if x := o.X; x != nil {
		typed["x"] = typedProvider{
			enabled: x.Enabled,
			cfg: ProviderConfig{
				ClientID:     x.ClientID,
				ClientSecret: x.ClientSecret,
				RedirectURL:  x.RedirectURI,
				Scopes:       x.Scopes,
			},
		}
	}
	return typed
}

func mergeProviderConfig(base ProviderConfig, hasEntry bool, typed typedProvider) ProviderConfig {
	base.Enabled = resolveEnabled(hasEntry, base.Enabled, true, typed.enabled)
	if typed.cfg.ClientID != "" {
		base.ClientID = typed.cfg.ClientID
	}
	if typed.cfg.ClientSecret != "" {
		base.ClientSecret = typed.cfg.ClientSecret
	}
	if typed.cfg.RedirectURL != "" {
		base.RedirectURL = typed.cfg.RedirectURL
	}
	if len(typed.cfg.Scopes) > 0 {
		base.Scopes = typed.cfg.Scopes
	}
	if typed.cfg.Tenant != "" {
		base.Tenant = typed.cfg.Tenant
	}
	if len(typed.cfg.TrustedTenants) > 0 {
		base.TrustedTenants = typed.cfg.TrustedTenants
	}
	if typed.cfg.JWKSCacheTTL > 0 {
		base.JWKSCacheTTL = typed.cfg.JWKSCacheTTL
	}
	if typed.cfg.GraphVersion != "" {
		base.GraphVersion = typed.cfg.GraphVersion
	}
	return base
}

// resolveEnabled applies the cross-surface enable switch: an explicit false on
// either surface disables the provider, so neither surface can resurrect a
// provider the other one switched off. An absent switch is neutral.
func resolveEnabled(hasEntry, mapEnabled, hasTyped bool, typedEnabled *bool) bool {
	if !hasEntry && !hasTyped {
		return false
	}
	if hasEntry && !mapEnabled {
		return false
	}
	if typedEnabled != nil {
		return *typedEnabled
	}
	return true
}

// applyProviderDefaults fills the unset fields of a merged entry; it is the only
// place provider defaults are applied.
func applyProviderDefaults(id string, p *ProviderConfig) {
	switch id {
	case "microsoft":
		if p.Tenant == "" {
			p.Tenant = "common"
		}
		if len(p.Scopes) == 0 {
			p.Scopes = []string{"openid", "profile", "email", "offline_access"}
		}
		if p.JWKSCacheTTL <= 0 {
			p.JWKSCacheTTL = 24 * time.Hour
		}
	case "facebook":
		if p.GraphVersion == "" {
			p.GraphVersion = "v19.0"
		}
		if len(p.Scopes) == 0 {
			p.Scopes = []string{"email", "public_profile"}
		}
	case "discord":
		if len(p.Scopes) == 0 {
			p.Scopes = []string{"identify", "email"}
		}
	case "x":
		if len(p.Scopes) == 0 {
			p.Scopes = []string{"tweet.read", "users.read", "offline.access"}
		}
	}
}
