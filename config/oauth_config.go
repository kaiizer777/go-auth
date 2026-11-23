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
	ClientSecret   string        `json:"-"` // Redacted in logs
	Tenant         string        `json:"tenant"` // "common", "organizations", "consumers", or specific tenant GUID
	TrustedTenants []string      `json:"trusted_tenants,omitempty"` // Whitelisted tenant GUIDs for multi-tenant linking
	RedirectURI    string        `json:"redirect_uri"`
	Scopes         []string      `json:"scopes"`
	JWKSCacheTTL   time.Duration `json:"jwks_cache_ttl"` // Default: 24h
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
