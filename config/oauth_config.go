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
