package config

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
)

// Re-exported payload and hook types owned by email package.
type VerificationEmailPayload = email.VerificationEmailPayload
type PasswordResetEmailPayload = email.PasswordResetEmailPayload
type SendVerificationEmailFunc = email.SendVerificationEmailFunc
type SendPasswordResetEmailFunc = email.SendPasswordResetEmailFunc

// Argon2Config defines cryptographic parameters for Argon2id password hashing.
type Argon2Config struct {
	Memory      uint32 // KiB per hash. Min: 19456. Default: 65536 (64 MiB)
	Time        uint32 // Iterations. Min: 2. Default: 3
	Parallelism uint8  // Threads. Min: 1. Default: 4
	SaltLength  uint32 // Bytes. Min: 16. Default: 16
	KeyLength   uint32 // Output bytes. Min: 32. Default: 32
}

// ProviderConfig defines client credentials and scopes for a single OAuth provider.
type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Enabled      bool

	// Apple-specific credentials for dynamic ES256 client_secret JWT signing
	TeamID     string // 10-character Apple Developer Team ID
	KeyID      string // 10-character Apple Developer Key ID
	PrivateKey string // PEM-encoded PKCS#8 ECDSA private key (.p8 content)

	// Authority settings shared across adapters; currently consumed only by
	// Microsoft Entra ID. Empty Tenant and non-positive JWKSCacheTTL fall back
	// to provider defaults ("common" / 24h). Empty TrustedTenants means no
	// allowlist: every tenant the configured authority admits stays trusted. A
	// non-empty allowlist marks unlisted tenants untrusted and evicts their
	// existing links on the next callback.
	Tenant         string        `json:"tenant,omitempty"`
	TrustedTenants []string      `json:"trusted_tenants,omitempty"`
	JWKSCacheTTL   time.Duration `json:"jwks_cache_ttl,omitempty"`

	// GraphVersion pins the Facebook Graph API version (e.g. "v19.0"); ignored
	// by every other adapter.
	GraphVersion string `json:"graph_version,omitempty"`

	// AssertEmailVerified declares that the operator trusts a non-empty email
	// from the Facebook Graph API as provider-verified, which enables the
	// existing-account merge. Default false keeps the address unattested;
	// ignored by every other adapter.
	AssertEmailVerified bool `json:"assert_email_verified,omitempty"`
}

// LogValue implements slog.LogValuer to ensure ClientSecret and PrivateKey are masked in logs.
func (p ProviderConfig) LogValue() slog.Value {
	secretMasked := "[REDACTED]"
	if p.ClientSecret == "" {
		secretMasked = ""
	}
	keyMasked := "[REDACTED]"
	if p.PrivateKey == "" {
		keyMasked = ""
	}
	return slog.GroupValue(
		slog.String("client_id", p.ClientID),
		slog.String("client_secret", secretMasked),
		slog.String("redirect_url", p.RedirectURL),
		slog.Any("scopes", p.Scopes),
		slog.Bool("enabled", p.Enabled),
		slog.String("team_id", p.TeamID),
		slog.String("key_id", p.KeyID),
		slog.String("private_key", keyMasked),
		slog.String("tenant", p.Tenant),
		slog.Any("trusted_tenants", p.TrustedTenants),
		slog.Duration("jwks_cache_ttl", p.JWKSCacheTTL),
		slog.String("graph_version", p.GraphVersion),
		slog.Bool("assert_email_verified", p.AssertEmailVerified),
	)
}

// String implements fmt.Stringer to ensure ClientSecret is masked when printed.
func (p ProviderConfig) String() string {
	secret := "[REDACTED]"
	if p.ClientSecret == "" {
		secret = ""
	}
	return fmt.Sprintf("ProviderConfig{ClientID: %s, ClientSecret: %s, RedirectURL: %s}", p.ClientID, secret, p.RedirectURL)
}

// OAuthConfig groups configurations for all external identity providers.
type OAuthConfig struct {
	// Providers maps provider ID ("google", "github", "apple", "microsoft") to provider configuration.
	// Validate merges the typed sections below into this map and applies provider
	// defaults there, so after validation this map is the authoritative source.
	Providers       map[string]ProviderConfig
	Microsoft       *MicrosoftConfig `json:"microsoft,omitempty"`
	Facebook        *FacebookConfig  `json:"facebook,omitempty"`
	Discord         *DiscordConfig   `json:"discord,omitempty"`
	X               *XConfig         `json:"x,omitempty"`
	StateCookieName string           // Default: "oauth_state"
	StateCookiePath string           // Default: "/" (ensures cookies are sent on /auth/oauth/* and /api/auth/oauth/*)
	StateTTL        time.Duration    // Default: 10 * time.Minute
	StateSecret     string           // Required when any OAuth provider is enabled; empty fails closed at startup. Min 32 bytes.
	CallbackBaseURL string           // e.g. "https://api.example.com"
	// StateCookieSameSite is the base SameSite policy for the OAuth state
	// cookie on GET-redirect flows. Default: Lax. form_post providers (Apple)
	// always escalate to None+Secure regardless, since browsers withhold Lax
	// on cross-site POST navigations.
	StateCookieSameSite http.SameSite
}

// LogValue implements slog.LogValuer to ensure StateSecret and nested provider secrets are redacted.
func (o OAuthConfig) LogValue() slog.Value {
	secretMasked := "[REDACTED]"
	if o.StateSecret == "" {
		secretMasked = ""
	}
	providerAttrs := make([]slog.Attr, 0, len(o.Providers))
	for name, provider := range o.Providers {
		providerAttrs = append(providerAttrs, slog.Any(name, provider.LogValue()))
	}
	attrs := []slog.Attr{
		slog.String("state_secret", secretMasked),
		slog.String("state_cookie_name", o.StateCookieName),
		slog.String("state_cookie_path", o.StateCookiePath),
		slog.Duration("state_ttl", o.StateTTL),
		slog.String("callback_base_url", o.CallbackBaseURL),
	}
	if len(providerAttrs) > 0 {
		attrs = append(attrs, slog.Attr{Key: "providers", Value: slog.GroupValue(providerAttrs...)})
	}
	if o.Microsoft != nil {
		attrs = append(attrs, slog.Any("microsoft", o.Microsoft.LogValue()))
	}
	if o.Facebook != nil {
		attrs = append(attrs, slog.Any("facebook", o.Facebook.LogValue()))
	}
	if o.Discord != nil {
		attrs = append(attrs, slog.Any("discord", o.Discord.LogValue()))
	}
	if o.X != nil {
		attrs = append(attrs, slog.Any("x", o.X.LogValue()))
	}
	return slog.GroupValue(attrs...)
}

// String implements fmt.Stringer to ensure StateSecret is masked when printed.
func (o OAuthConfig) String() string {
	secret := "[REDACTED]"
	if o.StateSecret == "" {
		secret = ""
	}
	return fmt.Sprintf("OAuthConfig{Providers: %v, Microsoft: %v, Facebook: %v, Discord: %v, X: %v, StateSecret: %s, CallbackBaseURL: %s}",
		o.Providers, o.Microsoft, o.Facebook, o.Discord, o.X, secret, o.CallbackBaseURL)
}

// SecurityHeadersConfig groups HTTP security header policies.
// Struct fields are ordered largest-to-smallest to eliminate memory alignment padding.
type SecurityHeadersConfig struct {
	FrameOptions          string        // Default: "DENY" ("DENY" or "SAMEORIGIN")
	ReferrerPolicy        string        // Default: "strict-origin-when-cross-origin"
	ContentSecurityPolicy string        // Default: "default-src 'self'; frame-ancestors 'none'"
	HSTSMaxAge            time.Duration // Default: 365 * 24 * time.Hour (1 year)
	EnableHSTS            bool          // Default: true
	HSTSIncludeSubdomains bool          // Default: true
	HSTSPreload           bool          // Default: false
}

// TOTPConfig groups configuration settings for RFC 6238 TOTP two-factor authentication.
type TOTPConfig struct {
	EncryptionKey        string        // 64-hex AES-256 key (32 bytes)
	Issuer               string        // App name / issuer for OTP URI; default "go-auth"
	ChallengeTokenTTL    time.Duration // Default: 10m; valid range: 1m–30m
	AttemptWindow        time.Duration // Default: 5m; min: 1m
	MaxAttemptsPerWindow int           // Default: 5; min: 1
}

// LogValue implements slog.LogValuer to prevent secret encryption key leakage in logs.
func (t TOTPConfig) LogValue() slog.Value {
	keyMasked := "[REDACTED]"
	if t.EncryptionKey == "" {
		keyMasked = ""
	}
	return slog.GroupValue(
		slog.String("encryption_key", keyMasked),
		slog.String("issuer", t.Issuer),
		slog.Duration("challenge_token_ttl", t.ChallengeTokenTTL),
		slog.Duration("attempt_window", t.AttemptWindow),
		slog.Int("max_attempts_per_window", t.MaxAttemptsPerWindow),
	)
}

// String implements fmt.Stringer to ensure EncryptionKey is masked when formatted.
func (t TOTPConfig) String() string {
	keyMasked := "[REDACTED]"
	if t.EncryptionKey == "" {
		keyMasked = ""
	}
	return fmt.Sprintf("TOTPConfig{EncryptionKey: %s, Issuer: %s, ChallengeTokenTTL: %v, AttemptWindow: %v, MaxAttemptsPerWindow: %d}",
		keyMasked, t.Issuer, t.ChallengeTokenTTL, t.AttemptWindow, t.MaxAttemptsPerWindow)
}

// DefaultTOTPConfig returns safe production defaults for TOTP configuration.
func DefaultTOTPConfig() TOTPConfig {
	return TOTPConfig{
		Issuer:               "go-auth",
		ChallengeTokenTTL:    10 * time.Minute,
		MaxAttemptsPerWindow: 5,
		AttemptWindow:        5 * time.Minute,
	}
}

// DatabaseType specifies the supported persistence backend dialect.
type DatabaseType string

const (
	DatabaseTypePostgres DatabaseType = "postgres"
	DatabaseTypeMySQL    DatabaseType = "mysql"
	DatabaseTypeMongo    DatabaseType = "mongodb"
	DatabaseTypeMongoDB  DatabaseType = "mongodb"
)

// MySQLConfig holds dialect-specific settings for MySQL/MariaDB connections.
type MySQLConfig struct {
	Collation string
}

// MongoDBConfig holds dialect-specific settings for MongoDB connections.
type MongoDBConfig struct {
	Database                   string
	DatabaseName               string
	ConnectTimeout             time.Duration
	ServerSelectionTimeout     time.Duration
	MaxConnIdleTime            time.Duration
	AllowNonTransactionalMongo bool
}

// MongoConfig is an alias for MongoDBConfig for backward compatibility.
type MongoConfig = MongoDBConfig

// Config holds all database, CORS, connection pool, and email hook settings.
type Config struct {
	// DatabaseType specifies the persistence backend ("postgres", "mysql", "mongodb").
	// Default is "postgres".
	DatabaseType DatabaseType
	// DatabaseURL is the database connection string or DSN.
	DatabaseURL string
	// MySQL holds configuration specific to MySQL.
	MySQL MySQLConfig
	// Mongo holds configuration specific to MongoDB.
	// Deprecated: Prefer MongoDB.
	Mongo MongoConfig
	// MongoDB holds configuration specific to MongoDB.
	MongoDB MongoDBConfig
	// MigrationsPath is the path to database migration files or empty for embedded defaults.
	MigrationsPath string

	// AllowedOrigins specifies trusted origins for CORS headers.
	AllowedOrigins []string
	// AllowedMethods specifies HTTP methods permitted during CORS preflight.
	AllowedMethods []string
	// AllowedHeaders specifies HTTP headers permitted during CORS preflight.
	AllowedHeaders []string

	// MaxOpenConns sets the maximum number of open connections to the database.
	MaxOpenConns int
	// MaxIdleConns sets the maximum number of connections in the idle pool.
	MaxIdleConns int
	// ConnMaxLifetime sets the maximum amount of time a connection may be reused.
	ConnMaxLifetime time.Duration
	// ConnMaxIdleTime sets the maximum amount of time a connection may remain idle.
	ConnMaxIdleTime time.Duration

	// BaseURL is the public URL used to construct verification and password reset links.
	// Must be non-empty; Config.Validate() returns ErrBaseURLRequired if empty and
	// ErrBaseURLInvalid if it is not a well-formed http/https URL.
	BaseURL string

	// Email delivery hooks (provided by host app)
	// Deprecated: Prefer EmailHooks for structured transactional email hooks.
	SendVerificationEmail  SendVerificationEmailFunc
	SendPasswordResetEmail SendPasswordResetEmailFunc

	// DisableAsyncEmailDispatch opts out of background non-blocking execution.
	DisableAsyncEmailDispatch bool
	// EmailDispatchTimeout max duration for email callback execution (default: 10s).
	EmailDispatchTimeout time.Duration

	// Argon2 holds parameters for password hashing.
	Argon2 Argon2Config

	// PasswordMinLength specifies minimum allowed password length in Unicode code points. Min: 8. Default: 8.
	PasswordMinLength uint
	// PasswordMaxLength specifies maximum allowed password length in Unicode code points. Max: 128. Default: 128.
	PasswordMaxLength uint

	// RequireEmailVerification blocks login for unverified accounts when true.
	RequireEmailVerification bool
	// VerificationTokenExpiry defines the lifetime of email verification tokens [15m..60m]. Default: 30m.
	VerificationTokenExpiry time.Duration
	// PasswordResetTokenExpiry defines the lifetime of password reset tokens [15m..60m]. Default: 30m.
	PasswordResetTokenExpiry time.Duration

	// EmailHooks holds optional callbacks for transactional email events.
	EmailHooks email.Hooks

	// Session settings
	SessionIdleTimeout    time.Duration // max inactivity before session expires; default 30m
	SessionAbsoluteMaxAge time.Duration // hard cap regardless of activity; default 24h
	SessionCookieName     string        // cookie name; default "sid"
	SessionCookieDomain   string        // cookie Domain attribute; default "" (omit -> current host)
	SessionCookiePath     string        // cookie Path attribute; default "/"
	SessionCookieSecure   bool          // must be true in prod; default true
	SessionCookieSameSite http.SameSite // default http.SameSiteLaxMode

	// CSRF
	CSRFCookieName string // default "csrf_token"
	CSRFHeaderName string // default "X-CSRF-Token"
	// CSRFCookieMaxAge is the lifetime of the CSRF double-submit cookie; default 24h.
	CSRFCookieMaxAge time.Duration

	// SecurityHeaders groups HTTP security header policies.
	SecurityHeaders SecurityHeadersConfig

	// OAuth holds optional third-party OAuth2/OIDC provider configurations.
	OAuth OAuthConfig

	// TOTP holds RFC 6238 TOTP two-factor authentication configuration.
	TOTP TOTPConfig

	// Rate limiting
	RateLimitLoginWindow  time.Duration // sliding window duration; default 15m
	RateLimitLoginMax     int           // max attempts in window; default 10
	RateLimitLoginIPMax   int           // max login attempts per IP in window; default 100
	RateLimitResetWindow  time.Duration // for password reset requests; default 15m
	RateLimitResetMax     int           // default 5
	RateLimitResetIPMax   int           // max reset requests per IP in window; default 20
	RateLimitSignupWindow time.Duration // for signup; default 15m
	RateLimitSignupMax    int           // default 10
	RateLimitSignupIPMax  int           // max signups per IP in window; default 50
	RateLimitOAuthWindow  time.Duration // for oauth initiate/callback; default 15m
	RateLimitOAuthIPMax   int           // max oauth calls per IP in window; default 100
	RateLimitCleanupTick  time.Duration // how often to prune expired entries; default 5m
}

// DefaultConfig returns safe default settings. AllowedOrigins is intentionally
// empty so callers must explicitly declare trusted origins.
func DefaultConfig() Config {
	return Config{
		DatabaseType:         DatabaseTypePostgres,
		MigrationsPath:       "db/migrations",
		MaxOpenConns:         25,
		MaxIdleConns:         10,
		ConnMaxLifetime:      time.Hour,
		ConnMaxIdleTime:      30 * time.Minute,
		AllowedMethods:       []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:       []string{"Authorization", "Content-Type", "X-CSRF-Token", "X-Auth-Type"},
		EmailDispatchTimeout: 10 * time.Second,
		Argon2: Argon2Config{
			Memory:      65536,
			Time:        3,
			Parallelism: 4,
			SaltLength:  16,
			KeyLength:   32,
		},
		PasswordMinLength:        8,
		PasswordMaxLength:        128,
		RequireEmailVerification: false,
		VerificationTokenExpiry:  30 * time.Minute,
		PasswordResetTokenExpiry: 30 * time.Minute,

		// Session settings
		SessionIdleTimeout:    30 * time.Minute,
		SessionAbsoluteMaxAge: 24 * time.Hour,
		SessionCookieName:     "sid",
		SessionCookieDomain:   "",
		SessionCookiePath:     "/",
		SessionCookieSecure:   true,
		SessionCookieSameSite: http.SameSiteLaxMode,

		// CSRF
		CSRFCookieName:   "csrf_token",
		CSRFHeaderName:   "X-CSRF-Token",
		CSRFCookieMaxAge: 24 * time.Hour,

		SecurityHeaders: SecurityHeadersConfig{
			FrameOptions:          "DENY",
			ReferrerPolicy:        "strict-origin-when-cross-origin",
			ContentSecurityPolicy: "default-src 'self'; frame-ancestors 'none'",
			HSTSMaxAge:            365 * 24 * time.Hour,
			EnableHSTS:            true,
			HSTSIncludeSubdomains: true,
			HSTSPreload:           false,
		},

		MongoDB: MongoDBConfig{},

		OAuth: OAuthConfig{
			StateCookieName:     "oauth_state",
			StateCookiePath:     "/",
			StateTTL:            10 * time.Minute,
			StateCookieSameSite: http.SameSiteLaxMode,
		},

		TOTP: DefaultTOTPConfig(),

		// Rate limiting
		RateLimitLoginWindow:  15 * time.Minute,
		RateLimitLoginMax:     10,
		RateLimitLoginIPMax:   100,
		RateLimitResetWindow:  15 * time.Minute,
		RateLimitResetMax:     5,
		RateLimitResetIPMax:   20,
		RateLimitSignupWindow: 15 * time.Minute,
		RateLimitSignupMax:    10,
		RateLimitSignupIPMax:  50,
		RateLimitOAuthWindow:  15 * time.Minute,
		RateLimitOAuthIPMax:   100,
		RateLimitCleanupTick:  5 * time.Minute,
	}
}

// Validate ensures required fields are set and connection parameters are sane.
// It commits the normalization only after every check passes: a rejected config
// keeps its original values instead of the half-applied defaults that were
// written before the failing check.
func (c *Config) Validate() error {
	working := c.clone()
	if err := working.validate(); err != nil {
		return err
	}
	*c = *working
	return nil
}

// clone isolates the sections validate writes into, so a failed validation
// cannot reach the caller through the typed provider pointers or the
// AllowedOrigins backing array.
func (c *Config) clone() *Config {
	cp := *c
	// validate normalizes origins in place; a shared backing array would mutate
	// the caller's slice even when the config is rejected.
	if c.AllowedOrigins != nil {
		cp.AllowedOrigins = append([]string(nil), c.AllowedOrigins...)
	}
	if c.OAuth.Microsoft != nil {
		v := *c.OAuth.Microsoft
		cp.OAuth.Microsoft = &v
	}
	if c.OAuth.Facebook != nil {
		v := *c.OAuth.Facebook
		cp.OAuth.Facebook = &v
	}
	if c.OAuth.Discord != nil {
		v := *c.OAuth.Discord
		cp.OAuth.Discord = &v
	}
	if c.OAuth.X != nil {
		v := *c.OAuth.X
		cp.OAuth.X = &v
	}
	return &cp
}

// validate is the mutating body of Validate: it defaults and normalizes c in
// place and reports the first failing check.
func (c *Config) validate() error {
	if c.DatabaseType == "" {
		c.DatabaseType = DatabaseTypePostgres
	}
	switch c.DatabaseType {
	case DatabaseTypePostgres:
		if c.DatabaseURL == "" {
			return errors.ErrDatabaseURLRequired
		}
		lowerURL := strings.ToLower(c.DatabaseURL)
		if strings.HasPrefix(lowerURL, "postgres://") || strings.HasPrefix(lowerURL, "postgresql://") {
			parsedDBURL, err := url.Parse(c.DatabaseURL)
			if err != nil || (parsedDBURL.Host == "" && parsedDBURL.Query().Get("host") == "") || parsedDBURL.Query().Has("socket") {
				return errors.ErrDatabaseURLInvalid
			}
		} else if urlSchemePrefixRegex.MatchString(c.DatabaseURL) || !dsnParamRegex.MatchString(c.DatabaseURL) {
			return errors.ErrDatabaseURLInvalid
		}
	case DatabaseTypeMySQL:
		if c.DatabaseURL == "" {
			return errors.ErrDatabaseURLRequired
		}
		if !strings.Contains(strings.ToLower(c.DatabaseURL), "parsetime=true") {
			return errors.ErrDatabaseURLInvalid
		}
		if c.MaxOpenConns == 0 {
			c.MaxOpenConns = 25
		}
		if c.MaxOpenConns < 1 {
			return errors.ErrMaxOpenConnsNegative
		}
	case DatabaseTypeMongo, "mongo":
		if c.DatabaseURL == "" {
			return errors.ErrDatabaseURLRequired
		}
		lowerURL := strings.ToLower(c.DatabaseURL)
		if !strings.HasPrefix(lowerURL, "mongodb://") && !strings.HasPrefix(lowerURL, "mongodb+srv://") {
			return errors.ErrDatabaseURLInvalid
		}
		parsedURL, err := url.Parse(c.DatabaseURL)
		if err != nil {
			return errors.ErrDatabaseURLInvalid
		}

		q := parsedURL.Query()
		for _, param := range []string{"connectTimeoutMS", "serverSelectionTimeoutMS", "timeoutMS", "wtimeoutMS"} {
			if val := q.Get(param); val != "" {
				parsedVal, err := strconv.Atoi(val)
				if err != nil || parsedVal <= 0 {
					return errors.ErrInvalidConfig
				}
			}
		}
		if val := q.Get("maxIdleTimeMS"); val != "" {
			parsedVal, err := strconv.Atoi(val)
			if err != nil || parsedVal < 0 {
				return errors.ErrInvalidConfig
			}
		}

		if c.MongoDB.Database == "" {
			if c.MongoDB.DatabaseName != "" {
				c.MongoDB.Database = c.MongoDB.DatabaseName
			} else if c.Mongo.Database != "" {
				c.MongoDB.Database = c.Mongo.Database
			} else if c.Mongo.DatabaseName != "" {
				c.MongoDB.Database = c.Mongo.DatabaseName
			} else if dbName := strings.Trim(parsedURL.Path, "/"); dbName != "" {
				c.MongoDB.Database = dbName
			}
		}
		if c.MongoDB.ConnectTimeout == 0 && c.Mongo.ConnectTimeout != 0 {
			c.MongoDB.ConnectTimeout = c.Mongo.ConnectTimeout
		}
		if c.MongoDB.ServerSelectionTimeout == 0 && c.Mongo.ServerSelectionTimeout != 0 {
			c.MongoDB.ServerSelectionTimeout = c.Mongo.ServerSelectionTimeout
		}
		if c.MongoDB.MaxConnIdleTime == 0 && c.Mongo.MaxConnIdleTime != 0 {
			c.MongoDB.MaxConnIdleTime = c.Mongo.MaxConnIdleTime
		}
		if !c.MongoDB.AllowNonTransactionalMongo && c.Mongo.AllowNonTransactionalMongo {
			c.MongoDB.AllowNonTransactionalMongo = true
		}

		if c.MongoDB.ConnectTimeout == 0 {
			c.MongoDB.ConnectTimeout = 10 * time.Second
		}
		if c.MongoDB.ServerSelectionTimeout == 0 {
			c.MongoDB.ServerSelectionTimeout = 10 * time.Second
		}
		if c.MongoDB.MaxConnIdleTime == 0 {
			c.MongoDB.MaxConnIdleTime = 30 * time.Minute
		}

		if c.MongoDB.Database == "" {
			return errors.ErrInvalidConfig
		}
		if c.MongoDB.ConnectTimeout <= 0 {
			return errors.ErrInvalidConfig
		}
		if c.MongoDB.ServerSelectionTimeout <= 0 {
			return errors.ErrInvalidConfig
		}
		if c.MongoDB.MaxConnIdleTime < 0 {
			return errors.ErrInvalidConfig
		}

		c.Mongo = c.MongoDB
	default:
		return errors.ErrDatabaseUnsupported
	}
	if c.BaseURL == "" {
		return errors.ErrBaseURLRequired
	}
	baseURL, err := url.Parse(c.BaseURL)
	if err != nil || baseURL.Host == "" || (baseURL.Scheme != "http" && baseURL.Scheme != "https") {
		return errors.ErrBaseURLInvalid
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	for i, origin := range c.AllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "*" {
			c.AllowedOrigins[i] = "*"
			continue
		}
		origin = strings.TrimRight(origin, "/")
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return errors.ErrAllowedOriginInvalid
		}
		c.AllowedOrigins[i] = origin
	}
	if c.MigrationsPath == "" {
		c.MigrationsPath = "db/migrations"
	}
	if c.MaxOpenConns < 0 {
		return errors.ErrMaxOpenConnsNegative
	}
	if c.MaxIdleConns < 0 {
		return errors.ErrMaxIdleConnsNegative
	}
	if c.MaxOpenConns > 0 && c.MaxIdleConns > c.MaxOpenConns {
		return errors.ErrMaxIdleExceedsOpen
	}
	if c.ConnMaxLifetime < 0 {
		return errors.ErrConnMaxLifetimeNegative
	}
	if c.ConnMaxIdleTime < 0 {
		return errors.ErrConnMaxIdleTimeNegative
	}
	if c.EmailDispatchTimeout < 0 {
		return errors.ErrEmailDispatchTimeoutNegative
	}
	if c.EmailDispatchTimeout == 0 {
		c.EmailDispatchTimeout = 10 * time.Second
	}

	if c.Argon2.Memory == 0 {
		c.Argon2.Memory = 65536
	}
	if c.Argon2.Time == 0 {
		c.Argon2.Time = 3
	}
	if c.Argon2.Parallelism == 0 {
		c.Argon2.Parallelism = 4
	}
	if c.Argon2.SaltLength == 0 {
		c.Argon2.SaltLength = 16
	}
	if c.Argon2.KeyLength == 0 {
		c.Argon2.KeyLength = 32
	}
	if c.Argon2.Memory < 19456 {
		return errors.ErrArgon2MemoryTooLow
	}
	if c.Argon2.Time < 2 {
		return errors.ErrArgon2TimeTooLow
	}
	if c.Argon2.SaltLength < 16 {
		return errors.ErrArgon2SaltLengthTooShort
	}
	if c.Argon2.KeyLength < 32 {
		return errors.ErrArgon2KeyLengthTooShort
	}

	if c.PasswordMinLength == 0 {
		c.PasswordMinLength = 8
	}
	if c.PasswordMaxLength == 0 {
		c.PasswordMaxLength = 128
	}
	if c.PasswordMinLength < 8 {
		return errors.ErrPasswordMinLengthTooShort
	}
	if c.PasswordMaxLength <= c.PasswordMinLength || c.PasswordMaxLength > 128 {
		return errors.ErrPasswordMaxLengthInvalid
	}

	if c.VerificationTokenExpiry == 0 {
		c.VerificationTokenExpiry = 30 * time.Minute
	} else if c.VerificationTokenExpiry < 15*time.Minute || c.VerificationTokenExpiry > 60*time.Minute {
		return errors.ErrVerificationTokenExpiryInvalid
	}

	if c.PasswordResetTokenExpiry == 0 {
		c.PasswordResetTokenExpiry = 30 * time.Minute
	} else if c.PasswordResetTokenExpiry < 15*time.Minute || c.PasswordResetTokenExpiry > 60*time.Minute {
		return errors.ErrPasswordResetTokenExpiryInvalid
	}

	if c.SessionCookieName == "" {
		c.SessionCookieName = "sid"
	}
	if c.SessionCookiePath == "" {
		c.SessionCookiePath = "/"
	}
	if c.CSRFCookieName == "" {
		c.CSRFCookieName = "csrf_token"
	}
	if c.CSRFHeaderName == "" {
		c.CSRFHeaderName = "X-CSRF-Token"
	}

	if !isToken(c.SessionCookieName) {
		return errors.ErrSessionCookieNameInvalid
	}
	if !isCookiePath(c.SessionCookiePath) {
		return errors.ErrSessionCookiePathInvalid
	}
	if !isCookieDomain(c.SessionCookieDomain) {
		return errors.ErrSessionCookieDomainInvalid
	}
	if !isToken(c.CSRFCookieName) {
		return errors.ErrCSRFCookieNameInvalid
	}
	if !isToken(c.CSRFHeaderName) {
		return errors.ErrCSRFHeaderNameInvalid
	}
	if c.CSRFCookieName == c.SessionCookieName {
		return errors.ErrCSRFCookieNameCollision
	}
	if c.CSRFCookieMaxAge == 0 {
		c.CSRFCookieMaxAge = 24 * time.Hour
	}
	// Sub-second ages truncate to MaxAge=0 on the wire and the cookie is discarded.
	if c.CSRFCookieMaxAge < time.Second {
		return errors.ErrCSRFCookieMaxAgeInvalid
	}
	if c.SecurityHeaders.FrameOptions == "" {
		c.SecurityHeaders.FrameOptions = "DENY"
	}
	if c.SecurityHeaders.FrameOptions != "DENY" && c.SecurityHeaders.FrameOptions != "SAMEORIGIN" {
		return errors.ErrFrameOptionsInvalid
	}
	if c.SecurityHeaders.ReferrerPolicy == "" {
		c.SecurityHeaders.ReferrerPolicy = "strict-origin-when-cross-origin"
	}
	switch c.SecurityHeaders.ReferrerPolicy {
	case "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
		"same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url":
	default:
		return errors.ErrReferrerPolicyInvalid
	}
	if c.SecurityHeaders.ContentSecurityPolicy == "" {
		c.SecurityHeaders.ContentSecurityPolicy = "default-src 'self'; frame-ancestors 'none'"
	}
	if c.SecurityHeaders.HSTSMaxAge == 0 {
		c.SecurityHeaders.HSTSMaxAge = 365 * 24 * time.Hour
	}
	if c.SecurityHeaders.HSTSMaxAge < 0 {
		return errors.ErrHSTSMaxAgeNegative
	}
	// Sub-second ages truncate to max-age=0 and strip the HSTS policy.
	// Zero was defaulted above, so any remaining sub-second value is explicit.
	if c.SecurityHeaders.HSTSMaxAge < time.Second {
		return errors.ErrHSTSMaxAgeTooSmall
	}

	if c.SessionIdleTimeout == 0 {
		c.SessionIdleTimeout = 30 * time.Minute
	}
	if c.SessionAbsoluteMaxAge == 0 {
		c.SessionAbsoluteMaxAge = 24 * time.Hour
	}
	if c.SessionIdleTimeout <= 0 {
		return errors.ErrSessionIdleTimeoutInvalid
	}
	if c.SessionAbsoluteMaxAge <= c.SessionIdleTimeout {
		return errors.ErrSessionAbsoluteMaxAgeInvalid
	}
	if c.SessionCookieSameSite == 0 {
		c.SessionCookieSameSite = http.SameSiteLaxMode
	}
	if c.SessionCookieSameSite == http.SameSiteNoneMode && !c.SessionCookieSecure {
		return errors.ErrSessionSameSiteNoneInsecure
	}

	if c.OAuth.StateCookieName == "" {
		c.OAuth.StateCookieName = "oauth_state"
	}
	if c.OAuth.StateCookiePath == "" {
		c.OAuth.StateCookiePath = "/"
	}
	if c.OAuth.StateTTL == 0 {
		c.OAuth.StateTTL = 10 * time.Minute
	}
	if c.OAuth.StateCookieSameSite == 0 {
		c.OAuth.StateCookieSameSite = http.SameSiteLaxMode
	}
	// Sub-second TTLs truncate to MaxAge=0 on the wire while Expires stays ahead — reject like CSRF.
	if c.OAuth.StateTTL < time.Second {
		return errors.ErrOAuthStateTTLInvalid
	}
	// Explicit secrets shorter than 32 bytes are brute-forceable. Empty is
	// fail-closed whenever any provider is enabled: the state HMAC must
	// verify across replicas and restarts, which a per-process fallback key
	// cannot do. With no providers enabled OAuth is inert and empty stays valid.
	if c.OAuth.StateSecret == "" {
		if c.OAuth.anyProviderEnabled() {
			return errors.ErrOAuthStateSecretRequired
		}
	} else if len(c.OAuth.StateSecret) < 32 {
		return errors.ErrOAuthStateSecretTooShort
	}
	if !isToken(c.OAuth.StateCookieName) {
		return errors.ErrOAuthStateCookieNameInvalid
	}
	// Same name + same default path as the session or CSRF cookie means one
	// cookie slot: issuance overwrites the session cookie and post-success
	// cleanup wipes the just-minted session. Mirrors the session-vs-CSRF
	// collision precedent above with a dedicated sentinel.
	if c.OAuth.StateCookieName == c.SessionCookieName || c.OAuth.StateCookieName == c.CSRFCookieName {
		return errors.ErrOAuthStateCookieNameCollision
	}
	if !isCookiePath(c.OAuth.StateCookiePath) {
		return errors.ErrOAuthStateCookiePathInvalid
	}
	// Normalized entries land in a fresh map: writing back into the map under
	// range leaves a partially normalized map behind on a later entry's error.
	normalizedProviders := make(map[string]ProviderConfig, len(c.OAuth.Providers))
	for id, provider := range c.OAuth.Providers {
		switch id {
		case "google", "github", "apple", "microsoft", "discord", "facebook", "x":
		default:
			return errors.ErrOAuthProviderUnknown
		}
		if id == "microsoft" {
			tenant, err := normalizeMicrosoftTenant(provider.Tenant)
			if err != nil {
				return err
			}
			provider.Tenant = tenant
		}
		normalizedProviders[id] = provider
	}
	c.OAuth.Providers = normalizedProviders

	if c.OAuth.Microsoft != nil {
		// Merge rule: typed defaults materialise only without a map entry for
		// this provider. A pre-merge "common"/scope/TTL default reads as an
		// explicit typed value and would otherwise shadow explicit map config.
		_, msMapEntry := c.OAuth.Providers["microsoft"]
		tenant := c.OAuth.Microsoft.Tenant
		if strings.TrimSpace(tenant) == "" && !msMapEntry {
			tenant = "common"
		}
		normalized, err := normalizeMicrosoftTenant(tenant)
		if err != nil {
			return err
		}
		c.OAuth.Microsoft.Tenant = normalized
		trusted := make([]string, 0, len(c.OAuth.Microsoft.TrustedTenants))
		for _, t := range c.OAuth.Microsoft.TrustedTenants {
			if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
				trusted = append(trusted, t)
			}
		}
		c.OAuth.Microsoft.TrustedTenants = trusted
		if len(c.OAuth.Microsoft.Scopes) == 0 && !msMapEntry {
			c.OAuth.Microsoft.Scopes = []string{"openid", "profile", "email", "offline_access"}
		}
		if c.OAuth.Microsoft.JWKSCacheTTL == 0 && !msMapEntry {
			c.OAuth.Microsoft.JWKSCacheTTL = 24 * time.Hour
		}
	}

	if c.OAuth.X != nil {
		// Same merge rule as Microsoft above: no pre-merge default when a map
		// entry carries explicit scopes.
		_, xMapEntry := c.OAuth.Providers["x"]
		if len(c.OAuth.X.Scopes) == 0 && !xMapEntry {
			c.OAuth.X.Scopes = []string{"users.read"}
		}
	}

	// Resolve folds typed sections into Providers and defaults merged entries.
	c.OAuth.resolveProviders()

	// Validate credentials on the resolved providers. Every check routes through
	// the resolved enabled state (resolveEnabled).
	for id, provider := range c.OAuth.Providers {
		if !provider.Enabled {
			continue
		}
		if provider.ClientID == "" {
			return errors.ErrOAuthClientIDRequired
		}
		switch id {
		case "google", "github", "microsoft", "discord", "facebook", "x":
			if provider.ClientSecret == "" {
				return errors.ErrOAuthClientSecretRequired
			}
		case "apple":
			if provider.ClientSecret == "" &&
				(provider.TeamID == "" || provider.KeyID == "" || provider.PrivateKey == "") {
				return errors.ErrOAuthClientSecretRequired
			}
		}
		if provider.RedirectURL == "" {
			return errors.ErrOAuthRedirectURLRequired
		}
		if id == "facebook" {
			if err := validateGraphVersion(provider.GraphVersion); err != nil {
				return err
			}
		}
	}

	if c.TOTP.Issuer == "" {
		c.TOTP.Issuer = "go-auth"
	}
	if c.TOTP.ChallengeTokenTTL == 0 {
		c.TOTP.ChallengeTokenTTL = 10 * time.Minute
	}
	if c.TOTP.MaxAttemptsPerWindow == 0 {
		c.TOTP.MaxAttemptsPerWindow = 5
	}
	if c.TOTP.AttemptWindow == 0 {
		c.TOTP.AttemptWindow = 5 * time.Minute
	}

	if c.TOTP.EncryptionKey != "" {
		if len(c.TOTP.EncryptionKey) != 64 {
			return errors.ErrTOTPEncryptionKeyInvalid
		}
		if _, err := hex.DecodeString(c.TOTP.EncryptionKey); err != nil {
			return errors.ErrTOTPEncryptionKeyInvalid
		}
	}

	if c.TOTP.ChallengeTokenTTL < time.Minute || c.TOTP.ChallengeTokenTTL > 30*time.Minute {
		return errors.ErrTOTPChallengeTokenTTLInvalid
	}
	if c.TOTP.MaxAttemptsPerWindow < 1 {
		return errors.ErrTOTPMaxAttemptsInvalid
	}
	if c.TOTP.AttemptWindow < time.Minute {
		return errors.ErrTOTPAttemptWindowInvalid
	}
	if !c.SessionCookieSecure {
		slog.Warn("SessionCookieSecure is false — not safe for production")
	}

	if c.RateLimitLoginWindow < 0 || c.RateLimitResetWindow < 0 || c.RateLimitSignupWindow < 0 || c.RateLimitOAuthWindow < 0 || c.RateLimitCleanupTick < 0 {
		return errors.ErrRateLimitWindowInvalid
	}
	if c.RateLimitLoginWindow == 0 {
		c.RateLimitLoginWindow = 15 * time.Minute
	}
	if c.RateLimitResetWindow == 0 {
		c.RateLimitResetWindow = 15 * time.Minute
	}
	if c.RateLimitSignupWindow == 0 {
		c.RateLimitSignupWindow = 15 * time.Minute
	}
	if c.RateLimitOAuthWindow == 0 {
		c.RateLimitOAuthWindow = 15 * time.Minute
	}
	if c.RateLimitCleanupTick == 0 {
		c.RateLimitCleanupTick = 5 * time.Minute
	}

	if c.RateLimitLoginMax == 0 {
		c.RateLimitLoginMax = 10
	}
	if c.RateLimitResetMax == 0 {
		c.RateLimitResetMax = 5
	}
	if c.RateLimitSignupMax == 0 {
		c.RateLimitSignupMax = 10
	}
	if c.RateLimitLoginIPMax == 0 {
		c.RateLimitLoginIPMax = c.RateLimitLoginMax * 10
	}
	if c.RateLimitResetIPMax == 0 {
		c.RateLimitResetIPMax = c.RateLimitResetMax * 4
	}
	if c.RateLimitSignupIPMax == 0 {
		c.RateLimitSignupIPMax = c.RateLimitSignupMax * 5
	}
	if c.RateLimitOAuthIPMax == 0 {
		c.RateLimitOAuthIPMax = 100
	}
	if c.RateLimitLoginMax < 1 || c.RateLimitResetMax < 1 || c.RateLimitSignupMax < 1 ||
		c.RateLimitLoginIPMax < 1 || c.RateLimitResetIPMax < 1 || c.RateLimitSignupIPMax < 1 ||
		c.RateLimitOAuthIPMax < 1 {
		return errors.ErrRateLimitMaxInvalid
	}

	return nil
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 33 || b > 126 || strings.IndexByte("()<>@,;:\"/[]?={}\\", b) >= 0 {
			return false
		}
	}
	return true
}

// validateGraphVersion accepts an empty value (defaulted after the merge) and
// requires "<major>.<minor>" with an optional "v" prefix, no leading zeros, and
// at least 19.0. Facebook serves no OAuth dialog below 19.0, and the raw value
// is interpolated into URL paths, so shapes such as NaN, Inf, exponents, hex
// floats or a missing minor version must not pass.
func validateGraphVersion(version string) error {
	if version == "" {
		return nil
	}
	if !graphVersionRegex.MatchString(version) {
		return errors.ErrOAuthGraphVersionInvalid
	}
	ver, err := strconv.ParseFloat(strings.TrimPrefix(version, "v"), 64)
	if err != nil || ver < 19.0 {
		return errors.ErrOAuthGraphVersionInvalid
	}
	return nil
}

func isCookiePath(s string) bool {
	if s == "" || s[0] != '/' {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 32 || b >= 127 || b == ';' {
			return false
		}
	}
	return true
}

func isCookieDomain(s string) bool {
	if s == "" {
		return true
	}
	// Reject schemes, ports, paths, and control characters per RFC 6265 §4.1.1.
	if strings.ContainsAny(s, ":/\\ \t\r\n;?#@") {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b <= 32 || b >= 127 {
			return false
		}
	}
	return true
}

var (
	dsnParamRegex        = regexp.MustCompile(`(?i)\b(host|dbname)\b\s*=\s*(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|\S+)`)
	graphVersionRegex    = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	urlSchemePrefixRegex = regexp.MustCompile(`^(?:[a-zA-Z][a-zA-Z0-9+.-]*:)?//`)
	dsnSecretRegex       = regexp.MustCompile(`(?i)\b(password|pass|token|secret|api_key|apikey|sslpassword)\b(\s*=\s*)(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|\S+)`)
	userinfoRegex        = regexp.MustCompile(`://([^:]+):([^@]+)@`)
	mysqlUserinfoRegex   = regexp.MustCompile(`(^|[^\w/])([a-zA-Z0-9_\-\.]+):(.+)@((?:tcp|unix)\([^\)]+\)|[a-zA-Z0-9_\-\.]*\/|$)`)
	tenantGUIDRegex      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	tenantDomainRegex    = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
)

// isMicrosoftTenantRef reports whether tenant is a GUID or domain name.
// Callers must lowercase tenant first; named authorities are handled separately.
func isMicrosoftTenantRef(tenant string) bool {
	return tenantGUIDRegex.MatchString(tenant) || tenantDomainRegex.MatchString(tenant)
}

// normalizeMicrosoftTenant lowercases and trims tenant, then rejects anything
// that is not a named authority, GUID, or domain.
func normalizeMicrosoftTenant(tenant string) (string, error) {
	tenant = strings.ToLower(strings.TrimSpace(tenant))
	switch tenant {
	case "", "common", "organizations", "consumers":
		return tenant, nil
	}
	if !isMicrosoftTenantRef(tenant) {
		return "", errors.WrapOverride(errors.ErrOAuthTenantInvalid, errors.CodeInvalidConfig, "oauth microsoft tenant is invalid: "+tenant)
	}
	return tenant, nil
}

func isSecretParam(k string) bool {
	switch strings.ToLower(k) {
	case "password", "pass", "token", "secret", "api_key", "apikey", "sslpassword", "access_token", "client_secret", "auth_token":
		return true
	default:
		return false
	}
}

// RedactURL masks sensitive credentials in a database or connection URL.
func RedactURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	if u, err := url.Parse(rawURL); err == nil && u.Scheme != "" && strings.Contains(rawURL, "://") {
		var redacted bool
		if u.User != nil {
			u.User = url.UserPassword(u.User.Username(), "REDACTED")
			redacted = true
		}
		if u.RawQuery != "" {
			q := u.Query()
			var queryRedacted bool
			for k := range q {
				if isSecretParam(k) {
					q.Set(k, "REDACTED")
					queryRedacted = true
				}
			}
			if queryRedacted {
				u.RawQuery = q.Encode()
				redacted = true
			}
		}
		if redacted {
			return u.String()
		}
		return rawURL
	}

	// Check MySQL DSN format (handles passwords containing '@')
	if redacted, ok := RedactMySQLDSN(rawURL); ok {
		return redacted
	}

	// Fallback for non-standard connection strings or DSNs containing passwords/secrets
	cleaned := dsnSecretRegex.ReplaceAllString(rawURL, "${1}${2}REDACTED")
	cleaned = userinfoRegex.ReplaceAllString(cleaned, "://${1}:REDACTED@")
	cleaned = mysqlUserinfoRegex.ReplaceAllString(cleaned, "${1}${2}:REDACTED@${4}")
	return cleaned
}

// LogValue implements slog.LogValuer to ensure DatabaseURL and sensitive secrets are masked.
func (c Config) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("database_url", RedactURL(c.DatabaseURL)),
		slog.String("base_url", c.BaseURL),
		slog.String("migrations_path", c.MigrationsPath),
		slog.Int("max_open_conns", c.MaxOpenConns),
		slog.Int("max_idle_conns", c.MaxIdleConns),
		slog.Duration("conn_max_lifetime", c.ConnMaxLifetime),
		slog.Duration("conn_max_idle_time", c.ConnMaxIdleTime),
		slog.String("session_cookie_name", c.SessionCookieName),
		slog.String("session_cookie_domain", c.SessionCookieDomain),
		slog.String("session_cookie_path", c.SessionCookiePath),
		slog.Bool("session_cookie_secure", c.SessionCookieSecure),
		slog.Int("session_cookie_samesite", int(c.SessionCookieSameSite)),
		slog.Duration("session_idle_timeout", c.SessionIdleTimeout),
		slog.Duration("session_absolute_max_age", c.SessionAbsoluteMaxAge),
		slog.String("csrf_cookie_name", c.CSRFCookieName),
		slog.String("csrf_header_name", c.CSRFHeaderName),
	}
	if len(c.OAuth.Providers) > 0 {
		oauthAttrs := make([]slog.Attr, 0, len(c.OAuth.Providers))
		for name, provider := range c.OAuth.Providers {
			oauthAttrs = append(oauthAttrs, slog.Any(name, provider.LogValue()))
		}
		attrs = append(attrs, slog.Attr{
			Key:   "oauth",
			Value: slog.GroupValue(oauthAttrs...),
		})
	}
	return slog.GroupValue(attrs...)
}

// String implements fmt.Stringer to ensure DatabaseURL and sensitive secrets are masked when formatted.
func (c Config) String() string {
	return fmt.Sprintf("Config{DatabaseURL: %s, BaseURL: %s, MigrationsPath: %s, MaxOpenConns: %d, MaxIdleConns: %d}",
		RedactURL(c.DatabaseURL), c.BaseURL, c.MigrationsPath, c.MaxOpenConns, c.MaxIdleConns)
}
