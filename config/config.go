package config

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
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

// OAuthConfig defines settings for a third-party OAuth2 / OIDC identity provider.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
}

// LogValue implements slog.LogValuer to ensure ClientSecret is masked in logs.
func (o OAuthConfig) LogValue() slog.Value {
	secret := "[REDACTED]"
	if o.ClientSecret == "" {
		secret = ""
	}
	return slog.GroupValue(
		slog.String("client_id", o.ClientID),
		slog.String("client_secret", secret),
		slog.String("redirect_url", o.RedirectURL),
		slog.String("auth_url", o.AuthURL),
		slog.String("token_url", o.TokenURL),
		slog.String("user_info_url", o.UserInfoURL),
	)
}

// String implements fmt.Stringer to ensure ClientSecret is masked when printed.
func (o OAuthConfig) String() string {
	secret := "[REDACTED]"
	if o.ClientSecret == "" {
		secret = ""
	}
	return fmt.Sprintf("OAuthConfig{ClientID: %s, ClientSecret: %s, RedirectURL: %s}", o.ClientID, secret, o.RedirectURL)
}

// Config holds all database, CORS, connection pool, and email hook settings.
type Config struct {
	// DatabaseURL is the PostgreSQL connection string.
	DatabaseURL string
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
	RateLimitCleanupTick  time.Duration // how often to prune expired entries; default 5m

	// OAuth holds optional third-party OAuth2/OIDC provider configurations keyed by provider name.
	OAuth map[string]OAuthConfig
}

// DefaultConfig returns safe default settings. AllowedOrigins is intentionally
// empty so callers must explicitly declare trusted origins.
func DefaultConfig() Config {
	return Config{
		MigrationsPath:       "db/migrations",
		MaxOpenConns:         25,
		MaxIdleConns:         10,
		ConnMaxLifetime:      time.Hour,
		ConnMaxIdleTime:      30 * time.Minute,
		AllowedMethods:       []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:       []string{"Authorization", "Content-Type", "X-CSRF-Token"},
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
		CSRFCookieName: "csrf_token",
		CSRFHeaderName: "X-CSRF-Token",

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
		RateLimitCleanupTick:  5 * time.Minute,
	}
}

// Validate ensures required fields are set and connection parameters are sane.
func (c *Config) Validate() error {
	if c.DatabaseURL == "" {
		return errors.ErrDatabaseURLRequired
	}
	if parsedDBURL, err := url.Parse(c.DatabaseURL); err == nil && (strings.ToLower(parsedDBURL.Scheme) == "postgres" || strings.ToLower(parsedDBURL.Scheme) == "postgresql") {
		if parsedDBURL.Host == "" && parsedDBURL.Query().Get("host") == "" && parsedDBURL.Query().Get("socket") == "" {
			return errors.ErrDatabaseURLInvalid
		}
	} else if strings.Contains(c.DatabaseURL, "://") || !dsnParamRegex.MatchString(c.DatabaseURL) {
		return errors.ErrDatabaseURLInvalid
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
	if !c.SessionCookieSecure {
		slog.Warn("SessionCookieSecure is false — not safe for production")
	}

	if c.RateLimitLoginWindow < 0 || c.RateLimitResetWindow < 0 || c.RateLimitSignupWindow < 0 || c.RateLimitCleanupTick < 0 {
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
	if c.RateLimitLoginMax < 1 || c.RateLimitResetMax < 1 || c.RateLimitSignupMax < 1 ||
		c.RateLimitLoginIPMax < 1 || c.RateLimitResetIPMax < 1 || c.RateLimitSignupIPMax < 1 {
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
	dsnParamRegex  = regexp.MustCompile(`(?i)\b(host|dbname)\b\s*=\s*(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|\S+)`)
	dsnSecretRegex = regexp.MustCompile(`(?i)\b(password|pass|token|secret|api_key|apikey|sslpassword)\b(\s*=\s*)(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|\S+)`)
	userinfoRegex  = regexp.MustCompile(`://([^:]+):([^@]+)@`)
)

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

	// Fallback for non-standard connection strings or DSNs containing passwords/secrets
	cleaned := dsnSecretRegex.ReplaceAllString(rawURL, "${1}${2}REDACTED")
	cleaned = userinfoRegex.ReplaceAllString(cleaned, "://${1}:REDACTED@")
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
	if len(c.OAuth) > 0 {
		oauthAttrs := make([]slog.Attr, 0, len(c.OAuth))
		for name, provider := range c.OAuth {
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
