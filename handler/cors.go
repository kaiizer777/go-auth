package handler

import (
	"net/http"
	"strings"

	"github.com/kaiizer777/go-auth/config"
)

// CORS returns HTTP middleware that applies Cross-Origin Resource Sharing (CORS) headers
// and handles preflight OPTIONS requests according to the provided configuration.
func CORS(cfg config.Config) func(http.Handler) http.Handler {
	allowedMethods := strings.Join(cfg.AllowedMethods, ", ")
	allowedHeaders := strings.Join(cfg.AllowedHeaders, ", ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Vary", "Origin")

			origin := r.Header.Get("Origin")
			allowOrigin, allowCredentials := checkOrigin(origin, cfg.AllowedOrigins)
			if allowOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
				if allowedMethods != "" {
					w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
				}
				if allowedHeaders != "" {
					w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
				}
				if allowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}

			if r.Method == http.MethodOptions && r.Header.Get("Origin") != "" && r.Header.Get("Access-Control-Request-Method") != "" {
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
				if allowOrigin != "" {
					w.Header().Set("Access-Control-Max-Age", "86400")
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isASCII reports whether all bytes in s are valid 7-bit US-ASCII.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// equalASCIIFold reports whether s1 and s2 are equal under ASCII case-folding.
func equalASCIIFold(s1, s2 string) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := 0; i < len(s1); i++ {
		c1 := s1[i]
		c2 := s2[i]
		if c1 >= 'A' && c1 <= 'Z' {
			c1 += 'a' - 'A'
		}
		if c2 >= 'A' && c2 <= 'Z' {
			c2 += 'a' - 'A'
		}
		if c1 != c2 {
			return false
		}
	}
	return true
}

// checkOrigin evaluates the incoming origin against the configured allowlist using strict ASCII matching.
// It returns the origin to reflect and whether credentials should be permitted.
func checkOrigin(origin string, allowed []string) (allowedOrigin string, allowCredentials bool) {
	if origin == "" || !isASCII(origin) {
		return "", false
	}
	cleanOrigin := strings.TrimRight(origin, "/")
	for _, o := range allowed {
		if o != "*" && isASCII(o) && equalASCIIFold(cleanOrigin, strings.TrimRight(o, "/")) {
			return origin, true
		}
	}
	for _, o := range allowed {
		if o == "*" {
			return "*", false
		}
	}
	return "", false
}

// isAllowedOrigin reports whether the provided origin is allowed by the configured allowlist.
func isAllowedOrigin(origin string, allowed []string) bool {
	allowOrigin, _ := checkOrigin(origin, allowed)
	return allowOrigin != ""
}
