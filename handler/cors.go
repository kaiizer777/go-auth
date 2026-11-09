package handler

import (
	"net/http"
	"strings"

	"github.com/kaiizer777/go-auth/config"
)

// CORS returns HTTP middleware that applies Cross-Origin Resource Sharing (CORS) headers
// and handles preflight OPTIONS requests according to the provided configuration.
func CORS(cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Vary", "Origin")

			origin := r.Header.Get("Origin")
			allowOrigin, allowCredentials := checkOrigin(origin, cfg.AllowedOrigins)
			if allowOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
				if len(cfg.AllowedMethods) > 0 {
					w.Header().Set("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
				}
				if len(cfg.AllowedHeaders) > 0 {
					w.Header().Set("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
				}
				if allowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}

			if r.Method == http.MethodOptions && r.Header.Get("Origin") != "" && r.Header.Get("Access-Control-Request-Method") != "" {
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// checkOrigin evaluates the incoming origin against the configured allowlist.
// It returns the origin to reflect and whether credentials should be permitted.
func checkOrigin(origin string, allowed []string) (allowedOrigin string, allowCredentials bool) {
	if origin == "" {
		return "", false
	}
	for _, o := range allowed {
		if o != "*" && strings.EqualFold(origin, o) {
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
