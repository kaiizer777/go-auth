package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/kaiizer777/go-auth/config"
)

type securityResponseWriter struct {
	http.ResponseWriter
	headers http.Header
	written bool
}

func (w *securityResponseWriter) WriteHeader(code int) {
	if !w.written {
		for k, v := range w.headers {
			w.ResponseWriter.Header()[k] = v
		}
		w.written = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *securityResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// SecurityHeaders injects the baseline HTTP security header set on every
// response. Downstream mutations are locked out at wire-write time.
func SecurityHeaders(cfg *config.Config) func(http.Handler) http.Handler {
	if cfg == nil {
		defaultCfg := config.DefaultConfig()
		cfg = &defaultCfg
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			baseHeaders := make(http.Header)
			baseHeaders.Set("X-Content-Type-Options", "nosniff")
			baseHeaders.Set("X-Frame-Options", cfg.SecurityHeaders.FrameOptions)
			baseHeaders.Set("Referrer-Policy", cfg.SecurityHeaders.ReferrerPolicy)
			baseHeaders.Set("Content-Security-Policy", cfg.SecurityHeaders.ContentSecurityPolicy)

			isSecure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
			if cfg.SecurityHeaders.EnableHSTS && isSecure {
				hsts := fmt.Sprintf("max-age=%d", int(cfg.SecurityHeaders.HSTSMaxAge.Seconds()))
				if cfg.SecurityHeaders.HSTSIncludeSubdomains {
					hsts += "; includeSubDomains"
				}
				if cfg.SecurityHeaders.HSTSPreload {
					hsts += "; preload"
				}
				baseHeaders.Set("Strict-Transport-Security", hsts)
			}

			for k, v := range baseHeaders {
				w.Header()[k] = v
			}
			wrapped := &securityResponseWriter{
				ResponseWriter: w,
				headers:        baseHeaders,
			}
			next.ServeHTTP(wrapped, r)
		})
	}
}
