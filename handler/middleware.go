package handler

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

type (
	ctxUserIDKey    struct{}
	ctxSessionIDKey struct{}
	ctxSessionKey   struct{}
	ctxRawIDKey     struct{}
)

var (
	contextKeyUserID    = ctxUserIDKey{}
	contextKeySessionID = ctxSessionIDKey{}
	contextKeySession   = ctxSessionKey{}
	contextKeyRawID     = ctxRawIDKey{}
)

// redactedToken encapsulates a raw session token to prevent accidental disclosure via context dumps/formatters.
type redactedToken string

func (r redactedToken) String() string {
	return "[REDACTED]"
}

func (r redactedToken) GoString() string {
	return "[REDACTED]"
}

// Internal helpers (consumed by handler/session.go)
func userIDFromContext(ctx context.Context) uuid.UUID {
	v, _ := ctx.Value(contextKeyUserID).(uuid.UUID)
	return v
}

func sessionIDFromContext(ctx context.Context) uuid.UUID {
	v, _ := ctx.Value(contextKeySessionID).(uuid.UUID)
	return v
}

func sessionFromContext(ctx context.Context) *session.Session {
	v, _ := ctx.Value(contextKeySession).(*session.Session)
	return v
}

func rawIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(contextKeyRawID).(redactedToken); ok {
		return string(v)
	}
	if v, ok := ctx.Value(contextKeyRawID).(string); ok {
		return v
	}
	return ""
}

// Exported helpers for host applications and external consumers
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(contextKeyUserID).(uuid.UUID)
	return v, ok && v != uuid.Nil
}

func SessionFromContext(ctx context.Context) *session.Session {
	return sessionFromContext(ctx)
}

func SessionIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(contextKeySessionID).(uuid.UUID)
	return v, ok && v != uuid.Nil
}

func RawSessionIDFromContext(ctx context.Context) (string, bool) {
	if v, ok := ctx.Value(contextKeyRawID).(redactedToken); ok && v != "" {
		return string(v), true
	}
	if v, ok := ctx.Value(contextKeyRawID).(string); ok && v != "" {
		return v, true
	}
	return "", false
}

func RawIDFromContext(ctx context.Context) (string, bool) {
	return RawSessionIDFromContext(ctx)
}

// SecurityHeaders returns HTTP middleware that applies standard defensive headers.
func SecurityHeaders(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
			if (cfg != nil && cfg.SessionCookieSecure) || r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
				w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			}
			next.ServeHTTP(w, r)
		})
	}
}

type recoveryResponseWriter struct {
	http.ResponseWriter
	committed bool
}

func (rw *recoveryResponseWriter) WriteHeader(statusCode int) {
	if statusCode < 100 || statusCode >= 200 || statusCode == http.StatusSwitchingProtocols {
		rw.committed = true
	}
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *recoveryResponseWriter) Write(b []byte) (int, error) {
	rw.committed = true
	return rw.ResponseWriter.Write(b)
}

func (rw *recoveryResponseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func (rw *recoveryResponseWriter) Flush() {
	flusher, ok := rw.ResponseWriter.(http.Flusher)
	if !ok {
		return
	}
	rw.committed = true
	flusher.Flush()
}

func isResponseCommitted(w http.ResponseWriter) bool {
	for w != nil {
		switch tw := w.(type) {
		case *recoveryResponseWriter:
			if tw.committed {
				return true
			}
			w = tw.ResponseWriter
		case *responseInterceptor:
			if tw.headerWritten {
				return true
			}
			w = tw.ResponseWriter
		case interface{ Committed() bool }:
			if tw.Committed() {
				return true
			}
			if u, ok := w.(interface{ Unwrap() http.ResponseWriter }); ok {
				w = u.Unwrap()
			} else {
				return false
			}
		case interface{ Unwrap() http.ResponseWriter }:
			w = tw.Unwrap()
		default:
			return false
		}
	}
	return false
}

// Recovery returns HTTP middleware that recovers from panics and emits an INTERNAL_ERROR response.
func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := &recoveryResponseWriter{ResponseWriter: w}
			defer func() {
				if rec := recover(); rec != nil {
					if rec == http.ErrAbortHandler {
						panic(rec)
					}
					logger.Error("panic recovered in http handler",
						"panic", fmt.Sprintf("%T", rec),
						"method", r.Method,
						"path", r.URL.Path,
					)
					if isResponseCommitted(rw) {
						panic(http.ErrAbortHandler)
					}
					apperrors.WriteHTTP(w, apperrors.New(apperrors.CodeInternalError, "internal server error", nil))
				}
			}()
			next.ServeHTTP(rw, r)
		})
	}
}

// Recover returns a default panic recovery middleware using slog.Default().
func Recover() func(http.Handler) http.Handler {
	return Recovery(nil)
}

// RequireAuth validates session credentials from cookies or Bearer headers.
func RequireAuth(sessionSvc session.Service, cfg *config.Config) func(http.Handler) http.Handler {
	if cfg == nil {
		defaultCfg := config.DefaultConfig()
		cfg = &defaultCfg
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if sessionSvc == nil {
				apperrors.WriteHTTP(w, apperrors.New(apperrors.CodeInternalError, "session service unconfigured", nil))
				return
			}

			var rawID string
			var err error
			var isBearer bool

			if r.Header.Get("Authorization") != "" {
				// If Authorization header is present, strictly authenticate via Bearer token.
				// Never fall back to cookie authentication to prevent CSRF bypass via Bearer header spoofing.
				isBearer = true
				rawID, err = session.ReadBearerToken(r)
				if err != nil {
					apperrors.WriteHTTP(w, err)
					return
				}
			} else {
				// No Authorization header: authenticate via session cookie.
				rawID, err = session.ReadSessionCookie(r, cfg)
				if err != nil {
					apperrors.WriteHTTP(w, err)
					return
				}
			}

			// 3. Validate session lifetime & state
			sess, err := sessionSvc.GetSession(r.Context(), rawID)
			if err != nil {
				apperrors.WriteHTTP(w, err)
				return
			}
			if sess == nil {
				apperrors.WriteHTTP(w, apperrors.ErrSessionNotFound)
				return
			}

			// Enforce transport binding: cookie sessions must be delivered via cookie;
			// bearer sessions must be delivered via Authorization: Bearer.
			if isBearer && sess.Type != db.SessionTypeBearer {
				apperrors.WriteHTTP(w, apperrors.ErrSessionInvalid)
				return
			}
			if !isBearer && sess.Type != db.SessionTypeCookie {
				apperrors.WriteHTTP(w, apperrors.ErrSessionInvalid)
				return
			}

			// 4. Inject authenticated session data into request context
			ctx := r.Context()
			ctx = context.WithValue(ctx, contextKeyUserID, sess.UserID)
			ctx = context.WithValue(ctx, contextKeySessionID, sess.ID)
			ctx = context.WithValue(ctx, contextKeySession, sess)
			ctx = context.WithValue(ctx, contextKeyRawID, redactedToken(rawID))

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
