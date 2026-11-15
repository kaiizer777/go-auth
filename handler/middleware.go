package handler

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/kaiizer777/go-auth/config"
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
	v, _ := ctx.Value(contextKeyRawID).(string)
	return v
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
	v, ok := ctx.Value(contextKeyRawID).(string)
	return v, ok && v != ""
}

func RawIDFromContext(ctx context.Context) (string, bool) {
	return RawSessionIDFromContext(ctx)
}

// RequireAuth validates session credentials from cookies or Bearer headers.
func RequireAuth(sessionSvc session.Service, cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var rawID string
			var err error

			if r.Header.Get("Authorization") != "" {
				// If Authorization header is present, strictly authenticate via Bearer token.
				// Never fall back to cookie authentication to prevent CSRF bypass via Bearer header spoofing.
				rawID, err = session.ReadBearerToken(r)
				if err != nil {
					apperrors.WriteHTTP(w, err)
					return
				}
			} else {
				// No Authorization header: authenticate via session cookie.
				rawID, err = session.ReadSessionCookie(r, cfg)
				if err != nil {
					apperrors.WriteHTTP(w, apperrors.ErrSessionNotFound)
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

			// 4. Inject authenticated session data into request context
			ctx := r.Context()
			ctx = context.WithValue(ctx, contextKeyUserID, sess.UserID)
			ctx = context.WithValue(ctx, contextKeySessionID, sess.ID)
			ctx = context.WithValue(ctx, contextKeySession, sess)
			ctx = context.WithValue(ctx, contextKeyRawID, rawID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
