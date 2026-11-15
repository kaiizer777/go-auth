package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

// SessionHandler exposes HTTP endpoints for session querying and revocation.
type SessionHandler struct {
	sessionSvc session.Service
	db         *gorm.DB
	cfg        *config.Config
}

// NewSessionHandler constructs a concrete SessionHandler.
func NewSessionHandler(sessionSvc session.Service, gormDB *gorm.DB, cfg *config.Config) *SessionHandler {
	return &SessionHandler{
		sessionSvc: sessionSvc,
		db:         gormDB,
		cfg:        cfg,
	}
}

// sessionWireResponse is the wire JSON shape for session endpoints.
// session_id is strictly the 64-character SHA-256 hex digest of the raw session ID.
// Raw session IDs and internal database UUIDs are never exposed.
type sessionWireResponse struct {
	SessionID    string    `json:"session_id"`
	CreatedAt    time.Time `json:"created_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	SessionType  string    `json:"session_type"`
}

func toWireResponse(s *session.Session) sessionWireResponse {
	return sessionWireResponse{
		SessionID:    s.IDHash,
		CreatedAt:    s.CreatedAt,
		LastActiveAt: s.LastActiveAt,
		ExpiresAt:    s.AbsoluteExpiresAt,
		SessionType:  string(s.Type),
	}
}

// GetCurrentSession returns the metadata of the currently authenticated session.
func (h *SessionHandler) GetCurrentSession(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		apperrors.WriteHTTP(w, apperrors.ErrSessionNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"session": toWireResponse(sess)})
}

// Logout invalidates the active session on the server and clears the session cookie.
func (h *SessionHandler) Logout(w http.ResponseWriter, r *http.Request) {
	rawID := rawIDFromContext(r.Context())
	userID := userIDFromContext(r.Context())
	ip := realIP(r)

	if h.sessionSvc != nil && rawID != "" {
		if err := h.sessionSvc.InvalidateSession(r.Context(), rawID); err != nil {
			apperrors.WriteHTTP(w, err)
			return
		}
	}

	session.ClearSessionCookie(w, h.cfg)

	slog.InfoContext(r.Context(), "logout",
		"user_id", userID.String(),
		"ip", ip,
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

// ListSessions returns all active, non-expired sessions belonging to the authenticated user.
func (h *SessionHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	currentSess := sessionFromContext(r.Context())

	if h.db == nil {
		apperrors.WriteHTTP(w, apperrors.New(apperrors.CodeInternalError, "database unavailable", nil))
		return
	}

	var records []db.Session
	if err := h.db.WithContext(r.Context()).
		Where("user_id = ?", userID).
		Order("last_active_at DESC").
		Find(&records).Error; err != nil {
		apperrors.WriteHTTP(w, apperrors.New(apperrors.CodeInternalError, "failed to list sessions", err))
		return
	}

	now := time.Now().UTC()
	type sessionListItem struct {
		sessionWireResponse
		IsCurrent bool `json:"is_current"`
	}

	results := make([]sessionListItem, 0, len(records))
	for _, rec := range records {
		if now.After(rec.AbsoluteExpiresAt) {
			continue
		}
		if now.After(rec.LastActiveAt.Add(h.cfg.SessionIdleTimeout)) {
			continue
		}
		isCurrent := currentSess != nil && rec.IDHash == currentSess.IDHash
		results = append(results, sessionListItem{
			sessionWireResponse: sessionWireResponse{
				SessionID:    rec.IDHash,
				CreatedAt:    rec.CreatedAt,
				LastActiveAt: rec.LastActiveAt,
				ExpiresAt:    rec.AbsoluteExpiresAt,
				SessionType:  string(rec.SessionType),
			},
			IsCurrent: isCurrent,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"sessions": results})
}

// InvalidateAllSessions revokes every session belonging to the user and clears the cookie.
func (h *SessionHandler) InvalidateAllSessions(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	ip := realIP(r)

	if h.sessionSvc != nil {
		if err := h.sessionSvc.InvalidateAllUserSessions(r.Context(), userID); err != nil {
			apperrors.WriteHTTP(w, err)
			return
		}
	}

	session.ClearSessionCookie(w, h.cfg)

	slog.InfoContext(r.Context(), "all_sessions_invalidated",
		"user_id", userID.String(),
		"ip", ip,
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "All sessions invalidated"})
}

// RotateSession generates a fresh session identifier and invalidates the old one.
func (h *SessionHandler) RotateSession(w http.ResponseWriter, r *http.Request) {
	oldRawID := rawIDFromContext(r.Context())
	if oldRawID == "" {
		apperrors.WriteHTTP(w, apperrors.ErrSessionNotFound)
		return
	}

	ip := realIP(r)
	ua := r.UserAgent()

	newSess, newRawID, err := h.sessionSvc.RotateSession(r.Context(), oldRawID, ip, ua)
	if err != nil {
		apperrors.WriteHTTP(w, err)
		return
	}

	if newSess.Type == db.SessionTypeBearer || r.Header.Get("X-Auth-Type") == "bearer" || r.URL.Query().Get("type") == "bearer" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      newRawID,
			"expires_at": newSess.AbsoluteExpiresAt,
		})
		return
	}

	session.SetSessionCookie(w, newRawID, h.cfg)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Session rotated successfully",
	})
}
