package session

import (
	"time"

	"github.com/google/uuid"
	"github.com/kaiizer777/go-auth/db"
)

// Session is the domain-layer view returned to callers.
// It never contains the raw session ID — that's returned once at creation only.
// IDHash is the SHA-256 hex of the raw session ID; safe for wire responses; NEVER logged.
type Session struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	IDHash            string
	Type              db.SessionType
	IPAddress         string
	UserAgent         string
	CredentialVersion int
	LastActiveAt      time.Time
	AbsoluteExpiresAt time.Time
	CreatedAt         time.Time
}

func fromDB(s *db.Session) *Session {
	if s == nil {
		return nil
	}
	return &Session{
		ID:                s.ID,
		UserID:            s.UserID,
		IDHash:            s.IDHash,
		Type:              s.SessionType,
		IPAddress:         s.IPAddress,
		UserAgent:         s.UserAgent,
		CredentialVersion: s.CredentialVersion,
		LastActiveAt:      s.LastActiveAt,
		AbsoluteExpiresAt: s.AbsoluteExpiresAt,
		CreatedAt:         s.CreatedAt,
	}
}
