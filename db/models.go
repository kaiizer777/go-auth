package db

import (
	"time"

	"github.com/google/uuid"
)

// User represents an authenticated account record in the database.
type User struct {
	ID            uuid.UUID `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	Email         string    `gorm:"type:varchar(255);uniqueIndex;not null"`
	PasswordHash      string `gorm:"type:text;not null"`
	CredentialVersion int    `gorm:"not null;default:0"`
	EmailVerified     bool   `gorm:"default:false;not null"`
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// TableName returns the table name for User.
func (User) TableName() string { return "users" }

// SessionType represents the session transport type enum.
type SessionType string

const (
	SessionTypeCookie SessionType = "cookie"
	SessionTypeBearer SessionType = "bearer"
)

// Session represents an active authenticated user session.
type Session struct {
	ID                uuid.UUID   `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	UserID            uuid.UUID   `gorm:"type:uuid;not null;index:idx_sessions_user_id"`
	IDHash            string      `gorm:"column:id_hash;type:char(64);uniqueIndex;not null"`
	SessionType       SessionType `gorm:"type:varchar(10);not null;default:'cookie'"`
	IPAddress         string      `gorm:"type:varchar(45);not null;default:''"`
	UserAgent         string      `gorm:"type:text;not null;default:''"`
	CredentialVersion int         `gorm:"not null;default:0"`
	LastActiveAt      time.Time   `gorm:"not null"`
	AbsoluteExpiresAt time.Time   `gorm:"not null"`
	CreatedAt         time.Time   `gorm:"autoCreateTime"`
}

// TableName returns the table name for Session.
func (Session) TableName() string { return "sessions" }

// VerificationToken represents an email verification token record.
type VerificationToken struct {
	TokenHash []byte    `gorm:"primaryKey;column:token_hash;type:bytea"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index:idx_verification_tokens_user_id"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

// TableName returns the table name for VerificationToken.
func (VerificationToken) TableName() string { return "verification_tokens" }

// PasswordResetToken represents a single-use password reset token record.
type PasswordResetToken struct {
	TokenHash []byte    `gorm:"primaryKey;column:token_hash;type:bytea"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index:idx_password_reset_tokens_user_id"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

// TableName returns the table name for PasswordResetToken.
func (PasswordResetToken) TableName() string { return "password_reset_tokens" }
