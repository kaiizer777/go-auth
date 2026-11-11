package db

import (
	"time"

	"github.com/google/uuid"
)

// User represents an authenticated account record in the database.
type User struct {
	ID            uuid.UUID `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	Email         string    `gorm:"type:varchar(255);uniqueIndex;not null"`
	PasswordHash  string    `gorm:"type:text;not null"`
	EmailVerified bool      `gorm:"default:false;not null"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// TableName returns the table name for User.
func (User) TableName() string { return "users" }

// Session represents an active authenticated user session.
type Session struct {
	ID            uuid.UUID `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	UserID        uuid.UUID `gorm:"type:uuid;not null;index:idx_sessions_user_id"`
	TokenHash     string    `gorm:"column:token_hash;type:text;uniqueIndex;not null"` // raw token is never persisted
	ExpiresAt     time.Time `gorm:"not null"`
	IdleExpiresAt time.Time `gorm:"not null"`
	CreatedAt     time.Time
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
