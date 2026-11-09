package db

import (
	"time"

	"github.com/google/uuid"
)

// User represents an authenticated account record.
type User struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey"`
	Email         string    `gorm:"type:varchar(255);uniqueIndex;not null"`
	PasswordHash  string    `gorm:"type:text;not null"`
	EmailVerified bool      `gorm:"default:false;not null"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Session represents an active authenticated user session.
type Session struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID        uuid.UUID `gorm:"type:uuid;not null;index"`
	TokenHash     string    `gorm:"column:token_hash;type:text;uniqueIndex;not null"` // raw token is never persisted
	ExpiresAt     time.Time `gorm:"not null"`
	IdleExpiresAt time.Time `gorm:"not null"`
	CreatedAt     time.Time
}

// VerificationToken represents an email verification token.
type VerificationToken struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index"`
	TokenHash string    `gorm:"column:token_hash;type:text;uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	Used      bool      `gorm:"default:false;not null"`
	CreatedAt time.Time
}

// PasswordResetToken represents a single-use password reset token.
type PasswordResetToken struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index"`
	TokenHash string    `gorm:"column:token_hash;type:text;uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	Used      bool      `gorm:"default:false;not null"`
	CreatedAt time.Time
}
