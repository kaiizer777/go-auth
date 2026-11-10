package db

import (
	"encoding/hex"
	"net/mail"
	"strings"

	"github.com/google/uuid"

	"github.com/kaiizer777/go-auth/errors"
)

// ValidateEmail validates an email address according to Phase 3 requirements.
// It enforces non-empty, max 255 length, no spaces, RFC 5322 compliance via net/mail,
// and domain structure (at least one dot, no empty labels, no trailing/leading dots).
func ValidateEmail(email string) error {
	if email == "" {
		return errors.New(errors.CodeInvalidEmail, "email is required", nil)
	}
	if len(email) > 255 {
		return errors.New(errors.CodeInvalidEmail, "email exceeds maximum length of 255 characters", nil)
	}
	if strings.Contains(email, " ") {
		return errors.New(errors.CodeInvalidEmail, "email cannot contain spaces", nil)
	}

	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return errors.New(errors.CodeInvalidEmail, "invalid email format", err)
	}

	parts := strings.Split(parsed.Address, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return errors.New(errors.CodeInvalidEmail, "invalid email format", nil)
	}

	domain := parts[1]
	if !strings.Contains(domain, ".") {
		return errors.New(errors.CodeInvalidEmail, "invalid email domain", nil)
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" {
			return errors.New(errors.CodeInvalidEmail, "invalid email domain", nil)
		}
	}

	return nil
}

// ValidateToken validates a 64-character hexadecimal token string.
func ValidateToken(token string) error {
	if len(token) != 64 {
		return errors.New(errors.CodeInvalidToken, "token must be 64 hex characters", nil)
	}
	var buf [32]byte
	if _, err := hex.Decode(buf[:], []byte(token)); err != nil {
		return errors.New(errors.CodeInvalidToken, "token must be valid hexadecimal", err)
	}
	return nil
}

// SignupRequest represents the payload for user registration.
type SignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate validates the signup request fields.
func (r SignupRequest) Validate() error {
	if err := ValidateEmail(r.Email); err != nil {
		return err
	}
	if r.Password == "" {
		return errors.New(errors.CodeValidationError, "password is required", nil)
	}
	return nil
}

// LoginRequest represents the payload for user login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate validates the login request fields.
func (r LoginRequest) Validate() error {
	if err := ValidateEmail(r.Email); err != nil {
		return err
	}
	if r.Password == "" {
		return errors.New(errors.CodeValidationError, "password is required", nil)
	}
	return nil
}

// VerifyEmailRequest represents the payload for email verification.
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// Validate validates the email verification request fields.
func (r VerifyEmailRequest) Validate() error {
	return ValidateToken(r.Token)
}

// PasswordResetRequest represents the payload for requesting a password reset.
type PasswordResetRequest struct {
	Email string `json:"email"`
}

// Validate validates the password reset request fields.
func (r PasswordResetRequest) Validate() error {
	return ValidateEmail(r.Email)
}

// PasswordResetConfirmRequest represents the payload for confirming a password reset.
type PasswordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// Validate validates the password reset confirmation request fields.
func (r PasswordResetConfirmRequest) Validate() error {
	if err := ValidateToken(r.Token); err != nil {
		return err
	}
	if r.NewPassword == "" {
		return errors.New(errors.CodeValidationError, "new password is required", nil)
	}
	return nil
}

// LoginResponse represents the response envelope on successful login.
type LoginResponse struct {
	UserID uuid.UUID `json:"user_id"`
}

// MessageResponse represents a generic success response message envelope.
type MessageResponse struct {
	Message string `json:"message"`
}
