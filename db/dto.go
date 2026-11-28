package db

import (
	"encoding/hex"
	"fmt"
	"net/mail"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/kaiizer777/go-auth/errors"
)

// ValidateEmail validates an email address according to Phase 3 requirements.
// It enforces non-empty, max 255 length, no spaces, RFC 5322 compliance via net/mail,
// and domain structure (at least one dot, no empty labels, no trailing/leading dots).
//
// This is the authenticity rule: login, password-reset requests and refresh only
// need to recognise an existing address, so they must keep accepting a stored
// address even if it would no longer fit a new claim key. Use ValidateClaimableEmail
// where a claim is about to be created.
func ValidateEmail(email string) error {
	if email == "" || strings.TrimSpace(email) == "" {
		return errors.New(errors.CodeInvalidEmail, "email is required", nil)
	}
	if len(email) > 255 {
		return errors.New(errors.CodeInvalidEmail, "email exceeds maximum length of 255 characters", nil)
	}
	if strings.IndexFunc(email, unicode.IsSpace) >= 0 {
		return errors.New(errors.CodeInvalidEmail, "email cannot contain spaces", nil)
	}

	parsed, err := mail.ParseAddress(email)
	if err != nil {
		return errors.New(errors.CodeInvalidEmail, "invalid email format", err)
	}

	lastAt := strings.LastIndex(parsed.Address, "@")
	if lastAt == -1 || lastAt == 0 || lastAt == len(parsed.Address)-1 {
		return errors.New(errors.CodeInvalidEmail, "invalid email format", nil)
	}

	localPart := parsed.Address[:lastAt]
	domainPart := parsed.Address[lastAt+1:]

	if parsed.Address != email && email != fmt.Sprintf("%q@%s", localPart, domainPart) {
		return errors.New(errors.CodeInvalidEmail, "invalid email format", nil)
	}

	if !strings.Contains(domainPart, ".") {
		return errors.New(errors.CodeInvalidEmail, "invalid email domain", nil)
	}

	labels := strings.Split(domainPart, ".")
	for _, label := range labels {
		if label == "" {
			return errors.New(errors.CodeInvalidEmail, "invalid email domain", nil)
		}
	}

	return nil
}

// ValidateClaimableEmail is ValidateEmail plus the claim key's folded-length
// limit. Go's unicode case folding can expand a character (U+023A is 2 bytes and
// folds to U+2C65, 3 bytes), so an address that fits raw can exceed the key limit
// once normalised. An address accepted here can always be claimed; an existing
// account whose stored address no longer fits keeps logging in because login paths
// use ValidateEmail.
func ValidateClaimableEmail(email string) error {
	if err := ValidateEmail(email); err != nil {
		return err
	}
	if key := NormalizeEmail(email); len(key) > claimKeyMaxLength {
		return errors.New(errors.CodeInvalidEmail, "email exceeds maximum length of 255 characters after case folding", nil)
	}
	return nil
}

// NormalizeEmail trims leading and trailing whitespace and lowercases the address
// with Go's locale-independent folding. Stored account emails keep their original
// case for delivery (RFC 5321 local parts can be case-sensitive).
//
// It is the claim key: claimed_emails stores this value and compares it byte for
// byte, so a reservation never depends on a database collation. Account lookups
// still fold in SQL (LOWER(email)), which agrees for ASCII and is not guaranteed
// to for non-ASCII; the claim key, not the lookup key, is what both writers agree
// on.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// LookupKey returns the canonical case-insensitive key for an email address.
func LookupKey(email string) string {
	return NormalizeEmail(email)
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
	if err := ValidateClaimableEmail(r.Email); err != nil {
		return err
	}
	if r.Password == "" {
		return errors.New(errors.CodeValidationError, "password is required", nil)
	}
	return nil
}

// NormalizedEmail returns the trimmed, lowercase email address.
func (r SignupRequest) NormalizedEmail() string {
	return NormalizeEmail(r.Email)
}

// Normalize trims and lowercases the email address in-place.
func (r *SignupRequest) Normalize() {
	r.Email = NormalizeEmail(r.Email)
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

// NormalizedEmail returns the trimmed, lowercase email address.
func (r LoginRequest) NormalizedEmail() string {
	return NormalizeEmail(r.Email)
}

// Normalize trims and lowercases the email address in-place.
func (r *LoginRequest) Normalize() {
	r.Email = NormalizeEmail(r.Email)
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

// NormalizedEmail returns the trimmed, lowercase email address.
func (r PasswordResetRequest) NormalizedEmail() string {
	return NormalizeEmail(r.Email)
}

// Normalize trims and lowercases the email address in-place.
func (r *PasswordResetRequest) Normalize() {
	r.Email = NormalizeEmail(r.Email)
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
