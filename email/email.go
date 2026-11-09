package email

import (
	"context"
	"time"
)

// VerificationEmailPayload contains parameters needed to deliver an email verification link.
type VerificationEmailPayload struct {
	UserID    string    `json:"user_id"`
	To        string    `json:"to"`
	Token     string    `json:"token"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PasswordResetEmailPayload contains parameters needed to deliver a password reset link.
type PasswordResetEmailPayload struct {
	UserID    string    `json:"user_id"`
	To        string    `json:"to"`
	Token     string    `json:"token"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SendVerificationEmailFunc is the callback provided by the consuming app.
type SendVerificationEmailFunc func(ctx context.Context, payload VerificationEmailPayload) error

// SendPasswordResetEmailFunc is the callback provided by the consuming app.
type SendPasswordResetEmailFunc func(ctx context.Context, payload PasswordResetEmailPayload) error

// BuildVerificationURL constructs the verification link URL.
func BuildVerificationURL(baseURL, token string) string {
	return baseURL + "/auth/verify/email?token=" + token
}

// BuildResetURL constructs the password reset link URL.
func BuildResetURL(baseURL, token string) string {
	return baseURL + "/auth/password/reset?token=" + token
}

func buildVerificationURL(baseURL, token string) string {
	return BuildVerificationURL(baseURL, token)
}

func buildResetURL(baseURL, token string) string {
	return BuildResetURL(baseURL, token)
}

// DispatcherConfig holds email dispatcher settings owned by the email package.
type DispatcherConfig struct {
	BaseURL                string
	AsyncEmailDispatch     bool
	EmailDispatchTimeout   time.Duration
	SendVerificationEmail  SendVerificationEmailFunc
	SendPasswordResetEmail SendPasswordResetEmailFunc
}
