package email

import "context"

// SendVerificationEmailFunc defines the callback for delivering verification emails.
type SendVerificationEmailFunc func(ctx context.Context, recipient, token string) error

// SendPasswordResetEmailFunc defines the callback for delivering password reset emails.
type SendPasswordResetEmailFunc func(ctx context.Context, recipient, token string) error

// Hooks provides custom callbacks for transactional email events.
type Hooks struct {
	SendVerificationEmail  SendVerificationEmailFunc
	SendPasswordResetEmail SendPasswordResetEmailFunc
}
