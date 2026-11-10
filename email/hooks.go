package email

import "context"

// SimpleSendVerificationEmailFunc defines the callback for delivering verification emails.
type SimpleSendVerificationEmailFunc func(ctx context.Context, recipient, token string) error

// SimpleSendPasswordResetEmailFunc defines the callback for delivering password reset emails.
type SimpleSendPasswordResetEmailFunc func(ctx context.Context, recipient, token string) error

// Hooks provides custom callbacks for transactional email events.
type Hooks struct {
	SendVerificationEmail  SimpleSendVerificationEmailFunc
	SendPasswordResetEmail SimpleSendPasswordResetEmailFunc
}
