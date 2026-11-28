package mongostore

import (
	"strings"

	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/kaiizer777/go-auth/errors"
)

// NormalizeMongoError inspects MongoDB driver errors and translates duplicate
// key violations (code 11000) to domain-specific error sentinels.
func NormalizeMongoError(err error) error {
	if err == nil {
		return nil
	}
	if !mongo.IsDuplicateKeyError(err) {
		return err
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, ".claimed_emails index:"):
		// Match the claim collection's index namespace, not the whole message: a
		// users.email duplicate whose value happens to contain "claimed_emails"
		// must still normalise to ErrEmailAlreadyExists. The claim key must never
		// collapse into that sentinel either, because the signup and link paths
		// classify the two differently.
		return errors.ErrEmailClaimed
	case strings.Contains(msg, "uq_users_email") || strings.Contains(msg, "email_1"):
		return errors.ErrEmailAlreadyExists
	case strings.Contains(msg, "uq_totp_used_codes_user_code") || strings.Contains(msg, "code_hash_1") || strings.Contains(msg, "code_hash"):
		return errors.ErrTOTPCodeReplayed
	case strings.Contains(msg, "uq_totp_secrets_user_id") || strings.Contains(msg, "totp_secrets"):
		return errors.ErrTOTPAlreadyEnabled
	case strings.Contains(msg, "uq_oauth_accounts_provider_tenant_uid") || strings.Contains(msg, "uq_oauth_accounts_provider_uid") || strings.Contains(msg, "provider_user_id"):
		return errors.ErrOAuthAccountAlreadyLinked
	default:
		return err
	}
}
