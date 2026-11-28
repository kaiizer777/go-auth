package db

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kaiizer777/go-auth/errors"
)

// ReleaseLinkClaim releases the address claim of a link that is being removed,
// but only when nothing else holds the address: neither the owner's own account
// row nor another link of the same owner. The claim names one account, so a
// release is always scoped to the link's owner and can never take an address from
// another account.
//
// Callers invoke it in the same transaction as the link delete, after the row is
// gone, so a stale claim cannot outlive the row that justified it. The owner row
// is read FOR UPDATE first: a concurrent attachLink of the same owner holds that
// same lock, so either it commits before this scan (and its link is seen, blocking
// the release) or it waits until after the release (and re-claims the address
// itself). Without the lock, a link inserted between the scan and the release
// would keep the address without its claim.
func ReleaseLinkClaim(ctx context.Context, store Store, link OAuthAccount) error {
	key := NormalizeEmail(link.Email)
	if key == "" {
		return nil
	}
	owner, err := store.Users().GetByIDForUpdate(ctx, link.UserID)
	switch {
	case err == nil && owner != nil:
		if NormalizeEmail(owner.Email) == key {
			return nil
		}
	case err != nil && !errors.Is(err, gorm.ErrRecordNotFound) && !errors.Is(err, errors.ErrUserNotFound):
		return err
	}
	links, err := store.OAuthAccounts().GetByUserID(ctx, link.UserID)
	if err != nil {
		return err
	}
	for _, other := range links {
		if other != nil && NormalizeEmail(other.Email) == key {
			return nil
		}
	}
	return store.ClaimedEmails().Release(ctx, key, link.UserID)
}

func dialectorIs(tx *gorm.DB, name string) bool {
	return tx.Dialector != nil && strings.Contains(strings.ToLower(tx.Name()), name)
}

func lockForUpdate(tx *gorm.DB) *gorm.DB {
	if dialectorIs(tx, "sqlite") {
		return tx
	}
	return tx.Clauses(clause.Locking{Strength: "UPDATE"})
}

// claimInsertStatement builds the idempotent claim insert. A duplicate must not
// fail the statement: PostgreSQL aborts the whole transaction on a constraint
// error, so "insert, then inspect the error" cannot work there. MySQL needs its
// own no-op on-duplicate form; GORM's clause translation is not relied on.
func claimInsertStatement(tx *gorm.DB) string {
	const columns = "(email, owner_user_id, verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
	if dialectorIs(tx, "mysql") {
		return "INSERT INTO claimed_emails " + columns + " ON DUPLICATE KEY UPDATE email = email"
	}
	return "INSERT INTO claimed_emails " + columns + " ON CONFLICT (email) DO NOTHING"
}

// ClaimKey normalises email and validates the result against the same address
// rule the rest of the system enforces (ValidateEmail). It is the only way a
// claim key may be produced: the key is a primary key (SQL) or a collection _id
// (MongoDB), so the value must be an address and not an arbitrary string.
//
// An empty or whitespace-only address yields ("", nil): such an address is never
// claimable and callers keep their existing no-op behaviour. Anything ValidateEmail
// rejects yields ErrInvalidEmail.
func ClaimKey(email string) (string, error) {
	key := NormalizeEmail(email)
	if key == "" {
		return "", nil
	}
	if len(key) > claimKeyMaxLength || ValidateEmail(key) != nil {
		return "", errors.ErrInvalidEmail
	}
	return key, nil
}

const claimKeyMaxLength = 255

// ClaimWithin takes the claim for email on behalf of ownerID inside the caller's
// transaction. It is the single arbiter both the store and the explicit import use:
// the insert blocks a competing writer, and the ownership decision is read back
// under a row lock.
func ClaimWithin(ctx context.Context, database *gorm.DB, email string, ownerID uuid.UUID, verified bool) error {
	key, err := ClaimKey(email)
	if err != nil {
		return err
	}
	if key == "" {
		return nil
	}
	tx := database.WithContext(ctx)
	now := time.Now().UTC()
	if err := tx.Exec(claimInsertStatement(tx), key, ownerID, verified, now, now).Error; err != nil {
		return NormalizeMySQLError(err)
	}
	// Locking read: under MySQL's default REPEATABLE READ a plain SELECT reuses
	// the snapshot an earlier statement in this transaction took, so it would miss
	// the claim a competing writer committed while this insert was blocked.
	var claim ClaimedEmail
	if err := lockForUpdate(tx).Where("email = ?", key).First(&claim).Error; err != nil {
		return err
	}
	if claim.OwnerUserID != ownerID {
		return errors.ErrEmailClaimed
	}
	if verified && !claim.Verified {
		return tx.Model(&ClaimedEmail{}).Where("email = ? AND owner_user_id = ?", key, ownerID).Update("verified", true).Error
	}
	return nil
}
