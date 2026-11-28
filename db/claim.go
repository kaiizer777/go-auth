package db

import (
	"context"

	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/errors"
)

// ReleaseLinkClaim releases the address claim of a link that is being removed,
// but only when nothing else holds the address: neither the owner's own account
// row nor another link of the same owner. The claim names one account, so a
// release is always scoped to the link's owner and can never take an address from
// another account.
//
// Callers invoke it in the same transaction as the link delete, after the row is
// gone, so a stale claim cannot outlive the row that justified it.
func ReleaseLinkClaim(ctx context.Context, store Store, link OAuthAccount) error {
	key := NormalizeEmail(link.Email)
	if key == "" {
		return nil
	}
	owner, err := store.Users().GetByID(ctx, link.UserID)
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
