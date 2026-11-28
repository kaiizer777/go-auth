package gormstore

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
)

// ClaimBackfillResult reports what BackfillClaimedEmails did.
type ClaimBackfillResult struct {
	Claims   int
	Promoted int
}

// claimHolder is one account's reservation of one normalised address.
type claimHolder struct {
	owner    uuid.UUID
	verified bool
}

// BackfillClaimedEmails imports the addresses already stored in users.email and
// oauth_accounts.email into claimed_emails. It is the only supported import path:
// no SQL migration backfills, because SQL lower()/trim() cannot reproduce
// db.NormalizeEmail (lower() folds by collation, trim() strips only spaces).
//
// Keys are db.NormalizeEmail output, so the rows are reachable by the same
// ClaimedEmails().Claim/Get the write paths use. The run is idempotent. When an
// address is held by more than one account it aborts, listing every such address
// and its competing accounts, instead of choosing a winner: electing one strips
// the other account's address attribution while its rows keep pointing at an
// address it no longer claims.
func BackfillClaimedEmails(ctx context.Context, database *gorm.DB) (ClaimBackfillResult, error) {
	if database == nil {
		return ClaimBackfillResult{}, fmt.Errorf("claimed_emails backfill: nil database")
	}
	holders, sourceConflicts, err := collectClaimHolders(ctx, database)
	if err != nil {
		return ClaimBackfillResult{}, fmt.Errorf("claimed_emails backfill: %w", err)
	}

	store := New(database)
	conflicts := make(map[string][]uuid.UUID, len(sourceConflicts))
	for key, owners := range sourceConflicts {
		conflicts[key] = owners
	}
	keys := make([]string, 0, len(holders))
	for key, holder := range holders {
		keys = append(keys, key)
		claim, gerr := store.ClaimedEmails().Get(ctx, key)
		switch {
		case gerr == nil && claim.OwnerUserID != holder.owner:
			conflicts[key] = appendUnique(appendUnique(conflicts[key], holder.owner), claim.OwnerUserID)
		case gerr != nil && !isNotFound(gerr):
			return ClaimBackfillResult{}, fmt.Errorf("claimed_emails backfill: read %q: %w", key, gerr)
		}
	}
	if len(conflicts) > 0 {
		return ClaimBackfillResult{}, conflictError(conflicts)
	}

	sort.Strings(keys)
	var result ClaimBackfillResult
	for _, key := range keys {
		holder := holders[key]
		claim, gerr := store.ClaimedEmails().Get(ctx, key)
		switch {
		case gerr != nil && !isNotFound(gerr):
			return result, fmt.Errorf("claimed_emails backfill: read %q: %w", key, gerr)
		case gerr != nil:
			result.Claims++
		case holder.verified && !claim.Verified:
			result.Promoted++
		}
		if cerr := store.ClaimedEmails().Claim(ctx, key, holder.owner, holder.verified); cerr != nil {
			return result, fmt.Errorf("claimed_emails backfill: claim %q: %w", key, cerr)
		}
	}
	return result, nil
}

// collectClaimHolders groups users.email and oauth_accounts.email by the key the
// application will look them up with, and reports the keys whose owners disagree.
func collectClaimHolders(ctx context.Context, database *gorm.DB) (map[string]claimHolder, map[string][]uuid.UUID, error) {
	var users []db.User
	if err := database.WithContext(ctx).Select("id", "email", "email_verified").Find(&users).Error; err != nil {
		return nil, nil, err
	}
	var links []db.OAuthAccount
	if err := database.WithContext(ctx).Select("user_id", "email", "verified").Find(&links).Error; err != nil {
		return nil, nil, err
	}

	holders := make(map[string]claimHolder, len(users)+len(links))
	conflicts := make(map[string][]uuid.UUID)
	add := func(email string, owner uuid.UUID, verified bool) {
		key := db.NormalizeEmail(email)
		if key == "" {
			return
		}
		current, ok := holders[key]
		if !ok {
			holders[key] = claimHolder{owner: owner, verified: verified}
			return
		}
		if current.owner != owner {
			// More than one account parsed the same address: the caller must
			// resolve it, so keep only the conflict, not a winner.
			conflicts[key] = appendUnique(appendUnique(conflicts[key], current.owner), owner)
			return
		}
		current.verified = current.verified || verified
		holders[key] = current
	}
	for _, user := range users {
		add(user.Email, user.ID, user.EmailVerified)
	}
	for _, link := range links {
		add(link.Email, link.UserID, link.Verified)
	}
	return holders, conflicts, nil
}

// isNotFound reports the store's ordinary "no claim row" result.
func isNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, apperrors.ErrUserNotFound)
}

func appendUnique(ids []uuid.UUID, id uuid.UUID) []uuid.UUID {
	for _, existing := range ids {
		if existing == id {
			return ids
		}
	}
	return append(ids, id)
}

// conflictError names every conflicting address and its competing accounts.
func conflictError(conflicts map[string][]uuid.UUID) error {
	keys := make([]string, 0, len(conflicts))
	for key := range conflicts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		owners := conflicts[key]
		names := make([]string, 0, len(owners))
		for _, owner := range owners {
			names = append(names, owner.String())
		}
		parts = append(parts, fmt.Sprintf("%s held by %s", key, strings.Join(names, ", ")))
	}
	return fmt.Errorf("claimed_emails backfill aborted: %d address(es) held by more than one account: %s",
		len(keys), strings.Join(parts, "; "))
}
