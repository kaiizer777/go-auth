package db

import (
	"context"
	stderrors "errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
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
// NormalizeEmail (lower() folds by collation, trim() strips only spaces).
//
// Keys are NormalizeEmail output, so the rows are reachable by the same
// ClaimedEmails().Claim/Get the write paths use. The run is idempotent and
// all-or-nothing: it validates every address, then writes inside one transaction,
// so a failure commits nothing. When an address is held by more than one account
// it aborts before writing anything, listing every such address and its competing
// accounts, instead of choosing a winner: electing one strips the other account's
// address attribution while its rows keep pointing at an address it no longer
// claims.
func BackfillClaimedEmails(ctx context.Context, database *gorm.DB) (ClaimBackfillResult, error) {
	if database == nil {
		return ClaimBackfillResult{}, fmt.Errorf("claimed_emails backfill: nil database")
	}
	var (
		result      ClaimBackfillResult
		conflictErr error
	)
	err := database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		holders, sourceConflicts, err := collectClaimHolders(ctx, tx)
		if err != nil {
			return err
		}

		conflicts := make(map[string][]uuid.UUID, len(sourceConflicts))
		for key, owners := range sourceConflicts {
			conflicts[key] = owners
		}
		keys := make([]string, 0, len(holders))
		for key, holder := range holders {
			keys = append(keys, key)
			claim, gerr := readClaim(ctx, tx, key)
			switch {
			case gerr == nil && claim.OwnerUserID != holder.owner:
				conflicts[key] = appendUnique(appendUnique(conflicts[key], holder.owner), claim.OwnerUserID)
			case gerr != nil && !stderrors.Is(gerr, gorm.ErrRecordNotFound):
				return fmt.Errorf("read %q: %w", key, gerr)
			}
		}
		if len(conflicts) > 0 {
			conflictErr = conflictError(conflicts)
			return conflictErr
		}

		sort.Strings(keys)
		for _, key := range keys {
			holder := holders[key]
			claim, gerr := readClaim(ctx, tx, key)
			switch {
			case gerr != nil && !stderrors.Is(gerr, gorm.ErrRecordNotFound):
				return fmt.Errorf("read %q: %w", key, gerr)
			case gerr != nil:
				result.Claims++
			case holder.verified && !claim.Verified:
				result.Promoted++
			}
			if cerr := ClaimWithin(ctx, tx, key, holder.owner, holder.verified); cerr != nil {
				return fmt.Errorf("claim %q: %w", key, cerr)
			}
		}
		return nil
	})
	if conflictErr != nil {
		return ClaimBackfillResult{}, conflictErr
	}
	if err != nil {
		return ClaimBackfillResult{}, fmt.Errorf("claimed_emails backfill: %w", err)
	}
	return result, nil
}

// readClaim returns the claim for key, or gorm.ErrRecordNotFound.
func readClaim(ctx context.Context, database *gorm.DB, key string) (*ClaimedEmail, error) {
	var claim ClaimedEmail
	if err := database.WithContext(ctx).Where("email = ?", key).First(&claim).Error; err != nil {
		return nil, err
	}
	return &claim, nil
}

// collectClaimHolders groups users.email and oauth_accounts.email by the key the
// application will look them up with, and reports the keys whose owners disagree.
func collectClaimHolders(ctx context.Context, database *gorm.DB) (map[string]claimHolder, map[string][]uuid.UUID, error) {
	var users []User
	if err := database.WithContext(ctx).Select("id", "email", "email_verified").Find(&users).Error; err != nil {
		return nil, nil, err
	}
	var links []OAuthAccount
	if err := database.WithContext(ctx).Select("user_id", "email", "verified").Find(&links).Error; err != nil {
		return nil, nil, err
	}

	holders := make(map[string]claimHolder, len(users)+len(links))
	conflicts := make(map[string][]uuid.UUID)
	add := func(email string, owner uuid.UUID, verified bool) {
		key := NormalizeEmail(email)
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
