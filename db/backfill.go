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

// claimBackfillBatchSize is the number of source rows read per page and written
// per transaction. One page of users plus one page of links is the unit of work.
const claimBackfillBatchSize = 500

// ClaimBackfillResult reports what BackfillClaimedEmails did.
type ClaimBackfillResult struct {
	Claims   int
	Promoted int
	// Skipped counts source rows whose address ClaimKey rejects. They are not
	// claimable anywhere, so they are reported rather than aborting the import.
	Skipped int
}

// claimHolder is one account's reservation of one normalised address.
type claimHolder struct {
	owner    uuid.UUID
	verified bool
}

// claimConflictError names every address one page proved to have competing
// owners, with the account IDs involved.
type claimConflictError struct {
	conflicts map[string][]uuid.UUID
}

func (e *claimConflictError) Error() string {
	keys := make([]string, 0, len(e.conflicts))
	for key := range e.conflicts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		owners := e.conflicts[key]
		names := make([]string, 0, len(owners))
		for _, owner := range owners {
			names = append(names, owner.String())
		}
		parts = append(parts, fmt.Sprintf("%s held by %s", key, strings.Join(names, ", ")))
	}
	return fmt.Sprintf("claimed_emails backfill aborted: %d address(es) held by more than one account: %s",
		len(keys), strings.Join(parts, "; "))
}

// BackfillClaimedEmails imports the addresses already stored in users.email and
// oauth_accounts.email into claimed_emails. It is an explicit operator/embedder
// utility, not a startup step: nothing in this package calls it, because booting
// must never scan the account tables. An embedder upgrading a database that may
// contain accounts must call it once after migrating.
//
// Keys are NormalizeEmail output, so the rows are reachable by the same
// ClaimedEmails().Claim/Get the write paths use. Rows are paged by primary key and
// each page is written in one short transaction: memory stays bounded, and a
// failed page commits nothing, so re-running continues from a known state. It is
// idempotent, so re-running after success changes nothing.
//
// When an address is held by more than one account, the page aborts before writing
// anything and the error names every conflicting address and account: electing a
// winner would strip the other account's attribution while its rows keep pointing
// at an address it no longer claims. Resolve the listed rows and re-run.
func BackfillClaimedEmails(ctx context.Context, database *gorm.DB) (ClaimBackfillResult, error) {
	if database == nil {
		return ClaimBackfillResult{}, fmt.Errorf("claimed_emails backfill: nil database")
	}
	var total ClaimBackfillResult
	for _, load := range []claimPageLoader{loadUserClaimRows, loadLinkClaimRows} {
		result, err := backfillClaimSource(ctx, database, load)
		total.Claims += result.Claims
		total.Promoted += result.Promoted
		total.Skipped += result.Skipped
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// claimPageLoader reads one keyset page of source rows after cursor.
type claimPageLoader func(tx *gorm.DB, cursor uuid.UUID, limit int) ([]claimRow, error)

// claimRow is one source row reduced to what the import needs.
type claimRow struct {
	id       uuid.UUID
	owner    uuid.UUID
	key      string
	verified bool
	// invalid marks a row whose address ClaimKey rejects: it is counted and
	// skipped, never written.
	invalid bool
}

func loadUserClaimRows(tx *gorm.DB, cursor uuid.UUID, limit int) ([]claimRow, error) {
	var users []User
	if err := tx.Select("id", "email", "email_verified").
		Where("id > ?", cursor).Order("id ASC").Limit(limit).Find(&users).Error; err != nil {
		return nil, err
	}
	rows := make([]claimRow, 0, len(users))
	for _, user := range users {
		key, kerr := ClaimKey(user.Email)
		rows = append(rows, claimRow{
			id:       user.ID,
			owner:    user.ID,
			key:      key,
			verified: user.EmailVerified,
			invalid:  kerr != nil,
		})
	}
	return rows, nil
}

func loadLinkClaimRows(tx *gorm.DB, cursor uuid.UUID, limit int) ([]claimRow, error) {
	var links []OAuthAccount
	if err := tx.Select("id", "user_id", "email", "verified").
		Where("id > ?", cursor).Order("id ASC").Limit(limit).Find(&links).Error; err != nil {
		return nil, err
	}
	rows := make([]claimRow, 0, len(links))
	for _, link := range links {
		key, kerr := ClaimKey(link.Email)
		rows = append(rows, claimRow{
			id:       link.ID,
			owner:    link.UserID,
			key:      key,
			verified: link.Verified,
			invalid:  kerr != nil,
		})
	}
	return rows, nil
}

func backfillClaimSource(ctx context.Context, database *gorm.DB, load claimPageLoader) (ClaimBackfillResult, error) {
	var total ClaimBackfillResult
	cursor := uuid.Nil
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var (
			batchResult ClaimBackfillResult
			lastID      uuid.UUID
			pageSize    int
		)
		err := database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			page, lerr := load(tx, cursor, claimBackfillBatchSize)
			if lerr != nil {
				return lerr
			}
			pageSize = len(page)
			if pageSize == 0 {
				return nil
			}
			lastID = page[pageSize-1].id
			batchResult, lerr = applyClaimPage(ctx, tx, page)
			return lerr
		})
		var conflict *claimConflictError
		if stderrors.As(err, &conflict) {
			return total, conflict
		}
		if err != nil {
			return total, fmt.Errorf("claimed_emails backfill: %w", err)
		}
		total.Claims += batchResult.Claims
		total.Promoted += batchResult.Promoted
		total.Skipped += batchResult.Skipped
		if pageSize < claimBackfillBatchSize {
			return total, nil
		}
		cursor = lastID
	}
}

// applyClaimPage writes one page of source rows inside the caller's transaction.
// It reads the page's existing claims in one statement, aborts the page before any
// write when an address has a competing owner, then applies the claims.
func applyClaimPage(ctx context.Context, tx *gorm.DB, page []claimRow) (ClaimBackfillResult, error) {
	holders := make(map[string]claimHolder, len(page))
	conflicts := make(map[string][]uuid.UUID)
	keys := make([]string, 0, len(page))
	var skipped int
	for _, row := range page {
		if row.invalid {
			skipped++
			continue
		}
		if row.key == "" {
			continue
		}
		current, ok := holders[row.key]
		switch {
		case !ok:
			holders[row.key] = claimHolder{owner: row.owner, verified: row.verified}
			keys = append(keys, row.key)
		case current.owner != row.owner:
			// Two accounts in this page parsed the same address.
			conflicts[row.key] = appendUnique(appendUnique(conflicts[row.key], current.owner), row.owner)
		default:
			current.verified = current.verified || row.verified
			holders[row.key] = current
		}
	}
	if len(keys) == 0 {
		return ClaimBackfillResult{Skipped: skipped}, nil
	}

	// One read for the page, so every conflict is reported and nothing is written
	// when one exists.
	var existing []ClaimedEmail
	if err := tx.Select("email", "owner_user_id", "verified").
		Where("email IN ?", keys).Find(&existing).Error; err != nil {
		return ClaimBackfillResult{}, err
	}
	existingByKey := make(map[string]ClaimedEmail, len(existing))
	for _, claim := range existing {
		key := string(claim.Email)
		existingByKey[key] = claim
		if claim.OwnerUserID != holders[key].owner {
			conflicts[key] = appendUnique(appendUnique(conflicts[key], holders[key].owner), claim.OwnerUserID)
		}
	}
	if len(conflicts) > 0 {
		return ClaimBackfillResult{}, &claimConflictError{conflicts: conflicts}
	}

	sort.Strings(keys)
	result := ClaimBackfillResult{Skipped: skipped}
	for _, key := range keys {
		holder := holders[key]
		if claim, ok := existingByKey[key]; !ok {
			result.Claims++
		} else if holder.verified && !claim.Verified {
			result.Promoted++
		}
		if err := ClaimWithin(ctx, tx, key, holder.owner, holder.verified); err != nil {
			return result, fmt.Errorf("claim %q: %w", key, err)
		}
	}
	return result, nil
}

func appendUnique(ids []uuid.UUID, id uuid.UUID) []uuid.UUID {
	for _, existing := range ids {
		if existing == id {
			return ids
		}
	}
	return append(ids, id)
}
