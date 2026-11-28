package mongostore

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/kaiizer777/go-auth/db"
)

// oauthVerifiedBackfillID is the schema_migrations marker of the data migration
// that mirrors SQL migration 000009 for MongoDB.
const oauthVerifiedBackfillID = "000009_oauth_account_verified"

// oauthVerifiedProgressID tracks resumable progress for the backfill sweep.
const oauthVerifiedProgressID = "000009_oauth_account_verified_progress"

// DefaultBackfillBatchSize is the maximum number of owners processed per sweep batch.
const DefaultBackfillBatchSize = 500

var backfillBatchSize = DefaultBackfillBatchSize

// BackfillOAuthAccountVerified re-derives oauth_accounts.verified from the
// owning user's local verification, exactly as SQL migration 000009 does: a
// legacy document has no field, decodes as false, and would otherwise be
// rejected and deleted for the verified-email owner whose only login method it
// is. Rows are only ever promoted to true, so the backfill is idempotent and
// safe to interleave with live traffic: an owner that is not verified yet keeps
// its link unverified and a later run after that owner verifies is not needed
// because the link rules re-derive trust from the owner on every callback.
//
// The sweep runs in batches with keyset pagination on _id to prevent cursor
// timeouts. Per-owner updates are batched into a single $in query per chunk.
// Resumable progress is checkpointed in schema_migrations so truncated runs
// resume without restarting from zero. The completion marker is written only
// after the full sweep completes.
func BackfillOAuthAccountVerified(ctx context.Context, database *mongo.Database) error {
	if database == nil {
		return nil
	}
	markers := database.Collection("schema_migrations")
	var marker bson.M
	err := markers.FindOne(ctx, bson.M{"_id": oauthVerifiedBackfillID}).Decode(&marker)
	if err == nil {
		return nil
	}
	if !stderrors.Is(err, mongo.ErrNoDocuments) {
		return err
	}

	users := database.Collection("users")
	links := database.Collection("oauth_accounts")

	// Ensure email_verified index exists before sweeping.
	if _, ierr := users.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email_verified", Value: 1}},
		Options: options.Index().SetName("idx_users_email_verified"),
	}); ierr != nil {
		return ierr
	}

	// Resume from last checkpoint if a prior run was truncated.
	var lastUserID string
	var progress struct {
		LastUserID string `bson:"last_user_id"`
	}
	perr := markers.FindOne(ctx, bson.M{"_id": oauthVerifiedProgressID}).Decode(&progress)
	if perr == nil {
		lastUserID = progress.LastUserID
	} else if !stderrors.Is(perr, mongo.ErrNoDocuments) {
		return perr
	}

	limit := int64(backfillBatchSize)
	if limit <= 0 {
		limit = DefaultBackfillBatchSize
	}

	updated := int64(0)
	for {
		filter := bson.M{"email_verified": true}
		if lastUserID != "" {
			filter["_id"] = bson.M{"$gt": lastUserID}
		}

		findOpts := options.Find().
			SetSort(bson.D{{Key: "_id", Value: 1}}).
			SetLimit(limit).
			SetProjection(bson.M{"_id": 1})

		cursor, ferr := users.Find(ctx, filter, findOpts)
		if ferr != nil {
			return ferr
		}

		var ownerIDs []string
		for cursor.Next(ctx) {
			var owner struct {
				ID string `bson:"_id"`
			}
			if derr := cursor.Decode(&owner); derr != nil {
				_ = cursor.Close(ctx)
				return derr
			}
			ownerIDs = append(ownerIDs, owner.ID)
		}
		if cerr := cursor.Err(); cerr != nil {
			_ = cursor.Close(ctx)
			return cerr
		}
		_ = cursor.Close(ctx)

		if len(ownerIDs) == 0 {
			break
		}

		res, uerr := links.UpdateMany(ctx,
			bson.M{"user_id": bson.M{"$in": ownerIDs}, "verified": bson.M{"$ne": true}},
			bson.M{"$set": bson.M{"verified": true}},
		)
		if uerr != nil {
			return uerr
		}
		updated += res.ModifiedCount

		lastUserID = ownerIDs[len(ownerIDs)-1]

		if _, perr := markers.UpdateOne(ctx,
			bson.M{"_id": oauthVerifiedProgressID},
			bson.M{"$set": bson.M{"last_user_id": lastUserID, "updated_at": time.Now().UTC()}},
			options.UpdateOne().SetUpsert(true),
		); perr != nil {
			return perr
		}
	}

	if _, merr := markers.UpdateOne(ctx,
		bson.M{"_id": oauthVerifiedBackfillID},
		bson.M{"$setOnInsert": bson.M{"applied_at": time.Now().UTC()}},
		options.UpdateOne().SetUpsert(true),
	); merr != nil {
		return merr
	}

	_, _ = markers.DeleteOne(ctx, bson.M{"_id": oauthVerifiedProgressID})

	slog.InfoContext(ctx, "oauth_verified_backfill_applied",
		"migration", oauthVerifiedBackfillID,
		"links_updated", updated,
	)
	return nil
}

// claimedEmailsBackfillID is the schema_migrations marker of the data migration
// that mirrors SQL migration 000014 for MongoDB.
const claimedEmailsBackfillID = "000014_create_claimed_emails"

// BackfillClaimedEmails populates the claimed_emails collection from users.email
// and oauth_accounts.email. It is an explicit operator/embedder utility, not a
// startup step: nothing calls it from Connect, because booting must never scan the
// account tables. An embedder upgrading a database that already has users or links
// must call it once. The key is db.NormalizeEmail, computed here so it is
// byte-identical to every Go write path; empty and whitespace-only addresses are
// skipped.
//
// It aborts, naming the address and both accounts, when the existing rows already
// disagree about who owns one: electing a winner strips the losing account's
// attribution while leaving its rows pointing at an address it does not claim.
// The insert is an idempotent $setOnInsert, so a run that aborted on the operator's
// data converges when re-run after the offending links are removed.
//
// Runs are safe to repeat: the completion marker below is recorded for operators,
// but it does not gate, so a re-run also picks up rows added after the last run.
func BackfillClaimedEmails(ctx context.Context, database *mongo.Database) error {
	if database == nil {
		return nil
	}
	markers := database.Collection("schema_migrations")

	claims := database.Collection("claimed_emails")
	sources := []struct {
		collection string
		ownerField string
	}{
		{collection: "users", ownerField: "_id"},
		{collection: "oauth_accounts", ownerField: "user_id"},
	}
	holders := int64(0)
	for _, src := range sources {
		cursor, cerr := database.Collection(src.collection).Find(ctx,
			bson.M{"email": bson.M{"$ne": ""}},
			options.Find().SetProjection(bson.M{"email": 1, src.ownerField: 1}),
		)
		if cerr != nil {
			return cerr
		}
		for cursor.Next(ctx) {
			var row struct {
				Email   string `bson:"email"`
				OwnerID string `bson:"user_id"`
				ID      string `bson:"_id"`
			}
			if derr := cursor.Decode(&row); derr != nil {
				_ = cursor.Close(ctx)
				return derr
			}
			key := db.NormalizeEmail(row.Email)
			if key == "" {
				continue
			}
			ownerID := row.OwnerID
			if src.ownerField == "_id" {
				ownerID = row.ID
			}
			// Idempotent: a re-run after an aborted pass converges on the rows the
			// first pass already wrote.
			_, ierr := claims.UpdateOne(ctx,
				bson.M{"_id": key},
				bson.M{"$setOnInsert": bson.M{
					"owner_user_id": ownerID,
					"verified":      false,
					"created_at":    time.Now().UTC(),
					"updated_at":    time.Now().UTC(),
				}},
				options.UpdateOne().SetUpsert(true),
			)
			if ierr != nil && !mongo.IsDuplicateKeyError(ierr) {
				_ = cursor.Close(ctx)
				return ierr
			}
			var existing ClaimedEmailDoc
			if derr := claims.FindOne(ctx, bson.M{"_id": key}).Decode(&existing); derr != nil {
				_ = cursor.Close(ctx)
				return derr
			}
			if existing.OwnerUserID != ownerID {
				_ = cursor.Close(ctx)
				return fmt.Errorf("claimed_emails backfill aborted: %q is held by accounts %s and %s", key, existing.OwnerUserID, ownerID)
			}
			holders++
		}
		if cerr := cursor.Err(); cerr != nil {
			_ = cursor.Close(ctx)
			return cerr
		}
		_ = cursor.Close(ctx)
	}

	// Promote exactly the keys a trusted holder already proved: a verified user
	// row, or a link the provider attested. Anything else keeps an unverified
	// claim, which is the state a provider-attested address may take over.
	promotions := []struct {
		collection string
		ownerField string
		filter     bson.M
	}{
		{collection: "users", ownerField: "_id", filter: bson.M{"email_verified": true}},
		{collection: "oauth_accounts", ownerField: "user_id", filter: bson.M{"verified": true}},
	}
	promoted := 0
	for _, p := range promotions {
		proofs, perr := database.Collection(p.collection).Find(ctx, p.filter,
			options.Find().SetProjection(bson.M{"email": 1, p.ownerField: 1}),
		)
		if perr != nil {
			return perr
		}
		for proofs.Next(ctx) {
			var row struct {
				Email   string `bson:"email"`
				OwnerID string `bson:"user_id"`
				ID      string `bson:"_id"`
			}
			if derr := proofs.Decode(&row); derr != nil {
				_ = proofs.Close(ctx)
				return derr
			}
			key := db.NormalizeEmail(row.Email)
			if key == "" {
				continue
			}
			ownerID := row.OwnerID
			if p.ownerField == "_id" {
				ownerID = row.ID
			}
			res, uerr := claims.UpdateOne(ctx,
				bson.M{"_id": key, "owner_user_id": ownerID},
				bson.M{"$set": bson.M{"verified": true, "updated_at": time.Now().UTC()}},
			)
			if uerr != nil {
				_ = proofs.Close(ctx)
				return uerr
			}
			promoted += int(res.ModifiedCount)
		}
		if perr := proofs.Err(); perr != nil {
			_ = proofs.Close(ctx)
			return perr
		}
		_ = proofs.Close(ctx)
	}

	if _, merr := markers.UpdateOne(ctx,
		bson.M{"_id": claimedEmailsBackfillID},
		bson.M{"$setOnInsert": bson.M{"applied_at": time.Now().UTC()}},
		options.UpdateOne().SetUpsert(true),
	); merr != nil {
		return merr
	}
	slog.InfoContext(ctx, "claimed_emails_backfill_applied",
		"migration", claimedEmailsBackfillID,
		"claims_held", holders,
		"claims_promoted", promoted,
	)
	return nil
}

// microsoftOIDBackfillID is the schema_migrations marker of the data migration
// that mirrors SQL migration 000010 for MongoDB.
const microsoftOIDBackfillID = "000010_resolve_microsoft_oid_links"

// oauthTenantScopeCheckID is the schema_migrations marker of the one-shot
// oauth_accounts tenant-scope sweep that mirrors SQL migration 000011.
const oauthTenantScopeCheckID = "000011_oauth_account_tenant_scope"

// VerifyOAuthAccountTenantScope refuses startup on a tenant-less
// oauth_accounts document once per database, not once per process. The
// predicate cannot be served by an index, so repeating it on every boot is a
// full collection scan inside the connect budget when nothing is wrong. It runs
// before index provisioning, so the first deploy is still refused rather than
// indexed. Trade-off: a tenant-less document written after the sweep completed
// is not caught here; writers take the field from the verified token, and the
// unique key still rejects a colliding identity.
func VerifyOAuthAccountTenantScope(ctx context.Context, database *mongo.Database) error {
	if database == nil {
		return nil
	}
	markers := database.Collection("schema_migrations")
	var marker bson.M
	err := markers.FindOne(ctx, bson.M{"_id": oauthTenantScopeCheckID}).Decode(&marker)
	if err == nil {
		return nil
	}
	if !stderrors.Is(err, mongo.ErrNoDocuments) {
		return err
	}

	if err := verifyOAuthAccountTenantScope(ctx, database); err != nil {
		return err
	}

	_, err = markers.UpdateOne(ctx,
		bson.M{"_id": oauthTenantScopeCheckID},
		bson.M{"$setOnInsert": bson.M{"applied_at": time.Now().UTC()}},
		options.UpdateOne().SetUpsert(true),
	)
	return err
}

// BackfillMicrosoftOIDLinks deduplicates pre-switch Microsoft links where both
// an oid-keyed row and a sub-keyed row exist for the same user, mirroring SQL
// migration 000010.
func BackfillMicrosoftOIDLinks(ctx context.Context, database *mongo.Database) error {
	if database == nil {
		return nil
	}
	markers := database.Collection("schema_migrations")
	var marker bson.M
	err := markers.FindOne(ctx, bson.M{"_id": microsoftOIDBackfillID}).Decode(&marker)
	if err == nil {
		return nil
	}
	if !stderrors.Is(err, mongo.ErrNoDocuments) {
		return err
	}

	links := database.Collection("oauth_accounts")
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{
			"provider_id": "microsoft",
			"email":       bson.M{"$ne": ""},
		}}},
		{{Key: "$sort", Value: bson.D{
			{Key: "verified", Value: -1},
			{Key: "created_at", Value: -1},
			{Key: "_id", Value: -1},
		}}},
		{{Key: "$group", Value: bson.M{
			"_id":   bson.M{"user_id": "$user_id", "email": "$email"},
			"count": bson.M{"$sum": 1},
			"docs":  bson.M{"$push": "$_id"},
		}}},
		{{Key: "$match", Value: bson.M{"count": bson.M{"$gt": 1}}}},
	}
	cursor, err := links.Aggregate(ctx, pipeline)
	if err != nil {
		return err
	}
	defer func() { _ = cursor.Close(ctx) }()

	var toDelete []string
	deleted := int64(0)
	for cursor.Next(ctx) {
		var res struct {
			ID struct {
				UserID string `bson:"user_id"`
				Email  string `bson:"email"`
			} `bson:"_id"`
			Docs []string `bson:"docs"`
		}
		if derr := cursor.Decode(&res); derr != nil {
			return derr
		}
		if len(res.Docs) > 1 {
			for _, docID := range res.Docs[1:] {
				slog.InfoContext(ctx, "microsoft_duplicate_link_deleted",
					"_id", docID,
					"user_id", res.ID.UserID,
					"email", res.ID.Email,
				)
				toDelete = append(toDelete, docID)
			}
		}
		if len(toDelete) >= 1000 {
			dres, derr := links.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": toDelete}})
			if derr != nil {
				return derr
			}
			deleted += dres.DeletedCount
			toDelete = toDelete[:0]
		}
	}
	if cerr := cursor.Err(); cerr != nil {
		return cerr
	}

	if len(toDelete) > 0 {
		dres, derr := links.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": toDelete}})
		if derr != nil {
			return derr
		}
		deleted += dres.DeletedCount
	}

	if _, merr := markers.UpdateOne(ctx,
		bson.M{"_id": microsoftOIDBackfillID},
		bson.M{"$setOnInsert": bson.M{"applied_at": time.Now().UTC()}},
		options.UpdateOne().SetUpsert(true),
	); merr != nil {
		return merr
	}
	slog.InfoContext(ctx, "microsoft_oid_backfill_applied",
		"migration", microsoftOIDBackfillID,
		"links_deleted", deleted,
	)
	return nil
}
