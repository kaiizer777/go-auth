package mongostore

import (
	"context"
	stderrors "errors"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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

// microsoftOIDBackfillID is the schema_migrations marker of the data migration
// that mirrors SQL migration 000010 for MongoDB.
const microsoftOIDBackfillID = "000010_resolve_microsoft_oid_links"

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
