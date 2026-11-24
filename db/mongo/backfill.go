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

// BackfillOAuthAccountVerified re-derives oauth_accounts.verified from the
// owning user's local verification, exactly as SQL migration 000009 does: a
// legacy document has no field, decodes as false, and would otherwise be
// rejected and deleted for the verified-email owner whose only login method it
// is. Rows are only ever promoted to true, so the backfill is idempotent and
// safe to interleave with live traffic: an owner that is not verified yet keeps
// its link unverified and a later run after that owner verifies is not needed
// because the link rules re-derive trust from the owner on every callback.
//
// The marker is written after the sweep. Concurrent instances may therefore run
// the sweep together (harmless, the predicate is stable) and only one marker row
// exists afterwards; a run that fails before writing the marker retries on the
// next start.
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
	cursor, err := users.Find(ctx,
		bson.M{"email_verified": true},
		options.Find().SetProjection(bson.M{"_id": 1}),
	)
	if err != nil {
		return err
	}
	defer func() { _ = cursor.Close(ctx) }()

	updated := int64(0)
	for cursor.Next(ctx) {
		var owner struct {
			ID string `bson:"_id"`
		}
		if derr := cursor.Decode(&owner); derr != nil {
			return derr
		}
		res, uerr := links.UpdateMany(ctx,
			bson.M{"user_id": owner.ID, "verified": bson.M{"$ne": true}},
			bson.M{"$set": bson.M{"verified": true}},
		)
		if uerr != nil {
			return uerr
		}
		updated += res.ModifiedCount
	}
	if cerr := cursor.Err(); cerr != nil {
		return cerr
	}

	if _, merr := markers.UpdateOne(ctx,
		bson.M{"_id": oauthVerifiedBackfillID},
		bson.M{"$setOnInsert": bson.M{"applied_at": time.Now().UTC()}},
		options.UpdateOne().SetUpsert(true),
	); merr != nil {
		return merr
	}
	slog.InfoContext(ctx, "oauth_verified_backfill_applied",
		"migration", oauthVerifiedBackfillID,
		"links_updated", updated,
	)
	return nil
}
