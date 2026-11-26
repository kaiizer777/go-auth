package mongostore

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// IndexSpecifications defines all index models for every collection.
func IndexSpecifications() map[string][]mongo.IndexModel {
	return map[string][]mongo.IndexModel{
		"users": {
			{
				Keys: bson.D{{Key: "email", Value: 1}},
				Options: options.Index().
					SetName("uq_users_email").
					SetUnique(true).
					SetCollation(&options.Collation{
						Locale:   "en",
						Strength: 2,
					}),
			},
			{
				Keys:    bson.D{{Key: "email_verified", Value: 1}},
				Options: options.Index().SetName("idx_users_email_verified"),
			},
		},
		"sessions": {
			{
				Keys:    bson.D{{Key: "id_hash", Value: 1}},
				Options: options.Index().SetName("uq_sessions_id_hash").SetUnique(true),
			},
			{
				Keys:    bson.D{{Key: "user_id", Value: 1}},
				Options: options.Index().SetName("idx_sessions_user_id"),
			},
			{
				Keys:    bson.D{{Key: "absolute_expires_at", Value: 1}},
				Options: options.Index().SetName("ttl_sessions_expiry").SetExpireAfterSeconds(0),
			},
		},
		"verification_tokens": {
			{
				Keys:    bson.D{{Key: "user_id", Value: 1}},
				Options: options.Index().SetName("idx_verification_tokens_user_id"),
			},
			{
				Keys:    bson.D{{Key: "expires_at", Value: 1}},
				Options: options.Index().SetName("ttl_verification_tokens_expiry").SetExpireAfterSeconds(0),
			},
		},
		"password_reset_tokens": {
			{
				Keys:    bson.D{{Key: "user_id", Value: 1}},
				Options: options.Index().SetName("idx_password_reset_tokens_user_id"),
			},
			{
				Keys:    bson.D{{Key: "expires_at", Value: 1}},
				Options: options.Index().SetName("ttl_password_reset_tokens_expiry").SetExpireAfterSeconds(0),
			},
		},
		"oauth_accounts": {
			{
				Keys: bson.D{
					{Key: "provider_id", Value: 1},
					{Key: "provider_tenant_id", Value: 1},
					{Key: "provider_user_id", Value: 1},
				},
				Options: options.Index().SetName("uq_oauth_accounts_provider_tenant_uid").SetUnique(true),
			},
			{
				Keys:    bson.D{{Key: "user_id", Value: 1}},
				Options: options.Index().SetName("idx_oauth_accounts_user_id"),
			},
		},
		"totp_secrets": {
			{
				Keys:    bson.D{{Key: "user_id", Value: 1}},
				Options: options.Index().SetName("uq_totp_secrets_user_id").SetUnique(true),
			},
		},
		"totp_used_codes": {
			{
				Keys: bson.D{
					{Key: "user_id", Value: 1},
					{Key: "code_hash", Value: 1},
				},
				Options: options.Index().SetName("uq_totp_used_codes_user_code").SetUnique(true),
			},
			{
				Keys: bson.D{
					{Key: "user_id", Value: 1},
					{Key: "used_at", Value: 1},
				},
				Options: options.Index().SetName("idx_totp_used_codes_user_used_at"),
			},
			{
				Keys:    bson.D{{Key: "used_at", Value: 1}},
				Options: options.Index().SetName("ttl_totp_used_codes_expiry").SetExpireAfterSeconds(300),
			},
		},
		"two_factor_tokens": {
			{
				Keys:    bson.D{{Key: "token_hash", Value: 1}},
				Options: options.Index().SetName("uq_two_factor_tokens_token_hash").SetUnique(true),
			},
			{
				Keys:    bson.D{{Key: "user_id", Value: 1}},
				Options: options.Index().SetName("idx_two_factor_tokens_user_id"),
			},
			{
				Keys:    bson.D{{Key: "expires_at", Value: 1}},
				Options: options.Index().SetName("ttl_two_factor_tokens_expiry").SetExpireAfterSeconds(0),
			},
		},
	}
}

// legacyOAuthUniqueIndex is the pre-000011 tenant-blind identity key. CreateMany
// never drops an index, so it is removed explicitly after the tenant-qualified
// index is built: leaving it in place keeps rejecting a pairwise subject that a
// second tenant legitimately owns.
const legacyOAuthUniqueIndex = "uq_oauth_accounts_provider_uid"

// verifyOAuthAccountTenantScope refuses startup on an oauth_accounts document
// whose tenant is missing or not a string. Mongo has no NOT NULL: such a
// document is indexed as null and is invisible to a tenant-qualified lookup,
// unlike SQL where the write fails.
func verifyOAuthAccountTenantScope(ctx context.Context, database *mongo.Database) error {
	var doc struct {
		ID string `bson:"_id"`
	}
	err := database.Collection("oauth_accounts").
		FindOne(ctx, tenantScopeViolationFilter(), options.FindOne().SetProjection(bson.M{"_id": 1})).
		Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("oauth_accounts document %q has no string provider_tenant_id", doc.ID)
}

// tenantScopeViolationFilter selects documents whose tenant cannot key a
// tenant-qualified lookup. $type:"string" also matches an array that contains a
// string, so arrays are excluded explicitly: Mongo indexes ["tenant-a"] as a
// multi-key value no equality lookup with the tenant string reaches.
func tenantScopeViolationFilter() bson.M {
	return bson.M{"$or": bson.A{
		bson.M{"provider_tenant_id": bson.M{"$not": bson.M{"$type": "string"}}},
		bson.M{"provider_tenant_id": bson.M{"$type": "array"}},
	}}
}

// EnsureIndexes provisions all required collection indexes idempotently.
func EnsureIndexes(ctx context.Context, database *mongo.Database) error {
	if database == nil {
		return nil
	}
	specs := IndexSpecifications()
	for colName, models := range specs {
		col := database.Collection(colName)
		if _, err := col.Indexes().CreateMany(ctx, models); err != nil {
			return err
		}
	}
	return dropLegacyOAuthIndex(ctx, database.Collection("oauth_accounts"))
}

// dropLegacyOAuthIndex removes the tenant-blind oauth_accounts index. A missing
// index is the steady state after the first run, not a failure.
func dropLegacyOAuthIndex(ctx context.Context, col *mongo.Collection) error {
	err := col.Indexes().DropOne(ctx, legacyOAuthUniqueIndex)
	if err == nil || isMissingIndex(err) {
		return nil
	}
	return err
}

// isMissingIndex reports the server codes for a collection or index that does
// not exist, so an already-clean database stays a no-op.
func isMissingIndex(err error) bool {
	var cmdErr mongo.CommandError
	if errors.As(err, &cmdErr) {
		const (
			namespaceNotFound = 26
			indexNotFound     = 27
		)
		return cmdErr.Code == namespaceNotFound || cmdErr.Code == indexNotFound
	}
	return false
}
