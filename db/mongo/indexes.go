package mongostore

import (
	"context"

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
					{Key: "provider_user_id", Value: 1},
				},
				Options: options.Index().SetName("uq_oauth_accounts_provider_uid").SetUnique(true),
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
	return nil
}
