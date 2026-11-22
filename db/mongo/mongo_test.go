package mongostore

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
)

func TestDocumentSerialization_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	t.Run("UserDoc", func(t *testing.T) {
		uid := uuid.New()
		user := &db.User{
			ID:                uid,
			Email:             "test@example.com",
			PasswordHash:      "hashed_secret",
			CredentialVersion: 3,
			EmailVerified:     true,
			CreatedAt:         now,
			UpdatedAt:         now,
		}

		doc := userDocFromDomain(user)
		if doc.ID != uid.String() {
			t.Fatalf("expected ID %s, got %s", uid.String(), doc.ID)
		}
		if doc.Email != user.Email || doc.CredentialVersion != 3 || !doc.EmailVerified {
			t.Fatalf("field mismatch in user doc: %+v", doc)
		}

		data, err := bson.Marshal(doc)
		if err != nil {
			t.Fatalf("bson.Marshal failed: %v", err)
		}

		var unmarshaled UserDoc
		if err := bson.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("bson.Unmarshal failed: %v", err)
		}

		roundTripped := unmarshaled.toDomain()
		if roundTripped.ID != user.ID || roundTripped.Email != user.Email ||
			roundTripped.PasswordHash != user.PasswordHash ||
			roundTripped.CredentialVersion != user.CredentialVersion ||
			roundTripped.EmailVerified != user.EmailVerified ||
			!roundTripped.CreatedAt.Equal(user.CreatedAt) ||
			!roundTripped.UpdatedAt.Equal(user.UpdatedAt) {
			t.Fatalf("roundtrip mismatch: got %+v, want %+v", roundTripped, user)
		}
	})

	t.Run("SessionDoc", func(t *testing.T) {
		sessID := uuid.New()
		userID := uuid.New()
		sess := &db.Session{
			ID:                sessID,
			UserID:            userID,
			IDHash:            "hash12345",
			SessionType:       db.SessionTypeBearer,
			IPAddress:         "192.168.1.1",
			UserAgent:         "GoAuth-Agent/1.0",
			CredentialVersion: 2,
			LastActiveAt:      now,
			AbsoluteExpiresAt: now.Add(24 * time.Hour),
			CreatedAt:         now,
		}

		doc := sessionDocFromDomain(sess)
		if doc.ID != sessID.String() || doc.UserID != userID.String() {
			t.Fatalf("doc ID mismatch: %+v", doc)
		}

		data, err := bson.Marshal(doc)
		if err != nil {
			t.Fatalf("bson.Marshal failed: %v", err)
		}

		var unmarshaled SessionDoc
		if err := bson.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("bson.Unmarshal failed: %v", err)
		}

		roundTripped := unmarshaled.toDomain()
		if roundTripped.ID != sess.ID || roundTripped.UserID != sess.UserID ||
			roundTripped.IDHash != sess.IDHash ||
			roundTripped.SessionType != sess.SessionType ||
			roundTripped.IPAddress != sess.IPAddress ||
			roundTripped.UserAgent != sess.UserAgent ||
			roundTripped.CredentialVersion != sess.CredentialVersion ||
			!roundTripped.LastActiveAt.Equal(sess.LastActiveAt) ||
			!roundTripped.AbsoluteExpiresAt.Equal(sess.AbsoluteExpiresAt) {
			t.Fatalf("roundtrip mismatch: got %+v, want %+v", roundTripped, sess)
		}
	})

	t.Run("VerificationTokenDoc", func(t *testing.T) {
		userID := uuid.New()
		tokenHash := []byte("verification_hash_32bytes_value!")
		tok := &db.VerificationToken{
			TokenHash: tokenHash,
			UserID:    userID,
			ExpiresAt: now.Add(30 * time.Minute),
			CreatedAt: now,
		}

		doc := verificationTokenDocFromDomain(tok)
		if string(doc.TokenHash) != string(tokenHash) || doc.UserID != userID.String() {
			t.Fatalf("doc token mismatch: %+v", doc)
		}

		data, err := bson.Marshal(doc)
		if err != nil {
			t.Fatalf("bson.Marshal failed: %v", err)
		}

		var unmarshaled VerificationTokenDoc
		if err := bson.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("bson.Unmarshal failed: %v", err)
		}

		roundTripped := unmarshaled.toDomain()
		if string(roundTripped.TokenHash) != string(tok.TokenHash) ||
			roundTripped.UserID != tok.UserID ||
			!roundTripped.ExpiresAt.Equal(tok.ExpiresAt) {
			t.Fatalf("roundtrip mismatch: got %+v, want %+v", roundTripped, tok)
		}
	})

	t.Run("PasswordResetTokenDoc", func(t *testing.T) {
		userID := uuid.New()
		tokenHash := []byte("reset_token_hash_32bytes_val!!")
		tok := &db.PasswordResetToken{
			TokenHash: tokenHash,
			UserID:    userID,
			ExpiresAt: now.Add(30 * time.Minute),
			CreatedAt: now,
		}

		doc := passwordResetTokenDocFromDomain(tok)
		data, err := bson.Marshal(doc)
		if err != nil {
			t.Fatalf("bson.Marshal failed: %v", err)
		}

		var unmarshaled PasswordResetTokenDoc
		if err := bson.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("bson.Unmarshal failed: %v", err)
		}

		roundTripped := unmarshaled.toDomain()
		if string(roundTripped.TokenHash) != string(tok.TokenHash) ||
			roundTripped.UserID != tok.UserID ||
			!roundTripped.ExpiresAt.Equal(tok.ExpiresAt) {
			t.Fatalf("roundtrip mismatch: got %+v, want %+v", roundTripped, tok)
		}
	})

	t.Run("OAuthAccountDoc", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		acc := &db.OAuthAccount{
			ID:             id,
			UserID:         userID,
			ProviderID:     "google",
			ProviderUserID: "google-uid-123",
			Email:          "user@example.com",
			CreatedAt:      now,
			UpdatedAt:      now,
		}

		doc := oauthAccountDocFromDomain(acc)
		data, err := bson.Marshal(doc)
		if err != nil {
			t.Fatalf("bson.Marshal failed: %v", err)
		}

		var unmarshaled OAuthAccountDoc
		if err := bson.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("bson.Unmarshal failed: %v", err)
		}

		roundTripped := unmarshaled.toDomain()
		if roundTripped.ID != acc.ID || roundTripped.UserID != acc.UserID ||
			roundTripped.ProviderID != acc.ProviderID ||
			roundTripped.ProviderUserID != acc.ProviderUserID ||
			roundTripped.Email != acc.Email {
			t.Fatalf("roundtrip mismatch: got %+v, want %+v", roundTripped, acc)
		}
	})

	t.Run("TotpSecretDoc", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		secret := &db.TotpSecret{
			ID:              id,
			UserID:          userID,
			EncryptedSecret: []byte("encrypted_secret_data"),
			BackupCodes:     []byte(`["code1","code2"]`),
			Enabled:         true,
			CreatedAt:       now,
			UpdatedAt:       now,
		}

		doc := totpSecretDocFromDomain(secret)
		data, err := bson.Marshal(doc)
		if err != nil {
			t.Fatalf("bson.Marshal failed: %v", err)
		}

		var unmarshaled TotpSecretDoc
		if err := bson.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("bson.Unmarshal failed: %v", err)
		}

		roundTripped := unmarshaled.toDomain()
		if roundTripped.ID != secret.ID || roundTripped.UserID != secret.UserID ||
			string(roundTripped.EncryptedSecret) != string(secret.EncryptedSecret) ||
			string(roundTripped.BackupCodes) != string(secret.BackupCodes) ||
			roundTripped.Enabled != secret.Enabled {
			t.Fatalf("roundtrip mismatch: got %+v, want %+v", roundTripped, secret)
		}
	})

	t.Run("TotpUsedCodeDoc", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		used := &db.TotpUsedCode{
			ID:       id,
			UserID:   userID,
			CodeHash: []byte("used_code_hash_123456"),
			UsedAt:   now,
		}

		doc := totpUsedCodeDocFromDomain(used)
		data, err := bson.Marshal(doc)
		if err != nil {
			t.Fatalf("bson.Marshal failed: %v", err)
		}

		var unmarshaled TotpUsedCodeDoc
		if err := bson.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("bson.Unmarshal failed: %v", err)
		}

		roundTripped := unmarshaled.toDomain()
		if roundTripped.ID != used.ID || roundTripped.UserID != used.UserID ||
			string(roundTripped.CodeHash) != string(used.CodeHash) ||
			!roundTripped.UsedAt.Equal(used.UsedAt) {
			t.Fatalf("roundtrip mismatch: got %+v, want %+v", roundTripped, used)
		}
	})

	t.Run("TwoFactorTokenDoc", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		tok := &db.TwoFactorToken{
			ID:        id,
			UserID:    userID,
			TokenHash: []byte("2fa_token_hash_val"),
			ExpiresAt: now.Add(5 * time.Minute),
			Attempts:  2,
		}

		doc := twoFactorTokenDocFromDomain(tok)
		data, err := bson.Marshal(doc)
		if err != nil {
			t.Fatalf("bson.Marshal failed: %v", err)
		}

		var unmarshaled TwoFactorTokenDoc
		if err := bson.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("bson.Unmarshal failed: %v", err)
		}

		roundTripped := unmarshaled.toDomain()
		if roundTripped.ID != tok.ID || roundTripped.UserID != tok.UserID ||
			string(roundTripped.TokenHash) != string(tok.TokenHash) ||
			!roundTripped.ExpiresAt.Equal(tok.ExpiresAt) ||
			roundTripped.Attempts != tok.Attempts {
			t.Fatalf("roundtrip mismatch: got %+v, want %+v", roundTripped, tok)
		}
	})
}

func TestIndexSpecifications_Completeness(t *testing.T) {
	specs := IndexSpecifications()

	expectedCollections := []string{
		"users",
		"sessions",
		"verification_tokens",
		"password_reset_tokens",
		"oauth_accounts",
		"totp_secrets",
		"totp_used_codes",
		"two_factor_tokens",
	}

	for _, col := range expectedCollections {
		models, ok := specs[col]
		if !ok || len(models) == 0 {
			t.Fatalf("missing index specifications for collection: %s", col)
		}
	}

	// Verify specific index names
	indexNames := make(map[string]map[string]bool)
	var emailCollation *options.Collation
	for col, models := range specs {
		indexNames[col] = make(map[string]bool)
		for _, m := range models {
			if m.Options != nil {
				opts := &options.IndexOptions{}
				for _, fn := range m.Options.List() {
					_ = fn(opts)
				}
				if opts.Name != nil {
					indexNames[col][*opts.Name] = true
					if *opts.Name == "uq_users_email" {
						emailCollation = opts.Collation
					}
				}
			}
		}
	}

	if emailCollation == nil || emailCollation.Locale != "en" || emailCollation.Strength != 2 {
		t.Fatalf("expected uq_users_email to configure case-insensitive collation (Locale: 'en', Strength: 2), got: %+v", emailCollation)
	}

	// Check essential index names
	checks := []struct {
		col  string
		name string
	}{
		{"users", "uq_users_email"},
		{"sessions", "uq_sessions_id_hash"},
		{"sessions", "idx_sessions_user_id"},
		{"sessions", "ttl_sessions_expiry"},
		{"verification_tokens", "idx_verification_tokens_user_id"},
		{"verification_tokens", "ttl_verification_tokens_expiry"},
		{"password_reset_tokens", "idx_password_reset_tokens_user_id"},
		{"password_reset_tokens", "ttl_password_reset_tokens_expiry"},
		{"oauth_accounts", "uq_oauth_accounts_provider_uid"},
		{"oauth_accounts", "idx_oauth_accounts_user_id"},
		{"totp_secrets", "uq_totp_secrets_user_id"},
		{"totp_used_codes", "uq_totp_used_codes_user_code"},
		{"totp_used_codes", "idx_totp_used_codes_user_used_at"},
		{"totp_used_codes", "ttl_totp_used_codes_expiry"},
		{"two_factor_tokens", "uq_two_factor_tokens_token_hash"},
		{"two_factor_tokens", "idx_two_factor_tokens_user_id"},
		{"two_factor_tokens", "ttl_two_factor_tokens_expiry"},
	}

	for _, c := range checks {
		if !indexNames[c.col][c.name] {
			t.Errorf("expected index %q on collection %q, not found", c.name, c.col)
		}
	}
}

func TestEnsureIndexes_NilDB(t *testing.T) {
	err := EnsureIndexes(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected nil on nil db, got: %v", err)
	}
}

func TestNormalizeMongoError(t *testing.T) {
	if err := NormalizeMongoError(nil); err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}

	genericErr := fmt.Errorf("connection refused")
	if err := NormalizeMongoError(genericErr); err != genericErr {
		t.Fatalf("expected generic error to pass through, got: %v", err)
	}

	// Construct mock mongo.ServerError for code 11000
	makeDupErr := func(msg string) error {
		return mongo.CommandError{
			Code:    11000,
			Message: msg,
		}
	}

	unmappedErr := &mongo.CommandError{
		Code:    11000,
		Message: "E11000 duplicate key error collection: test.misc index: some_other_index dup key: { foo: \"bar\" }",
	}

	unmappedEmailErr := &mongo.CommandError{
		Code:    11000,
		Message: "E11000 duplicate key error collection: test.newsletter index: newsletter_subscribers dup key: { email: \"user@example.com\" }",
	}

	tests := []struct {
		name    string
		err     error
		wantErr error
	}{
		{
			name:    "email duplicate by index name",
			err:     makeDupErr("E11000 duplicate key error collection: test.users index: uq_users_email dup key: { email: \"user@example.com\" }"),
			wantErr: errors.ErrEmailAlreadyExists,
		},
		{
			name:    "email duplicate by field name",
			err:     makeDupErr("E11000 duplicate key error collection: test.users index: email_1 dup key: { email: \"user@example.com\" }"),
			wantErr: errors.ErrEmailAlreadyExists,
		},
		{
			name:    "totp used code duplicate",
			err:     makeDupErr("E11000 duplicate key error collection: test.totp_used_codes index: uq_totp_used_codes_user_code dup key: { user_id: \"uid\", code_hash: BinData(0, ...) }"),
			wantErr: errors.ErrTOTPCodeReplayed,
		},
		{
			name:    "totp secrets duplicate user",
			err:     makeDupErr("E11000 duplicate key error collection: test.totp_secrets index: uq_totp_secrets_user_id dup key: { user_id: \"uid\" }"),
			wantErr: errors.ErrTOTPAlreadyEnabled,
		},
		{
			name:    "oauth account duplicate provider uid",
			err:     makeDupErr("E11000 duplicate key error collection: test.oauth_accounts index: uq_oauth_accounts_provider_uid dup key: { provider_id: \"google\", provider_user_id: \"123\" }"),
			wantErr: errors.ErrOAuthAccountAlreadyLinked,
		},
		{
			name:    "oauth account duplicate with email in dup key maps to oauth account error",
			err:     makeDupErr("E11000 duplicate key error collection: test.oauth_accounts index: uq_oauth_accounts_provider_uid dup key: { provider_id: \"google\", email: \"user@example.com\" }"),
			wantErr: errors.ErrOAuthAccountAlreadyLinked,
		},
		{
			name:    "unmapped duplicate key error with email substring returns original error",
			err:     unmappedEmailErr,
			wantErr: unmappedEmailErr,
		},
		{
			name:    "unmapped duplicate key error returns original error",
			err:     unmappedErr,
			wantErr: unmappedErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeMongoError(tt.err)
			if !errors.Is(got, tt.wantErr) {
				t.Fatalf("NormalizeMongoError(%v) = %v, want %v", tt.err, got, tt.wantErr)
			}
		})
	}
}

func TestStandaloneTransactionDetection(t *testing.T) {
	standaloneErrors := []error{
		fmt.Errorf("Command startTransaction failed: Transaction numbers are only allowed on a replica set member or mongos"),
		fmt.Errorf("error code 20: transaction numbers are only allowed on a replica set member"),
		fmt.Errorf("standalone instance does not support transactions"),
		mongo.CommandError{Code: 115, Name: "CommandNotSupportedOnStandalone", Message: "command not supported on standalone"},
		&mongo.CommandError{Code: 115, Name: "CommandNotSupportedOnStandalone"},
		mongo.CommandError{Code: 20, Message: "illegal operation"},
	}

	for _, err := range standaloneErrors {
		if !isStandaloneTransactionError(err) {
			t.Errorf("expected isStandaloneTransactionError(%v) = true, got false", err)
		}
	}

	nonStandaloneErrors := []error{
		fmt.Errorf("context deadline exceeded"),
		fmt.Errorf("connection reset by peer"),
		fmt.Errorf("write error on database standalone_test.users: duplicate key"),
		fmt.Errorf("database name contains standalone but this is a normal query error"),
		nil,
	}

	for _, err := range nonStandaloneErrors {
		if isStandaloneTransactionError(err) {
			t.Errorf("expected isStandaloneTransactionError(%v) = false, got true", err)
		}
	}
}

func TestEnsureIndexes_ModelsAndNilDatabase(t *testing.T) {
	if err := EnsureIndexes(context.Background(), nil); err != nil {
		t.Fatalf("expected nil error on nil database, got: %v", err)
	}

	specs := IndexSpecifications()
	expectedCollections := []string{
		"users",
		"sessions",
		"verification_tokens",
		"password_reset_tokens",
		"oauth_accounts",
		"totp_secrets",
		"totp_used_codes",
		"two_factor_tokens",
	}

	for _, col := range expectedCollections {
		models, ok := specs[col]
		if !ok || len(models) == 0 {
			t.Errorf("expected non-empty index models for collection %s", col)
		}
	}
}

func TestMongoConnect_InvalidURI(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DatabaseType = config.DatabaseTypeMongo
	cfg.DatabaseURL = "invalid://mongodb:not_a_valid_uri"
	cfg.MongoDB.Database = "testdb"
	cfg.MongoDB.ConnectTimeout = 100 * time.Millisecond

	store, err := Connect(cfg)
	if err == nil {
		_ = store.Close()
		t.Fatal("expected error on invalid mongo uri, got nil")
	}
}

func TestMongoStore_NilClientOperations(t *testing.T) {
	store := New(nil, nil, false)

	if err := store.Ping(context.Background()); !errors.Is(err, errors.ErrDatabaseUnsupported) {
		t.Errorf("Ping() on nil client: expected ErrDatabaseUnsupported, got %v", err)
	}

	if err := store.Close(); err != nil {
		t.Errorf("Close() on nil client: expected nil, got %v", err)
	}

	err := store.Transaction(context.Background(), func(txStore db.Store) error {
		return nil
	})
	if !errors.Is(err, errors.ErrTransactionUnsupported) {
		t.Errorf("Transaction() on nil client: expected ErrTransactionUnsupported, got %v", err)
	}

	if store.Users() == nil || store.Sessions() == nil || store.VerificationTokens() == nil ||
		store.PasswordResetTokens() == nil || store.OAuthAccounts() == nil || store.Totp() == nil {
		t.Errorf("expected non-nil sub-stores on MongoStore")
	}
}

func TestMongoStore_ResolveCtx_DynamicBinding(t *testing.T) {
	store := New(nil, nil, false)
	ctx := context.Background()

	// Base store without session returns caller's context unchanged
	if store.resolveCtx(ctx) != ctx {
		t.Errorf("expected resolveCtx to return caller context when session is nil")
	}

	// Tx store created with nil session returns caller's context unchanged
	txStore := store.withSession(nil)
	if txStore.resolveCtx(ctx) != ctx {
		t.Errorf("expected resolveCtx to return caller context when session is nil")
	}
}

func TestUserStore_Delete_Cascade(t *testing.T) {
	uri := os.Getenv("TEST_MONGO_URI")
	if uri == "" {
		t.Skip("TEST_MONGO_URI unset; skipping live MongoDB cascade test")
	}
	cfg := config.DefaultConfig()
	cfg.DatabaseType = config.DatabaseTypeMongo
	cfg.DatabaseURL = uri
	cfg.MongoDB.Database = fmt.Sprintf("goauth_test_cascade_%s", strings.ReplaceAll(uuid.New().String(), "-", ""))
	cfg.MongoDB.AllowNonTransactionalMongo = true

	store, err := Connect(cfg)
	if err != nil {
		t.Fatalf("failed to connect to mongodb: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Database().Drop(context.Background())
		_ = store.Close()
	})

	ctx := context.Background()
	uid := uuid.New()
	user := &db.User{
		ID:            uid,
		Email:         "cascade@example.com",
		PasswordHash:  "dummy_hash",
		EmailVerified: true,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	if err := store.Users().Create(ctx, user); err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	// Seed child documents across collections
	sess := &db.Session{
		ID:                uuid.New(),
		UserID:            uid,
		IDHash:            "id_hash_1",
		SessionType:       db.SessionTypeBearer,
		LastActiveAt:      time.Now().UTC(),
		AbsoluteExpiresAt: time.Now().Add(time.Hour).UTC(),
		CreatedAt:         time.Now().UTC(),
	}
	if err := store.Sessions().Create(ctx, sess); err != nil {
		t.Fatalf("Create session failed: %v", err)
	}

	tok := &db.VerificationToken{
		TokenHash: []byte("vtok_hash_1"),
		UserID:    uid,
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
		CreatedAt: time.Now().UTC(),
	}
	if err := store.VerificationTokens().Create(ctx, tok); err != nil {
		t.Fatalf("Create verification token failed: %v", err)
	}

	// Delete user
	if err := store.Users().Delete(ctx, uid); err != nil {
		t.Fatalf("Delete user failed: %v", err)
	}

	// Verify child collections are purged
	sessions, err := store.Sessions().ListByUserID(ctx, uid)
	if err != nil {
		t.Fatalf("ListByUserID failed: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions after cascade delete, got %d", len(sessions))
	}

	_, err = store.VerificationTokens().GetByTokenHash(ctx, []byte("vtok_hash_1"))
	if !errors.Is(err, gorm.ErrRecordNotFound) && err == nil {
		t.Fatal("expected verification token to be deleted by cascade, but found it")
	}
}

func TestMongoStore_CanceledContext_AllMethods(t *testing.T) {
	opts := options.Client().
		ApplyURI("mongodb://127.0.0.1:27017").
		SetServerSelectionTimeout(1 * time.Millisecond).
		SetConnectTimeout(1 * time.Millisecond).
		SetTimeout(1 * time.Millisecond)
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("mongo.Connect failed: %v", err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	dbInst := client.Database("test_db")
	store := New(client, dbInst, true)

	if store.Client() != client || store.Database() != dbInst {
		t.Fatal("Client() or Database() mismatch")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assertCanceled := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s expected error on canceled context, got nil", name)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%s expected context.Canceled, got: %v", name, err)
		}
	}

	uid := uuid.New()
	user := &db.User{
		ID:        uid,
		Email:     "test@example.com",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	assertCanceled("Users.Create", store.Users().Create(ctx, user))
	_, err = store.Users().GetByID(ctx, uid)
	assertCanceled("Users.GetByID", err)
	_, err = store.Users().GetByIDForUpdate(ctx, uid)
	assertCanceled("Users.GetByIDForUpdate", err)
	_, err = store.Users().GetByEmail(ctx, "test@example.com")
	assertCanceled("Users.GetByEmail", err)
	assertCanceled("Users.Update", store.Users().Update(ctx, user))
	assertCanceled("Users.UpdatePassword", store.Users().UpdatePassword(ctx, uid, "newpass"))
	_, err = store.Users().IncrementCredentialVersion(ctx, uid)
	assertCanceled("Users.IncrementCredentialVersion", err)
	assertCanceled("Users.SetEmailVerified", store.Users().SetEmailVerified(ctx, uid, true))
	assertCanceled("Users.Delete", store.Users().Delete(ctx, uid))

	sess := &db.Session{
		ID:                uuid.New(),
		UserID:            uid,
		IDHash:            "idhash",
		SessionType:       db.SessionTypeCookie,
		CreatedAt:         time.Now().UTC(),
		LastActiveAt:      time.Now().UTC(),
		AbsoluteExpiresAt: time.Now().Add(time.Hour),
	}
	assertCanceled("Sessions.Create", store.Sessions().Create(ctx, sess))
	_, err = store.Sessions().GetByID(ctx, sess.ID)
	assertCanceled("Sessions.GetByID", err)
	_, err = store.Sessions().GetByIDHash(ctx, "idhash")
	assertCanceled("Sessions.GetByIDHash", err)
	_, err = store.Sessions().ListByUserID(ctx, uid)
	assertCanceled("Sessions.ListByUserID", err)
	assertCanceled("Sessions.UpdateLastActive", store.Sessions().UpdateLastActive(ctx, sess.ID, time.Now().UTC()))
	assertCanceled("Sessions.Delete", store.Sessions().Delete(ctx, sess.ID))
	_, err = store.Sessions().DeleteByIDHash(ctx, "idhash")
	assertCanceled("Sessions.DeleteByIDHash", err)
	_, err = store.Sessions().DeleteIfStale(ctx, sess.ID, time.Now().UTC())
	assertCanceled("Sessions.DeleteIfStale", err)
	_, err = store.Sessions().DeleteIfStaleByIDHash(ctx, "idhash", time.Now().UTC())
	assertCanceled("Sessions.DeleteIfStaleByIDHash", err)
	assertCanceled("Sessions.DeleteByUserID", store.Sessions().DeleteByUserID(ctx, uid))
	_, err = store.Sessions().DeleteExpired(ctx, time.Now().UTC(), time.Now().UTC())
	assertCanceled("Sessions.DeleteExpired", err)
	assertCanceled("Sessions.DeleteExpiredByUserID", store.Sessions().DeleteExpiredByUserID(ctx, uid, time.Now().UTC(), time.Now().UTC()))

	vtok := &db.VerificationToken{
		TokenHash: []byte("vtok"),
		UserID:    uid,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	assertCanceled("VerificationTokens.Create", store.VerificationTokens().Create(ctx, vtok))
	_, err = store.VerificationTokens().GetByTokenHash(ctx, []byte("vtok"))
	assertCanceled("VerificationTokens.GetByTokenHash", err)
	_, err = store.VerificationTokens().Delete(ctx, []byte("vtok"))
	assertCanceled("VerificationTokens.Delete", err)
	assertCanceled("VerificationTokens.DeleteByUserID", store.VerificationTokens().DeleteByUserID(ctx, uid))

	rtok := &db.PasswordResetToken{
		TokenHash: []byte("rtok"),
		UserID:    uid,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	assertCanceled("PasswordResetTokens.Create", store.PasswordResetTokens().Create(ctx, rtok))
	_, err = store.PasswordResetTokens().GetByTokenHash(ctx, []byte("rtok"))
	assertCanceled("PasswordResetTokens.GetByTokenHash", err)
	_, err = store.PasswordResetTokens().Delete(ctx, []byte("rtok"))
	assertCanceled("PasswordResetTokens.Delete", err)
	assertCanceled("PasswordResetTokens.DeleteByUserID", store.PasswordResetTokens().DeleteByUserID(ctx, uid))
	_, err = store.PasswordResetTokens().ConsumeToken(ctx, []byte("rtok"), time.Now().UTC())
	assertCanceled("PasswordResetTokens.ConsumeToken", err)

	acc := &db.OAuthAccount{
		ID:             uuid.New(),
		UserID:         uid,
		ProviderID:     "gh",
		ProviderUserID: "123",
	}
	assertCanceled("OAuthAccounts.Create", store.OAuthAccounts().Create(ctx, acc))
	_, err = store.OAuthAccounts().GetByProvider(ctx, "gh", "123")
	assertCanceled("OAuthAccounts.GetByProvider", err)
	_, err = store.OAuthAccounts().GetByUserID(ctx, uid)
	assertCanceled("OAuthAccounts.GetByUserID", err)
	assertCanceled("OAuthAccounts.Delete", store.OAuthAccounts().Delete(ctx, acc.ID))
	assertCanceled("OAuthAccounts.DeleteByUserID", store.OAuthAccounts().DeleteByUserID(ctx, uid))

	sec := &db.TotpSecret{
		ID:              uuid.New(),
		UserID:          uid,
		EncryptedSecret: []byte("sec"),
	}
	assertCanceled("Totp.CreateSecret", store.Totp().CreateSecret(ctx, sec))
	_, err = store.Totp().GetSecretByUserID(ctx, uid)
	assertCanceled("Totp.GetSecretByUserID", err)
	_, err = store.Totp().GetSecretByUserIDForUpdate(ctx, uid)
	assertCanceled("Totp.GetSecretByUserIDForUpdate", err)
	assertCanceled("Totp.EnableSecret", store.Totp().EnableSecret(ctx, sec.ID, []byte("[]")))
	assertCanceled("Totp.UpdateBackupCodes", store.Totp().UpdateBackupCodes(ctx, uid, []string{"1"}))
	assertCanceled("Totp.UpdateBackupCodesJSON", store.Totp().UpdateBackupCodesJSON(ctx, sec.ID, []byte("[]")))
	_, err = store.Totp().UpdateBackupCodesCAS(ctx, uid, []string{"1"}, []string{"2"})
	assertCanceled("Totp.UpdateBackupCodesCAS", err)
	assertCanceled("Totp.DeleteSecret", store.Totp().DeleteSecret(ctx, uid))
	assertCanceled("Totp.DeleteUnconfirmedSecret", store.Totp().DeleteUnconfirmedSecret(ctx, uid))
	_, err = store.Totp().IsTotpEnabled(ctx, uid)
	assertCanceled("Totp.IsTotpEnabled", err)
	_, err = store.Totp().HasUsedCode(ctx, uid, []byte("code"), time.Now().UTC())
	assertCanceled("Totp.HasUsedCode", err)

	usedCode := &db.TotpUsedCode{
		ID:       uuid.New(),
		UserID:   uid,
		CodeHash: []byte("code"),
		UsedAt:   time.Now().UTC(),
	}
	assertCanceled("Totp.RecordUsedCode", store.Totp().RecordUsedCode(ctx, usedCode))
	assertCanceled("Totp.PruneUsedCodes", store.Totp().PruneUsedCodes(ctx, uid, time.Now().UTC()))

	tfTok := &db.TwoFactorToken{
		ID:        uuid.New(),
		UserID:    uid,
		TokenHash: []byte("tf"),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	assertCanceled("Totp.CreateTwoFactorToken", store.Totp().CreateTwoFactorToken(ctx, tfTok))
	_, err = store.Totp().GetTwoFactorToken(ctx, []byte("tf"))
	assertCanceled("Totp.GetTwoFactorToken", err)
	_, err = store.Totp().IncrementTwoFactorAttempts(ctx, []byte("tf"), 5, time.Now().UTC())
	assertCanceled("Totp.IncrementTwoFactorAttempts", err)
	_, err = store.Totp().ConsumeTwoFactorToken(ctx, []byte("tf"), 5, time.Now().UTC())
	assertCanceled("Totp.ConsumeTwoFactorToken", err)
	_, err = store.Totp().DeleteTwoFactorToken(ctx, tfTok.ID)
	assertCanceled("Totp.DeleteTwoFactorToken", err)
	assertCanceled("Totp.DeleteTwoFactorTokensByUserID", store.Totp().DeleteTwoFactorTokensByUserID(ctx, uid))

	assertCanceled("Ping", store.Ping(ctx))
	assertCanceled("Transaction", store.Transaction(ctx, func(txStore db.Store) error {
		return nil
	}))
	_ = store.Close()
}
