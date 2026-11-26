//go:build mongodb

package mongostore

import (
	"context"
	stderrors "errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
)

// requireMongoURI returns the live MongoDB DSN. The mongodb build tag opts this
// file in, so an unset URI is a misconfigured run, not a reason to skip.
func requireMongoURI(t *testing.T) string {
	t.Helper()
	uri := os.Getenv("TEST_MONGO_URI")
	if uri == "" {
		t.Fatal("TEST_MONGO_URI is unset: the mongodb build tag requires a live MongoDB DSN")
	}
	return uri
}

// TestEnsureIndexes_ReplacesTenantBlindOAuthIndex pins the index replacement:
// the pre-000011 index survives CreateMany forever unless it is dropped, and it
// keeps rejecting a pairwise subject a second tenant legitimately owns.
func TestEnsureIndexes_ReplacesTenantBlindOAuthIndex(t *testing.T) {
	uri := requireMongoURI(t)
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo.Connect failed: %v", err)
	}
	database := client.Database(fmt.Sprintf("goauth_test_ms_tenant_index_%s", strings.ReplaceAll(uuid.New().String(), "-", "")))
	t.Cleanup(func() {
		_ = database.Drop(context.Background())
		_ = client.Disconnect(context.Background())
	})
	ctx := context.Background()
	links := database.Collection("oauth_accounts")

	// Reproduce the tenant-blind schema the migration has to replace.
	if _, err := links.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "provider_id", Value: 1}, {Key: "provider_user_id", Value: 1}},
		Options: options.Index().SetName(legacyOAuthUniqueIndex).SetUnique(true),
	}); err != nil {
		t.Fatalf("seed legacy index: %v", err)
	}

	if err := EnsureIndexes(ctx, database); err != nil {
		t.Fatalf("EnsureIndexes failed: %v", err)
	}

	names := map[string]bool{}
	cursor, err := links.Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	for cursor.Next(ctx) {
		var idx struct {
			Name string `bson:"name"`
		}
		if err := cursor.Decode(&idx); err == nil {
			names[idx.Name] = true
		}
	}
	if names[legacyOAuthUniqueIndex] {
		t.Fatal("EnsureIndexes left the tenant-blind unique index in place")
	}
	if !names["uq_oauth_accounts_provider_tenant_uid"] {
		t.Fatal("EnsureIndexes did not create the tenant-qualified unique index")
	}

	// The same pairwise subject in two tenants is two identities, not a conflict.
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if _, err := links.InsertOne(ctx, bson.M{
			"_id": uuid.New().String(), "user_id": uuid.New().String(), "provider_id": "microsoft",
			"provider_tenant_id": tenant, "provider_user_id": "shared-sub", "email": tenant + "@example.com",
		}); err != nil {
			t.Fatalf("insert link for %s: %v", tenant, err)
		}
	}
}

// TestVerifyOAuthAccountTenantScope pins the Mongo analogue of SQL NOT NULL:
// a document whose tenant is missing or null must refuse startup rather than
// index as null and disappear from tenant-qualified lookups.
func TestVerifyOAuthAccountTenantScope(t *testing.T) {
	uri := requireMongoURI(t)
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo.Connect failed: %v", err)
	}
	database := client.Database(fmt.Sprintf("goauth_test_ms_tenant_scope_%s", strings.ReplaceAll(uuid.New().String(), "-", "")))
	t.Cleanup(func() {
		_ = database.Drop(context.Background())
		_ = client.Disconnect(context.Background())
	})
	ctx := context.Background()
	links := database.Collection("oauth_accounts")
	id := uuid.New().String()
	if _, err := links.InsertOne(ctx, bson.M{
		"_id": id, "provider_id": "microsoft", "provider_user_id": "sub-1", "provider_tenant_id": "",
	}); err != nil {
		t.Fatalf("insert link: %v", err)
	}
	if err := verifyOAuthAccountTenantScope(ctx, database); err != nil {
		t.Fatalf("an empty tenant is a valid non-Microsoft scope: %v", err)
	}
	if _, err := links.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$unset": bson.M{"provider_tenant_id": ""}}); err != nil {
		t.Fatalf("unset tenant: %v", err)
	}
	if err := verifyOAuthAccountTenantScope(ctx, database); err == nil {
		t.Fatal("a document without provider_tenant_id must refuse startup")
	}
	if _, err := links.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"provider_tenant_id": nil}}); err != nil {
		t.Fatalf("null tenant: %v", err)
	}
	if err := verifyOAuthAccountTenantScope(ctx, database); err == nil {
		t.Fatal("a null provider_tenant_id must refuse startup")
	}
	if _, err := links.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"provider_tenant_id": []string{"tenant-a"}}}); err != nil {
		t.Fatalf("array tenant: %v", err)
	}
	if err := verifyOAuthAccountTenantScope(ctx, database); err == nil {
		t.Fatal("an array provider_tenant_id must refuse startup")
	}
}

// TestVerifyOAuthAccountTenantScope_RunsOncePerSchemaVersion pins the one-shot
// gate: a successful sweep records its schema_migrations marker and later boots
// skip the scan, while a refused sweep leaves no marker so the next boot
// re-checks.
func TestVerifyOAuthAccountTenantScope_RunsOncePerSchemaVersion(t *testing.T) {
	uri := requireMongoURI(t)
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo.Connect failed: %v", err)
	}
	database := client.Database(fmt.Sprintf("goauth_test_ms_tenant_once_%s", strings.ReplaceAll(uuid.New().String(), "-", "")))
	t.Cleanup(func() {
		_ = database.Drop(context.Background())
		_ = client.Disconnect(context.Background())
	})
	ctx := context.Background()
	links := database.Collection("oauth_accounts")
	id := uuid.New().String()
	if _, err := links.InsertOne(ctx, bson.M{
		"_id": id, "provider_id": "microsoft", "provider_user_id": "sub-1",
	}); err != nil {
		t.Fatalf("insert link: %v", err)
	}

	if err := VerifyOAuthAccountTenantScope(ctx, database); err == nil {
		t.Fatal("a document without provider_tenant_id must refuse startup")
	}
	var marker bson.M
	err = database.Collection("schema_migrations").FindOne(ctx, bson.M{"_id": oauthTenantScopeCheckID}).Decode(&marker)
	if !stderrors.Is(err, mongo.ErrNoDocuments) {
		t.Fatalf("a refused sweep must not record its marker: %v", err)
	}

	if _, err := links.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"provider_tenant_id": ""}}); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
	if err := VerifyOAuthAccountTenantScope(ctx, database); err != nil {
		t.Fatalf("a clean collection must pass: %v", err)
	}
	if err := database.Collection("schema_migrations").FindOne(ctx, bson.M{"_id": oauthTenantScopeCheckID}).Decode(&marker); err != nil {
		t.Fatalf("a passing sweep must record its marker: %v", err)
	}

	// The marker is what keeps the unindexable scan off every later boot.
	if _, err := links.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$unset": bson.M{"provider_tenant_id": ""}}); err != nil {
		t.Fatalf("unset tenant: %v", err)
	}
	if err := VerifyOAuthAccountTenantScope(ctx, database); err != nil {
		t.Fatalf("the sweep must not repeat after its marker is written: %v", err)
	}
}

// TestBackfillOAuthAccountVerified pins the MongoDB mirror of SQL migration
// 000009: a legacy document written without the flag is promoted only for a
// locally verified owner, an unverified owner keeps the fail-closed default, and
// the run is idempotent and marked.
func TestBackfillOAuthAccountVerified(t *testing.T) {
	uri := requireMongoURI(t)
	opts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("mongo.Connect failed: %v", err)
	}
	database := client.Database(fmt.Sprintf("goauth_test_backfill_%s", strings.ReplaceAll(uuid.New().String(), "-", "")))
	t.Cleanup(func() {
		_ = database.Drop(context.Background())
		_ = client.Disconnect(context.Background())
	})
	ctx := context.Background()

	verifiedOwner, unverifiedOwner := uuid.New(), uuid.New()
	users := database.Collection("users")
	if _, err := users.InsertMany(ctx, []any{
		bson.M{"_id": verifiedOwner.String(), "email": "verified@example.com", "email_verified": true},
		bson.M{"_id": unverifiedOwner.String(), "email": "unverified@example.com", "email_verified": false},
	}); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	links := database.Collection("oauth_accounts")
	legacyVerified, legacyUnverified := uuid.New().String(), uuid.New().String()
	if _, err := links.InsertMany(ctx, []any{
		// Legacy documents carry no verified field at all.
		bson.M{"_id": legacyVerified, "user_id": verifiedOwner.String(), "provider_id": "google",
			"provider_user_id": "sub-legacy-verified", "email": "verified@example.com"},
		bson.M{"_id": legacyUnverified, "user_id": unverifiedOwner.String(), "provider_id": "google",
			"provider_user_id": "sub-legacy-unverified", "email": "unverified@example.com"},
	}); err != nil {
		t.Fatalf("seed links: %v", err)
	}

	readVerified := func(t *testing.T, id string) bool {
		t.Helper()
		var doc OAuthAccountDoc
		if err := links.FindOne(ctx, bson.M{"_id": id}).Decode(&doc); err != nil {
			t.Fatalf("load link %s: %v", id, err)
		}
		return doc.Verified
	}

	for run := 1; run <= 2; run++ {
		if err := BackfillOAuthAccountVerified(ctx, database); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		if !readVerified(t, legacyVerified) {
			t.Fatalf("run %d: link on a verified owner stayed unverified", run)
		}
		if readVerified(t, legacyUnverified) {
			t.Fatalf("run %d: link on an unverified owner must stay unverified", run)
		}
	}
	if n, err := database.Collection("schema_migrations").CountDocuments(ctx, bson.M{"_id": oauthVerifiedBackfillID}); err != nil || n != 1 {
		t.Fatalf("migration marker rows = %d (err %v); want 1", n, err)
	}
	if n, err := database.Collection("schema_migrations").CountDocuments(ctx, bson.M{"_id": oauthVerifiedProgressID}); err != nil || n != 0 {
		t.Fatalf("progress marker rows = %d; want 0 (cleaned up)", n)
	}
}

// TestBackfillOAuthAccountVerified_ConcurrentRuns pins the startup overlap: two
// connect paths racing the one-shot marker must both succeed, promote exactly the
// verified owner's link, and leave a single marker row.
func TestBackfillOAuthAccountVerified_ConcurrentRuns(t *testing.T) {
	uri := requireMongoURI(t)
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo.Connect failed: %v", err)
	}
	database := client.Database(fmt.Sprintf("goauth_test_bf_conc_%s", strings.ReplaceAll(uuid.New().String(), "-", "")))
	t.Cleanup(func() {
		_ = database.Drop(context.Background())
		_ = client.Disconnect(context.Background())
	})
	ctx := context.Background()

	verifiedOwner, unverifiedOwner := uuid.New(), uuid.New()
	if _, err := database.Collection("users").InsertMany(ctx, []any{
		bson.M{"_id": verifiedOwner.String(), "email": "verified@example.com", "email_verified": true},
		bson.M{"_id": unverifiedOwner.String(), "email": "unverified@example.com", "email_verified": false},
	}); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	links := database.Collection("oauth_accounts")
	legacyVerified, legacyUnverified := uuid.New().String(), uuid.New().String()
	if _, err := links.InsertMany(ctx, []any{
		bson.M{"_id": legacyVerified, "user_id": verifiedOwner.String(), "provider_id": "google",
			"provider_user_id": "sub-concurrent-verified", "email": "verified@example.com"},
		bson.M{"_id": legacyUnverified, "user_id": unverifiedOwner.String(), "provider_id": "google",
			"provider_user_id": "sub-concurrent-unverified", "email": "unverified@example.com"},
	}); err != nil {
		t.Fatalf("seed links: %v", err)
	}

	const runs = 2
	start := make(chan struct{})
	errs := make(chan error, runs)
	var wg sync.WaitGroup
	for range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- BackfillOAuthAccountVerified(ctx, database)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent run failed: %v", err)
		}
	}

	readVerified := func(id string) bool {
		t.Helper()
		var doc OAuthAccountDoc
		if err := links.FindOne(ctx, bson.M{"_id": id}).Decode(&doc); err != nil {
			t.Fatalf("load link %s: %v", id, err)
		}
		return doc.Verified
	}
	if !readVerified(legacyVerified) {
		t.Fatal("link on a verified owner stayed unverified under concurrent runs")
	}
	if readVerified(legacyUnverified) {
		t.Fatal("link on an unverified owner must stay unverified under concurrent runs")
	}
	if n, err := database.Collection("schema_migrations").CountDocuments(ctx, bson.M{"_id": oauthVerifiedBackfillID}); err != nil || n != 1 {
		t.Fatalf("migration marker rows = %d (err %v); want 1", n, err)
	}
	if n, err := database.Collection("schema_migrations").CountDocuments(ctx, bson.M{"_id": oauthVerifiedProgressID}); err != nil || n != 0 {
		t.Fatalf("progress marker rows = %d (err %v); want 0", n, err)
	}
}

func TestBackfillOAuthAccountVerified_BatchingAndResumability(t *testing.T) {
	uri := requireMongoURI(t)
	opts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("mongo.Connect failed: %v", err)
	}
	database := client.Database(fmt.Sprintf("goauth_test_backfill_batch_%s", strings.ReplaceAll(uuid.New().String(), "-", "")))
	t.Cleanup(func() {
		_ = database.Drop(context.Background())
		_ = client.Disconnect(context.Background())
	})
	ctx := context.Background()

	oldBatchSize := backfillBatchSize
	backfillBatchSize = 2
	defer func() { backfillBatchSize = oldBatchSize }()

	users := database.Collection("users")
	links := database.Collection("oauth_accounts")
	markers := database.Collection("schema_migrations")

	owners := []string{"u1", "u2", "u3", "u4", "u5"}
	var userDocs []any
	var linkDocs []any
	for _, id := range owners {
		userDocs = append(userDocs, bson.M{"_id": id, "email": id + "@example.com", "email_verified": true})
		linkDocs = append(linkDocs, bson.M{
			"_id":              "link-" + id,
			"user_id":          id,
			"provider_id":      "google",
			"provider_user_id": "sub-" + id,
			"email":            id + "@example.com",
		})
	}
	if _, err := users.InsertMany(ctx, userDocs); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := links.InsertMany(ctx, linkDocs); err != nil {
		t.Fatalf("seed links: %v", err)
	}

	// 1. Simulate a prior truncated run that processed up to u2
	if _, err := markers.InsertOne(ctx, bson.M{
		"_id":          oauthVerifiedProgressID,
		"last_user_id": "u2",
		"updated_at":   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed progress: %v", err)
	}

	// Run the backfill - it should resume from u3 onwards
	if err := BackfillOAuthAccountVerified(ctx, database); err != nil {
		t.Fatalf("BackfillOAuthAccountVerified resume run failed: %v", err)
	}

	// Verify all links from u3 to u5 are now verified
	for _, id := range []string{"u3", "u4", "u5"} {
		var doc OAuthAccountDoc
		if err := links.FindOne(ctx, bson.M{"_id": "link-" + id}).Decode(&doc); err != nil {
			t.Fatalf("find link-%s: %v", id, err)
		}
		if !doc.Verified {
			t.Errorf("expected link-%s to be verified after resume", id)
		}
	}

	// Verify links u1 and u2 were skipped (remain unverified)
	for _, id := range []string{"u1", "u2"} {
		var doc OAuthAccountDoc
		if err := links.FindOne(ctx, bson.M{"_id": "link-" + id}).Decode(&doc); err != nil {
			t.Fatalf("find link-%s: %v", id, err)
		}
		if doc.Verified {
			t.Errorf("expected link-%s to remain unverified (skipped by resume)", id)
		}
	}

	// Verify completion marker exists
	var m bson.M
	if err := markers.FindOne(ctx, bson.M{"_id": oauthVerifiedBackfillID}).Decode(&m); err != nil {
		t.Fatalf("completion marker not found: %v", err)
	}

	// Verify progress marker was cleaned up
	var prog bson.M
	err = markers.FindOne(ctx, bson.M{"_id": oauthVerifiedProgressID}).Decode(&prog)
	if !stderrors.Is(err, mongo.ErrNoDocuments) {
		t.Fatalf("expected progress marker to be deleted, got err: %v", err)
	}

	// Verify email_verified index was created
	cursor, err := users.Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	var foundIndex bool
	for cursor.Next(ctx) {
		var idx struct {
			Name string `bson:"name"`
		}
		if err := cursor.Decode(&idx); err == nil && idx.Name == "idx_users_email_verified" {
			foundIndex = true
			break
		}
	}
	if !foundIndex {
		t.Errorf("expected index idx_users_email_verified to be created")
	}
}

func TestBackfillMicrosoftOIDLinks(t *testing.T) {
	uri := requireMongoURI(t)
	opts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("mongo.Connect failed: %v", err)
	}
	database := client.Database(fmt.Sprintf("goauth_test_ms_backfill_%s", strings.ReplaceAll(uuid.New().String(), "-", "")))
	t.Cleanup(func() {
		_ = database.Drop(context.Background())
		_ = client.Disconnect(context.Background())
	})
	ctx := context.Background()

	ownerID := uuid.New().String()
	links := database.Collection("oauth_accounts")
	now := time.Now().UTC()

	// 1. Identity duplicate on (user_id, email): verified beats newer unverified
	olderVerifiedID := uuid.New().String()
	newerUnverifiedID := uuid.New().String()
	sharedEmail := "ms-shared@example.com"

	// 2. Different emails on same user_id: both must survive
	workLinkID := uuid.New().String()
	personalLinkID := uuid.New().String()

	// 3. 3+ duplicate links for same user_id and email: newest verified survives
	tripleEmail := "ms-triple@example.com"
	tripleOldUnverifiedID := uuid.New().String()
	tripleOlderVerifiedID := uuid.New().String()
	tripleNewestVerifiedID := uuid.New().String()

	// 4. Missing created_at handled gracefully
	missingCreatedAtEmail := "ms-missing-created@example.com"
	missingCreatedAtID := uuid.New().String()
	validCreatedAtID := uuid.New().String()

	if _, err := links.InsertMany(ctx, []any{
		// Pair 1
		bson.M{"_id": olderVerifiedID, "user_id": ownerID, "provider_id": "microsoft",
			"provider_user_id": "ms-oid-1", "email": sharedEmail, "verified": true, "created_at": now.Add(-10 * time.Minute)},
		bson.M{"_id": newerUnverifiedID, "user_id": ownerID, "provider_id": "microsoft",
			"provider_user_id": "ms-sub-1", "email": sharedEmail, "verified": false, "created_at": now},

		// Pair 2: distinct emails on same user
		bson.M{"_id": workLinkID, "user_id": ownerID, "provider_id": "microsoft",
			"provider_user_id": "ms-work-uid", "email": "work@example.com", "verified": true, "created_at": now},
		bson.M{"_id": personalLinkID, "user_id": ownerID, "provider_id": "microsoft",
			"provider_user_id": "ms-personal-uid", "email": "personal@example.com", "verified": true, "created_at": now},

		// Triple group
		bson.M{"_id": tripleOldUnverifiedID, "user_id": ownerID, "provider_id": "microsoft",
			"provider_user_id": "ms-triple-1", "email": tripleEmail, "verified": false, "created_at": now.Add(-20 * time.Minute)},
		bson.M{"_id": tripleOlderVerifiedID, "user_id": ownerID, "provider_id": "microsoft",
			"provider_user_id": "ms-triple-2", "email": tripleEmail, "verified": true, "created_at": now.Add(-10 * time.Minute)},
		bson.M{"_id": tripleNewestVerifiedID, "user_id": ownerID, "provider_id": "microsoft",
			"provider_user_id": "ms-triple-3", "email": tripleEmail, "verified": true, "created_at": now},

		// Missing created_at
		bson.M{"_id": missingCreatedAtID, "user_id": ownerID, "provider_id": "microsoft",
			"provider_user_id": "ms-nocreated-sub", "email": missingCreatedAtEmail, "verified": false},
		bson.M{"_id": validCreatedAtID, "user_id": ownerID, "provider_id": "microsoft",
			"provider_user_id": "ms-validcreated-sub", "email": missingCreatedAtEmail, "verified": true, "created_at": now},
	}); err != nil {
		t.Fatalf("seed links: %v", err)
	}

	for run := 1; run <= 2; run++ {
		if err := BackfillMicrosoftOIDLinks(ctx, database); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}

		// Check Pair 1: verified survived, unverified deleted
		var doc OAuthAccountDoc
		if err := links.FindOne(ctx, bson.M{"_id": olderVerifiedID}).Decode(&doc); err != nil {
			t.Fatalf("run %d: verified link should survive: %v", run, err)
		}
		if err := links.FindOne(ctx, bson.M{"_id": newerUnverifiedID}).Decode(&doc); !stderrors.Is(err, mongo.ErrNoDocuments) {
			t.Fatalf("run %d: unverified duplicate should be deleted, err=%v", run, err)
		}

		// Check Pair 2: distinct identities on same user both survived
		if err := links.FindOne(ctx, bson.M{"_id": workLinkID}).Decode(&doc); err != nil {
			t.Fatalf("run %d: work link should survive: %v", run, err)
		}
		if err := links.FindOne(ctx, bson.M{"_id": personalLinkID}).Decode(&doc); err != nil {
			t.Fatalf("run %d: personal link should survive: %v", run, err)
		}

		// Check Triple group: only newest verified survived
		if err := links.FindOne(ctx, bson.M{"_id": tripleNewestVerifiedID}).Decode(&doc); err != nil {
			t.Fatalf("run %d: newest verified triple link should survive: %v", run, err)
		}
		if err := links.FindOne(ctx, bson.M{"_id": tripleOldUnverifiedID}).Decode(&doc); !stderrors.Is(err, mongo.ErrNoDocuments) {
			t.Fatalf("run %d: old unverified triple duplicate should be deleted, err=%v", run, err)
		}
		if err := links.FindOne(ctx, bson.M{"_id": tripleOlderVerifiedID}).Decode(&doc); !stderrors.Is(err, mongo.ErrNoDocuments) {
			t.Fatalf("run %d: older verified triple duplicate should be deleted, err=%v", run, err)
		}

		// Check Missing created_at: verified with created_at survived
		if err := links.FindOne(ctx, bson.M{"_id": validCreatedAtID}).Decode(&doc); err != nil {
			t.Fatalf("run %d: valid created_at link should survive: %v", run, err)
		}
		if err := links.FindOne(ctx, bson.M{"_id": missingCreatedAtID}).Decode(&doc); !stderrors.Is(err, mongo.ErrNoDocuments) {
			t.Fatalf("run %d: duplicate missing created_at should be deleted, err=%v", run, err)
		}
	}
	if n, err := database.Collection("schema_migrations").CountDocuments(ctx, bson.M{"_id": microsoftOIDBackfillID}); err != nil || n != 1 {
		t.Fatalf("migration marker rows = %d (err %v); want 1", n, err)
	}
}

func TestUserStore_Delete_Cascade(t *testing.T) {
	uri := requireMongoURI(t)
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
		LastActiveAt:      time.Now().Add(-10 * time.Minute).UTC(),
		AbsoluteExpiresAt: time.Now().Add(time.Hour).UTC(),
		CreatedAt:         time.Now().UTC(),
	}
	if err := store.Sessions().Create(ctx, sess); err != nil {
		t.Fatalf("Create session failed: %v", err)
	}

	sess2 := &db.Session{
		ID:                uuid.New(),
		UserID:            uid,
		IDHash:            "id_hash_2",
		SessionType:       db.SessionTypeCookie,
		LastActiveAt:      time.Now().UTC(),
		AbsoluteExpiresAt: time.Now().Add(time.Hour).UTC(),
		CreatedAt:         time.Now().Add(-1 * time.Hour).UTC(),
	}
	if err := store.Sessions().Create(ctx, sess2); err != nil {
		t.Fatalf("Create session2 failed: %v", err)
	}

	// Verify ListByUserID orders by last_active_at DESC
	activeList, err := store.Sessions().ListByUserID(ctx, uid)
	if err != nil {
		t.Fatalf("ListByUserID failed: %v", err)
	}
	if len(activeList) < 2 {
		t.Fatalf("expected at least 2 sessions, got %d", len(activeList))
	}
	if activeList[0].ID != sess2.ID {
		t.Fatalf("expected sess2 first by last_active_at DESC, got %v", activeList[0].ID)
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
	if !stderrors.Is(err, gorm.ErrRecordNotFound) && err == nil {
		t.Fatal("expected verification token to be deleted by cascade, but found it")
	}
}
