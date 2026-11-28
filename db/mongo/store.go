package mongostore

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
)

// MongoStore represents a MongoDB-backed implementation of db.Store.
type MongoStore struct {
	client                *mongo.Client
	database              *mongo.Database
	allowNonTransactional bool
	session               *mongo.Session

	users              *userStore
	sessions           *sessionStore
	verificationTokens *verificationTokenStore
	passwordReset      *passwordResetTokenStore
	oauthAccounts      *oauthAccountStore
	totp               *totpStore
	claimedEmails      *claimedEmailStore
}

// New creates a new MongoStore instance wrapping a MongoDB client and database.
func New(client *mongo.Client, database *mongo.Database, allowNonTransactional bool) *MongoStore {
	store := &MongoStore{
		client:                client,
		database:              database,
		allowNonTransactional: allowNonTransactional,
	}
	store.users = &userStore{store: store}
	store.sessions = &sessionStore{store: store}
	store.verificationTokens = &verificationTokenStore{store: store}
	store.passwordReset = &passwordResetTokenStore{store: store}
	store.oauthAccounts = &oauthAccountStore{store: store}
	store.totp = &totpStore{store: store}
	store.claimedEmails = &claimedEmailStore{store: store}
	return store
}

func (s *MongoStore) withSession(sess *mongo.Session) *MongoStore {
	store := &MongoStore{
		client:                s.client,
		database:              s.database,
		allowNonTransactional: s.allowNonTransactional,
		session:               sess,
	}
	store.users = &userStore{store: store}
	store.sessions = &sessionStore{store: store}
	store.verificationTokens = &verificationTokenStore{store: store}
	store.passwordReset = &passwordResetTokenStore{store: store}
	store.oauthAccounts = &oauthAccountStore{store: store}
	store.totp = &totpStore{store: store}
	store.claimedEmails = &claimedEmailStore{store: store}
	return store
}

func (s *MongoStore) resolveCtx(ctx context.Context) context.Context {
	if s.session != nil {
		return mongo.NewSessionContext(ctx, s.session)
	}
	return ctx
}

func (s *MongoStore) Users() db.UserStore                             { return s.users }
func (s *MongoStore) Sessions() db.SessionStore                       { return s.sessions }
func (s *MongoStore) VerificationTokens() db.VerificationTokenStore   { return s.verificationTokens }
func (s *MongoStore) PasswordResetTokens() db.PasswordResetTokenStore { return s.passwordReset }
func (s *MongoStore) OAuthAccounts() db.OAuthAccountStore             { return s.oauthAccounts }
func (s *MongoStore) Totp() db.TotpStore                              { return s.totp }
func (s *MongoStore) ClaimedEmails() db.ClaimedEmailStore             { return s.claimedEmails }

func (s *MongoStore) Client() *mongo.Client     { return s.client }
func (s *MongoStore) Database() *mongo.Database { return s.database }

func (s *MongoStore) Ping(ctx context.Context) error {
	if s.client == nil {
		return errors.ErrDatabaseUnsupported
	}
	return s.client.Ping(ctx, readpref.Primary())
}

func (s *MongoStore) Close() error {
	if s.client == nil {
		return nil
	}
	return s.client.Disconnect(context.Background())
}

func (s *MongoStore) Transaction(ctx context.Context, fn func(txStore db.Store) error) error {
	if s.client == nil {
		return errors.ErrTransactionUnsupported
	}
	if s.session != nil {
		return fn(s)
	}
	sess, err := s.client.StartSession()
	if err != nil {
		if s.allowNonTransactional {
			slog.Warn("MongoDB StartSession failed; executing non-transactional fallback", "err", err)
			return fn(s)
		}
		return errors.Wrap(errors.ErrTransactionUnsupported, errors.CodeTransactionUnsupported, err.Error())
	}
	defer sess.EndSession(ctx)

	_, err = sess.WithTransaction(ctx, func(sessCtx context.Context) (any, error) {
		txStore := s.withSession(sess)
		return nil, fn(txStore)
	})
	if err != nil {
		if isStandaloneTransactionError(err) {
			if s.allowNonTransactional {
				slog.Warn("MongoDB standalone instance detected with AllowNonTransactionalMongo enabled; executing transaction callback without session isolation")
				return fn(s)
			}
			return errors.Wrap(errors.ErrTransactionUnsupported, errors.CodeTransactionUnsupported, err.Error())
		}
		return NormalizeMongoError(err)
	}
	return nil
}

func isStandaloneTransactionError(err error) bool {
	if err == nil {
		return false
	}
	var srvErr mongo.ServerError
	if errors.As(err, &srvErr) {
		if srvErr.HasErrorCode(115) || srvErr.HasErrorCode(20) {
			return true
		}
	}
	var cmdErr mongo.CommandError
	if errors.As(err, &cmdErr) {
		if cmdErr.Code == 115 || cmdErr.Code == 20 || cmdErr.Name == "CommandNotSupportedOnStandalone" {
			return true
		}
	}
	var cmdErrPtr *mongo.CommandError
	if errors.As(err, &cmdErrPtr) && cmdErrPtr != nil {
		if cmdErrPtr.Code == 115 || cmdErrPtr.Code == 20 || cmdErrPtr.Name == "CommandNotSupportedOnStandalone" {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "transaction numbers are only allowed on a replica set") ||
		strings.Contains(msg, "commandnotsupportedonstandalone") ||
		strings.Contains(msg, "error code 115") ||
		strings.Contains(msg, "error code 20") ||
		strings.Contains(msg, "standalone instance does not support transactions")
}

// Connect establishes a connection to MongoDB, validates connectivity via ping,
// refuses oauth_accounts documents without a string tenant (once per schema
// version), and idempotently provisions native indexes and the
// oauth_accounts.verified data backfill.
func Connect(cfg config.Config) (*MongoStore, error) {
	opts := options.Client().ApplyURI(cfg.DatabaseURL)

	maxOpen := cfg.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 100
	}
	opts.SetMaxPoolSize(uint64(maxOpen))

	if cfg.MaxIdleConns > 0 {
		opts.SetMinPoolSize(uint64(cfg.MaxIdleConns))
	}
	if cfg.MongoDB.MaxConnIdleTime > 0 {
		opts.SetMaxConnIdleTime(cfg.MongoDB.MaxConnIdleTime)
	}
	connectTimeout := cfg.MongoDB.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
	}

	if cfg.MongoDB.ConnectTimeout > 0 {
		opts.SetConnectTimeout(cfg.MongoDB.ConnectTimeout)
	}
	if cfg.MongoDB.ServerSelectionTimeout > 0 {
		opts.SetServerSelectionTimeout(cfg.MongoDB.ServerSelectionTimeout)
	}

	opts.SetReadPreference(readpref.Primary())
	opts.SetWriteConcern(writeconcern.Majority())
	opts.SetTimeout(connectTimeout)

	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to connect to mongodb")
	}

	pingCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	if err := client.Ping(pingCtx, readpref.Primary()); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to ping mongodb")
	}

	dbName := cfg.MongoDB.Database
	database := client.Database(dbName)

	initOp := func(fn func(context.Context, *mongo.Database) error, opName string) error {
		ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		defer cancel()
		if err := fn(ctx, database); err != nil {
			_ = client.Disconnect(context.Background())
			return errors.Wrap(err, errors.CodeDatabaseError, opName)
		}
		return nil
	}

	if err := initOp(VerifyOAuthAccountTenantScope, "failed to verify oauth account tenant scope"); err != nil {
		return nil, err
	}
	if err := initOp(EnsureIndexes, "failed to provision mongodb indexes"); err != nil {
		return nil, err
	}
	if err := initOp(BackfillOAuthAccountVerified, "failed to backfill oauth account verification"); err != nil {
		return nil, err
	}
	if err := initOp(BackfillMicrosoftOIDLinks, "failed to backfill microsoft oid links"); err != nil {
		return nil, err
	}
	if err := initOp(BackfillClaimedEmails, "failed to backfill claimed emails"); err != nil {
		return nil, err
	}

	return New(client, database, cfg.MongoDB.AllowNonTransactionalMongo), nil
}

// ==========================================
// UserStore implementation
// ==========================================

type userStore struct {
	store *MongoStore
}

func (s *userStore) collection() *mongo.Collection {
	return s.store.database.Collection("users")
}

func (s *userStore) Create(ctx context.Context, user *db.User) error {
	doc := userDocFromDomain(user)
	_, err := s.collection().InsertOne(s.store.resolveCtx(ctx), doc)
	if err != nil {
		return NormalizeMongoError(err)
	}
	return nil
}

func (s *userStore) GetByID(ctx context.Context, id uuid.UUID) (*db.User, error) {
	var doc UserDoc
	err := s.collection().FindOne(s.store.resolveCtx(ctx), bson.M{"_id": id.String()}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, err
	}
	return doc.toDomain(), nil
}

func (s *userStore) GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*db.User, error) {
	if s.store.session != nil {
		filter := bson.M{"_id": id.String()}
		update := bson.M{"$set": bson.M{"updated_at": time.Now().UTC()}}
		var doc UserDoc
		err := s.collection().FindOneAndUpdate(s.store.resolveCtx(ctx), filter, update).Decode(&doc)
		if err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				return nil, gorm.ErrRecordNotFound
			}
			return nil, NormalizeMongoError(err)
		}
		return doc.toDomain(), nil
	}
	return s.GetByID(ctx, id)
}

func (s *userStore) GetByEmail(ctx context.Context, email string) (*db.User, error) {
	trimmed := strings.TrimSpace(email)
	if trimmed == "" {
		return nil, gorm.ErrRecordNotFound
	}
	filter := bson.D{{Key: "email", Value: trimmed}}
	findOpts := options.FindOne().SetCollation(&options.Collation{
		Locale:   "en",
		Strength: 2,
	})
	var doc UserDoc
	// codeql[go/sql-injection] Safe: trimmed is a strictly-typed Go string serialized as a BSON string literal.
	err := s.collection().FindOne(s.store.resolveCtx(ctx), filter, findOpts).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, err
	}
	return doc.toDomain(), nil
}

func (s *userStore) Update(ctx context.Context, user *db.User) error {
	user.UpdatedAt = time.Now().UTC()
	update := bson.M{
		"$set": bson.M{
			"email":              user.Email,
			"password_hash":      user.PasswordHash,
			"credential_version": user.CredentialVersion,
			"email_verified":     user.EmailVerified,
			"updated_at":         user.UpdatedAt,
		},
	}
	_, err := s.collection().UpdateOne(s.store.resolveCtx(ctx), bson.M{"_id": user.ID.String()}, update)
	if err != nil {
		return NormalizeMongoError(err)
	}
	return nil
}

func (s *userStore) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	update := bson.M{
		"$set": bson.M{
			"password_hash": passwordHash,
			"updated_at":    time.Now().UTC(),
		},
	}
	_, err := s.collection().UpdateOne(s.store.resolveCtx(ctx), bson.M{"_id": id.String()}, update)
	return err
}

func (s *userStore) IncrementCredentialVersion(ctx context.Context, userID uuid.UUID) (uint32, error) {
	filter := bson.M{"_id": userID.String()}
	update := bson.M{
		"$inc": bson.M{"credential_version": 1},
		"$set": bson.M{"updated_at": time.Now().UTC()},
	}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var updated UserDoc
	err := s.collection().FindOneAndUpdate(s.store.resolveCtx(ctx), filter, update, opts).Decode(&updated)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return 0, nil
		}
		return 0, err
	}
	return uint32(updated.CredentialVersion), nil
}

func (s *userStore) SetEmailVerified(ctx context.Context, id uuid.UUID, verified bool) error {
	update := bson.M{
		"$set": bson.M{
			"email_verified": verified,
			"updated_at":     time.Now().UTC(),
		},
	}
	_, err := s.collection().UpdateOne(s.store.resolveCtx(ctx), bson.M{"_id": id.String()}, update)
	return err
}

func (s *userStore) Delete(ctx context.Context, id uuid.UUID) error {
	uidStr := id.String()
	return s.store.Transaction(ctx, func(txStore db.Store) error {
		mTx, ok := txStore.(*MongoStore)
		if !ok {
			mTx = s.store
		}
		cCtx := mTx.resolveCtx(ctx)
		childCollections := []string{
			"sessions",
			"verification_tokens",
			"password_reset_tokens",
			"oauth_accounts",
			"totp_secrets",
			"totp_used_codes",
			"two_factor_tokens",
		}
		for _, col := range childCollections {
			if _, err := mTx.database.Collection(col).DeleteMany(cCtx, bson.M{"user_id": uidStr}); err != nil {
				return err
			}
		}
		// The claim collection names its owner column owner_user_id, so it is not
		// covered by the user_id sweep above: these rows are what release an
		// address for re-registration after the account is gone.
		if _, err := mTx.database.Collection("claimed_emails").DeleteMany(cCtx, bson.M{"owner_user_id": uidStr}); err != nil {
			return err
		}
		_, err := mTx.database.Collection("users").DeleteOne(cCtx, bson.M{"_id": uidStr})
		return err
	})
}

// ==========================================
// SessionStore implementation
// ==========================================

type sessionStore struct {
	store *MongoStore
}

func (s *sessionStore) collection() *mongo.Collection {
	return s.store.database.Collection("sessions")
}

func (s *sessionStore) Create(ctx context.Context, session *db.Session) error {
	doc := sessionDocFromDomain(session)
	_, err := s.collection().InsertOne(s.store.resolveCtx(ctx), doc)
	if err != nil {
		return NormalizeMongoError(err)
	}
	return nil
}

func (s *sessionStore) GetByID(ctx context.Context, id uuid.UUID) (*db.Session, error) {
	var doc SessionDoc
	err := s.collection().FindOne(s.store.resolveCtx(ctx), bson.M{"_id": id.String()}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, err
	}
	return doc.toDomain(), nil
}

func (s *sessionStore) GetByIDHash(ctx context.Context, idHash string) (*db.Session, error) {
	var doc SessionDoc
	// codeql[go/sql-injection] Safe: idHash is a strictly-typed Go string serialized as a BSON string literal.
	err := s.collection().FindOne(s.store.resolveCtx(ctx), bson.M{"id_hash": idHash}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, err
	}
	return doc.toDomain(), nil
}

func (s *sessionStore) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*db.Session, error) {
	opts := options.Find().SetSort(bson.D{{Key: "last_active_at", Value: -1}}).SetLimit(50)
	cursor, err := s.collection().Find(s.store.resolveCtx(ctx), bson.M{"user_id": userID.String()}, opts)
	if err != nil {
		return []*db.Session{}, err
	}
	defer func() { _ = cursor.Close(s.store.resolveCtx(ctx)) }()

	var docs []SessionDoc
	if err := cursor.All(s.store.resolveCtx(ctx), &docs); err != nil {
		return []*db.Session{}, err
	}
	sessions := make([]*db.Session, 0, len(docs))
	for i := range docs {
		sessions = append(sessions, docs[i].toDomain())
	}
	return sessions, nil
}

func (s *sessionStore) UpdateLastActive(ctx context.Context, id uuid.UUID, lastActive time.Time) error {
	filter := bson.M{
		"_id":            id.String(),
		"last_active_at": bson.M{"$lt": lastActive.UTC()},
	}
	update := bson.M{
		"$set": bson.M{"last_active_at": lastActive.UTC()},
	}
	_, err := s.collection().UpdateOne(s.store.resolveCtx(ctx), filter, update)
	return err
}

func (s *sessionStore) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.collection().DeleteOne(s.store.resolveCtx(ctx), bson.M{"_id": id.String()})
	return err
}

func (s *sessionStore) DeleteByIDHash(ctx context.Context, idHash string) (int64, error) {
	// codeql[go/sql-injection] Safe: idHash is a strictly-typed Go string serialized as a BSON string literal.
	res, err := s.collection().DeleteMany(s.store.resolveCtx(ctx), bson.M{"id_hash": idHash})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

func (s *sessionStore) DeleteIfStale(ctx context.Context, id uuid.UUID, lastActive time.Time) (int64, error) {
	filter := bson.M{
		"_id":            id.String(),
		"last_active_at": bson.M{"$lte": lastActive.UTC()},
	}
	res, err := s.collection().DeleteMany(s.store.resolveCtx(ctx), filter)
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

func (s *sessionStore) DeleteIfStaleByIDHash(ctx context.Context, idHash string, lastActive time.Time) (int64, error) {
	filter := bson.M{
		"id_hash":        idHash,
		"last_active_at": bson.M{"$lte": lastActive.UTC()},
	}
	// codeql[go/sql-injection] Safe: idHash is a strictly-typed Go string serialized as a BSON string literal.
	res, err := s.collection().DeleteMany(s.store.resolveCtx(ctx), filter)
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

func (s *sessionStore) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := s.collection().DeleteMany(s.store.resolveCtx(ctx), bson.M{"user_id": userID.String()})
	return err
}

func (s *sessionStore) DeleteExpired(ctx context.Context, now time.Time, idleCutoff time.Time) (int64, error) {
	filter := bson.M{
		"$or": []bson.M{
			{"absolute_expires_at": bson.M{"$lte": now.UTC()}},
			{"last_active_at": bson.M{"$lte": idleCutoff.UTC()}},
		},
	}
	res, err := s.collection().DeleteMany(s.store.resolveCtx(ctx), filter)
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

func (s *sessionStore) DeleteExpiredByUserID(ctx context.Context, userID uuid.UUID, now time.Time, idleCutoff time.Time) error {
	filter := bson.M{
		"user_id": userID.String(),
		"$or": []bson.M{
			{"absolute_expires_at": bson.M{"$lte": now.UTC()}},
			{"last_active_at": bson.M{"$lte": idleCutoff.UTC()}},
		},
	}
	_, err := s.collection().DeleteMany(s.store.resolveCtx(ctx), filter)
	return err
}

// ==========================================
// VerificationTokenStore implementation
// ==========================================

type verificationTokenStore struct {
	store *MongoStore
}

func (s *verificationTokenStore) collection() *mongo.Collection {
	return s.store.database.Collection("verification_tokens")
}

func (s *verificationTokenStore) Create(ctx context.Context, token *db.VerificationToken) error {
	doc := verificationTokenDocFromDomain(token)
	_, err := s.collection().InsertOne(s.store.resolveCtx(ctx), doc)
	if err != nil {
		return NormalizeMongoError(err)
	}
	return nil
}

func (s *verificationTokenStore) GetByTokenHash(ctx context.Context, tokenHash []byte) (*db.VerificationToken, error) {
	var doc VerificationTokenDoc
	// codeql[go/sql-injection] Safe: tokenHash is a strictly-typed byte slice serialized as a BSON binary literal.
	err := s.collection().FindOne(s.store.resolveCtx(ctx), bson.M{"_id": tokenHash}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, err
	}
	return doc.toDomain(), nil
}

func (s *verificationTokenStore) Delete(ctx context.Context, tokenHash []byte) (int64, error) {
	res, err := s.collection().DeleteOne(s.store.resolveCtx(ctx), bson.M{"_id": tokenHash})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

func (s *verificationTokenStore) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := s.collection().DeleteMany(s.store.resolveCtx(ctx), bson.M{"user_id": userID.String()})
	return err
}

// ==========================================
// PasswordResetTokenStore implementation
// ==========================================

type passwordResetTokenStore struct {
	store *MongoStore
}

func (s *passwordResetTokenStore) collection() *mongo.Collection {
	return s.store.database.Collection("password_reset_tokens")
}

func (s *passwordResetTokenStore) Create(ctx context.Context, token *db.PasswordResetToken) error {
	doc := passwordResetTokenDocFromDomain(token)
	_, err := s.collection().InsertOne(s.store.resolveCtx(ctx), doc)
	if err != nil {
		return NormalizeMongoError(err)
	}
	return nil
}

func (s *passwordResetTokenStore) GetByTokenHash(ctx context.Context, tokenHash []byte) (*db.PasswordResetToken, error) {
	var doc PasswordResetTokenDoc
	// codeql[go/sql-injection] Safe: tokenHash is a strictly-typed byte slice serialized as a BSON binary literal.
	err := s.collection().FindOne(s.store.resolveCtx(ctx), bson.M{"_id": tokenHash}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, err
	}
	return doc.toDomain(), nil
}

func (s *passwordResetTokenStore) Delete(ctx context.Context, tokenHash []byte) (int64, error) {
	res, err := s.collection().DeleteOne(s.store.resolveCtx(ctx), bson.M{"_id": tokenHash})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

func (s *passwordResetTokenStore) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := s.collection().DeleteMany(s.store.resolveCtx(ctx), bson.M{"user_id": userID.String()})
	return err
}

func (s *passwordResetTokenStore) ConsumeToken(ctx context.Context, tokenHash []byte, now time.Time) (bool, error) {
	filter := bson.M{
		"_id":        tokenHash,
		"expires_at": bson.M{"$gt": now.UTC()},
	}
	// codeql[go/sql-injection] Safe: tokenHash is a strictly-typed byte slice serialized as a BSON binary literal.
	res, err := s.collection().DeleteOne(s.store.resolveCtx(ctx), filter)
	if err != nil {
		return false, err
	}
	return res.DeletedCount > 0, nil
}

// ==========================================
// OAuthAccountStore implementation
// ==========================================

type oauthAccountStore struct {
	store *MongoStore
}

func (s *oauthAccountStore) collection() *mongo.Collection {
	return s.store.database.Collection("oauth_accounts")
}

func (s *oauthAccountStore) Create(ctx context.Context, account *db.OAuthAccount) error {
	cCtx := s.store.resolveCtx(ctx)
	// Verify target user exists before inserting link to prevent orphaned links
	var userDoc UserDoc
	err := s.store.database.Collection("users").FindOne(cCtx, bson.M{"_id": account.UserID.String()}).Decode(&userDoc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.ErrUserNotFound
		}
		return NormalizeMongoError(err)
	}

	doc := oauthAccountDocFromDomain(account)
	_, err = s.collection().InsertOne(cCtx, doc)
	if err != nil {
		return NormalizeMongoError(err)
	}
	return nil
}

func (s *oauthAccountStore) GetByProvider(ctx context.Context, providerID, providerTenantID, providerUserID string) (*db.OAuthAccount, error) {
	filter := bson.M{
		"provider_id":        providerID,
		"provider_tenant_id": providerTenantID,
		"provider_user_id":   providerUserID,
	}
	var doc OAuthAccountDoc
	// codeql[go/sql-injection] Safe: providerID, providerTenantID and providerUserID are strictly-typed Go strings serialized as BSON string literals.
	err := s.collection().FindOne(s.store.resolveCtx(ctx), filter).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, err
	}
	return doc.toDomain(), nil
}

func (s *oauthAccountStore) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*db.OAuthAccount, error) {
	// Most recently updated first: a user can hold two links for one provider
	// and the newest is the one a single-row lookup must resolve.
	opts := options.Find().SetSort(bson.D{{Key: "updated_at", Value: -1}})
	cursor, err := s.collection().Find(s.store.resolveCtx(ctx), bson.M{"user_id": userID.String()}, opts)
	if err != nil {
		return []*db.OAuthAccount{}, err
	}
	defer func() { _ = cursor.Close(s.store.resolveCtx(ctx)) }()

	var docs []OAuthAccountDoc
	if err := cursor.All(s.store.resolveCtx(ctx), &docs); err != nil {
		return []*db.OAuthAccount{}, err
	}
	accounts := make([]*db.OAuthAccount, 0, len(docs))
	for i := range docs {
		accounts = append(accounts, docs[i].toDomain())
	}
	return accounts, nil
}

func (s *oauthAccountStore) UpdateProviderUserID(ctx context.Context, id uuid.UUID, providerUserID string) error {
	res, err := s.collection().UpdateOne(s.store.resolveCtx(ctx),
		bson.M{"_id": id.String()},
		bson.M{"$set": bson.M{"provider_user_id": providerUserID, "updated_at": time.Now().UTC()}},
	)
	if err != nil {
		return NormalizeMongoError(err)
	}
	if res.MatchedCount == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (s *oauthAccountStore) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.collection().DeleteOne(s.store.resolveCtx(ctx), bson.M{"_id": id.String()})
	return err
}

func (s *oauthAccountStore) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := s.collection().DeleteMany(s.store.resolveCtx(ctx), bson.M{"user_id": userID.String()})
	return err
}

// oauthAccessSetDoc is the $set payload for an access-only write: the refresh
// fields are absent so a tokenless grant cannot erase them. A nil expiry is
// written as null so the field decodes back to a nil pointer, never a year-1
// time.
func oauthAccessSetDoc(rec db.OAuthTokenRecord) bson.M {
	set := bson.M{
		"access_token_ciphertext": rec.AccessTokenCiphertext,
		"token_scope":             rec.TokenScope,
		"updated_at":              time.Now().UTC(),
	}
	if rec.TokenExpiresAt != nil {
		set["token_expires_at"] = rec.TokenExpiresAt.UTC()
	} else {
		set["token_expires_at"] = nil
	}
	return set
}

// oauthTokenSetDoc is the $set payload both all-column write paths share.
func oauthTokenSetDoc(rec db.OAuthTokenRecord) bson.M {
	set := oauthAccessSetDoc(rec)
	set["refresh_token_ciphertext"] = rec.RefreshTokenCiphertext
	set["refresh_token_fingerprint"] = rec.RefreshTokenFingerprint
	return set
}

func (s *oauthAccountStore) SaveOAuthTokens(ctx context.Context, id uuid.UUID, rec db.OAuthTokenRecord) error {
	res, err := s.collection().UpdateOne(s.store.resolveCtx(ctx),
		bson.M{"_id": id.String()},
		bson.M{"$set": oauthTokenSetDoc(rec)},
	)
	if err != nil {
		return NormalizeMongoError(err)
	}
	if res.MatchedCount == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (s *oauthAccountStore) SaveOAuthTokensCAS(ctx context.Context, id uuid.UUID, expectedFingerprint string, rec db.OAuthTokenRecord) (bool, error) {
	// An empty expectation is never proof of the stored token: a link that
	// carries no fingerprint must not be overwritten by a refresh that has
	// nothing to match. Checked before the filter is built.
	if expectedFingerprint == "" {
		return false, nil
	}
	res, err := s.collection().UpdateOne(s.store.resolveCtx(ctx),
		bson.M{"_id": id.String(), "refresh_token_fingerprint": expectedFingerprint},
		bson.M{"$set": oauthTokenSetDoc(rec)},
	)
	if err != nil {
		return false, NormalizeMongoError(err)
	}
	return res.MatchedCount > 0, nil
}

func (s *oauthAccountStore) SaveOAuthTokensIfUnset(ctx context.Context, id uuid.UUID, rec db.OAuthTokenRecord) (bool, error) {
	res, err := s.collection().UpdateOne(s.store.resolveCtx(ctx),
		bson.M{"_id": id.String(), "$or": oauthAbsentOr("refresh_token_fingerprint")},
		bson.M{"$set": oauthTokenSetDoc(rec)},
	)
	if err != nil {
		return false, NormalizeMongoError(err)
	}
	return res.MatchedCount > 0, nil
}

func (s *oauthAccountStore) SaveOAuthAccess(ctx context.Context, id uuid.UUID, rec db.OAuthTokenRecord) error {
	res, err := s.collection().UpdateOne(s.store.resolveCtx(ctx),
		bson.M{"_id": id.String()},
		bson.M{"$set": oauthAccessSetDoc(rec)},
	)
	if err != nil {
		return NormalizeMongoError(err)
	}
	if res.MatchedCount == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// oauthAbsentOr matches a token column that holds no value, counting a document
// written before that column existed as absent: it decodes to the empty string,
// but an equality on "" alone would never match it.
func oauthAbsentOr(field string) []bson.M {
	return []bson.M{
		{field: ""},
		{field: bson.M{"$exists": false}},
	}
}

func (s *oauthAccountStore) SaveOAuthAccessCAS(ctx context.Context, id uuid.UUID, expectedCiphertext string, rec db.OAuthTokenRecord) (bool, error) {
	filter := bson.M{"_id": id.String()}
	if expectedCiphertext == "" {
		filter["$or"] = oauthAbsentOr("access_token_ciphertext")
	} else {
		filter["access_token_ciphertext"] = expectedCiphertext
	}
	res, err := s.collection().UpdateOne(s.store.resolveCtx(ctx), filter, bson.M{"$set": oauthAccessSetDoc(rec)})
	if err != nil {
		return false, NormalizeMongoError(err)
	}
	return res.MatchedCount > 0, nil
}

func (s *oauthAccountStore) ClearOAuthRefresh(ctx context.Context, id uuid.UUID, expectedFingerprint string) (bool, error) {
	if expectedFingerprint == "" {
		return false, nil
	}
	res, err := s.collection().UpdateOne(s.store.resolveCtx(ctx),
		bson.M{"_id": id.String(), "refresh_token_fingerprint": expectedFingerprint},
		bson.M{"$set": oauthRefreshClearSet()},
	)
	if err != nil {
		return false, NormalizeMongoError(err)
	}
	return res.MatchedCount > 0, nil
}

// oauthRefreshClearSet is the payload for a refresh-only clear: the access
// fields are absent so a discarded refresh grant leaves its envelope in place.
func oauthRefreshClearSet() bson.M {
	return bson.M{
		"refresh_token_ciphertext":  "",
		"refresh_token_fingerprint": "",
		"updated_at":                time.Now().UTC(),
	}
}

// oauthRefreshPairSet is the payload for a rotated pair that owns only the
// refresh columns, leaving the access envelope to its own writers.
func oauthRefreshPairSet(rec db.OAuthTokenRecord) bson.M {
	return bson.M{
		"refresh_token_ciphertext":  rec.RefreshTokenCiphertext,
		"refresh_token_fingerprint": rec.RefreshTokenFingerprint,
		"updated_at":                time.Now().UTC(),
	}
}

// SaveOAuthRefreshIfUnset installs the rotated refresh pair over a row holding
// none, then writes the access columns only while the row still holds no access
// envelope. An update document cannot carry a per-field condition, so the access
// write is its own statement guarded on the column it writes; the refresh pair
// landed first, so a failed second statement leaves a usable grant behind.
func (s *oauthAccountStore) SaveOAuthRefreshIfUnset(ctx context.Context, id uuid.UUID, rec db.OAuthTokenRecord) (bool, error) {
	if rec.RefreshTokenFingerprint == "" {
		return false, nil
	}
	filter := bson.M{"_id": id.String(), "$or": oauthAbsentOr("refresh_token_fingerprint")}
	res, err := s.collection().UpdateOne(s.store.resolveCtx(ctx), filter, bson.M{"$set": oauthRefreshPairSet(rec)})
	if err != nil {
		return false, NormalizeMongoError(err)
	}
	if res.MatchedCount == 0 {
		return false, nil
	}
	if rec.AccessTokenCiphertext == "" {
		return true, nil
	}
	accessFilter := bson.M{"_id": id.String(), "$or": oauthAbsentOr("access_token_ciphertext")}
	if _, err := s.collection().UpdateOne(s.store.resolveCtx(ctx), accessFilter,
		bson.M{"$set": oauthAccessSetDoc(rec)},
	); err != nil {
		return true, NormalizeMongoError(err)
	}
	return true, nil
}

// ==========================================
// TotpStore implementation
// ==========================================

type totpStore struct {
	store *MongoStore
}

func (s *totpStore) secrets() *mongo.Collection {
	return s.store.database.Collection("totp_secrets")
}

func (s *totpStore) usedCodes() *mongo.Collection {
	return s.store.database.Collection("totp_used_codes")
}

func (s *totpStore) twoFactorTokens() *mongo.Collection {
	return s.store.database.Collection("two_factor_tokens")
}

func (s *totpStore) CreateSecret(ctx context.Context, secret *db.TotpSecret) error {
	doc := totpSecretDocFromDomain(secret)
	_, err := s.secrets().InsertOne(s.store.resolveCtx(ctx), doc)
	if err != nil {
		return NormalizeMongoError(err)
	}
	return nil
}

func (s *totpStore) GetSecretByUserID(ctx context.Context, userID uuid.UUID) (*db.TotpSecret, error) {
	var doc TotpSecretDoc
	err := s.secrets().FindOne(s.store.resolveCtx(ctx), bson.M{"user_id": userID.String()}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, err
	}
	return doc.toDomain(), nil
}

func (s *totpStore) GetSecretByUserIDForUpdate(ctx context.Context, userID uuid.UUID) (*db.TotpSecret, error) {
	var doc TotpSecretDoc
	err := s.secrets().FindOne(s.store.resolveCtx(ctx), bson.M{"user_id": userID.String(), "enabled": true}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, err
	}
	return doc.toDomain(), nil
}

// totpRewrapDoc is the stored shape the sweep reads; secret_kid is bookkeeping
// only and absent on documents written before the sweep first touched them.
type totpRewrapDoc struct {
	ID              string `bson:"_id"`
	UserID          string `bson:"user_id"`
	EncryptedSecret []byte `bson:"encrypted_secret"`
	SecretKid       string `bson:"secret_kid"`
}

func (s *totpStore) ListSecretsForRewrap(ctx context.Context, afterID uuid.UUID, limit int) ([]db.TotpSecretRewrap, error) {
	if limit <= 0 {
		return nil, nil
	}

	filter := bson.M{}
	if afterID != uuid.Nil {
		filter["_id"] = bson.M{"$gt": afterID.String()}
	}
	opts := options.Find().
		SetSort(bson.D{{Key: "_id", Value: 1}}).
		SetLimit(int64(limit))

	resolveCtx := s.store.resolveCtx(ctx)
	cursor, err := s.secrets().Find(resolveCtx, filter, opts)
	if err != nil {
		return nil, NormalizeMongoError(err)
	}
	defer func() {
		_ = cursor.Close(resolveCtx)
	}()

	var docs []totpRewrapDoc
	if err := cursor.All(resolveCtx, &docs); err != nil {
		return nil, NormalizeMongoError(err)
	}

	secrets := make([]db.TotpSecretRewrap, 0, len(docs))
	for _, doc := range docs {
		id, err := uuid.Parse(doc.ID)
		if err != nil {
			return nil, errors.New(errors.CodeDatabaseError, "totp secret has a malformed id", err)
		}
		userID, err := uuid.Parse(doc.UserID)
		if err != nil {
			return nil, errors.New(errors.CodeDatabaseError, "totp secret has a malformed user id", err)
		}
		secrets = append(secrets, db.TotpSecretRewrap{
			ID:              id,
			UserID:          userID,
			EncryptedSecret: doc.EncryptedSecret,
			SecretKid:       doc.SecretKid,
		})
	}
	return secrets, nil
}

func (s *totpStore) UpdateSecretForRewrap(ctx context.Context, id uuid.UUID, expectedCiphertext, newCiphertext []byte, newKid string) (bool, error) {
	filter := bson.M{
		"_id":              id.String(),
		"encrypted_secret": expectedCiphertext,
	}
	update := bson.M{
		"$set": bson.M{
			"encrypted_secret": newCiphertext,
			"secret_kid":       newKid,
			"updated_at":       time.Now().UTC(),
		},
	}
	res, err := s.secrets().UpdateOne(s.store.resolveCtx(ctx), filter, update)
	if err != nil {
		return false, NormalizeMongoError(err)
	}
	return res.MatchedCount > 0, nil
}

func (s *totpStore) EnableSecret(ctx context.Context, secretID uuid.UUID, backupCodesJSON []byte) error {
	filter := bson.M{
		"_id":     secretID.String(),
		"enabled": false,
	}
	update := bson.M{
		"$set": bson.M{
			"enabled":      true,
			"backup_codes": backupCodesJSON,
			"updated_at":   time.Now().UTC(),
		},
	}
	res, err := s.secrets().UpdateOne(s.store.resolveCtx(ctx), filter, update)
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return errors.ErrTOTPAlreadyEnabled
	}
	return nil
}

func (s *totpStore) UpdateBackupCodes(ctx context.Context, userID uuid.UUID, backupCodes []string) error {
	rawJSON, err := json.Marshal(backupCodes)
	if err != nil {
		return err
	}
	filter := bson.M{
		"user_id": userID.String(),
		"enabled": true,
	}
	update := bson.M{
		"$set": bson.M{
			"backup_codes": rawJSON,
			"updated_at":   time.Now().UTC(),
		},
	}
	_, err = s.secrets().UpdateOne(s.store.resolveCtx(ctx), filter, update)
	return err
}

func (s *totpStore) UpdateBackupCodesJSON(ctx context.Context, secretID uuid.UUID, backupCodesJSON []byte) error {
	filter := bson.M{
		"_id":     secretID.String(),
		"enabled": true,
	}
	update := bson.M{
		"$set": bson.M{
			"backup_codes": backupCodesJSON,
			"updated_at":   time.Now().UTC(),
		},
	}
	res, err := s.secrets().UpdateOne(s.store.resolveCtx(ctx), filter, update)
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return errors.ErrTOTPNotEnrolled
	}
	return nil
}

func (s *totpStore) UpdateBackupCodesCAS(ctx context.Context, userID uuid.UUID, expectedCodes []string, newCodes []string) (bool, error) {
	expectedJSON, err := json.Marshal(expectedCodes)
	if err != nil {
		return false, err
	}
	newJSON, err := json.Marshal(newCodes)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()

	filter := bson.M{
		"user_id": userID.String(),
		"enabled": true,
		"$or": []bson.M{
			{"backup_codes": expectedCodes},
			{"backup_codes": expectedJSON},
			{"backup_codes": string(expectedJSON)},
		},
	}
	update := bson.M{
		"$set": bson.M{
			"backup_codes": newJSON,
			"updated_at":   now,
		},
	}
	res, err := s.secrets().UpdateOne(s.store.resolveCtx(ctx), filter, update)
	if err != nil {
		return false, err
	}
	return res.ModifiedCount > 0, nil
}

func (s *totpStore) DeleteSecret(ctx context.Context, userID uuid.UUID) error {
	_, err := s.secrets().DeleteMany(s.store.resolveCtx(ctx), bson.M{"user_id": userID.String()})
	return err
}

func (s *totpStore) DeleteUnconfirmedSecret(ctx context.Context, userID uuid.UUID) error {
	_, err := s.secrets().DeleteMany(s.store.resolveCtx(ctx), bson.M{"user_id": userID.String(), "enabled": false})
	return err
}

func (s *totpStore) IsTotpEnabled(ctx context.Context, userID uuid.UUID) (bool, error) {
	count, err := s.secrets().CountDocuments(s.store.resolveCtx(ctx), bson.M{"user_id": userID.String(), "enabled": true})
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *totpStore) HasUsedCode(ctx context.Context, userID uuid.UUID, codeHash []byte, since time.Time) (bool, error) {
	filter := bson.M{
		"user_id":   userID.String(),
		"code_hash": codeHash,
		"used_at":   bson.M{"$gt": since.UTC()},
	}
	count, err := s.usedCodes().CountDocuments(s.store.resolveCtx(ctx), filter)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *totpStore) RecordUsedCode(ctx context.Context, usedCode *db.TotpUsedCode) error {
	doc := totpUsedCodeDocFromDomain(usedCode)
	_, err := s.usedCodes().InsertOne(s.store.resolveCtx(ctx), doc)
	if err != nil {
		return NormalizeMongoError(err)
	}
	return nil
}

func (s *totpStore) PruneUsedCodes(ctx context.Context, userID uuid.UUID, before time.Time) error {
	_, err := s.usedCodes().DeleteMany(s.store.resolveCtx(ctx), bson.M{
		"user_id": userID.String(),
		"used_at": bson.M{"$lt": before.UTC()},
	})
	return err
}

func (s *totpStore) CreateTwoFactorToken(ctx context.Context, token *db.TwoFactorToken) error {
	doc := twoFactorTokenDocFromDomain(token)
	_, err := s.twoFactorTokens().InsertOne(s.store.resolveCtx(ctx), doc)
	if err != nil {
		return NormalizeMongoError(err)
	}
	return nil
}

func (s *totpStore) GetTwoFactorToken(ctx context.Context, tokenHash []byte) (*db.TwoFactorToken, error) {
	var doc TwoFactorTokenDoc
	// codeql[go/sql-injection] Safe: tokenHash is a strictly-typed byte slice serialized as a BSON binary literal.
	err := s.twoFactorTokens().FindOne(s.store.resolveCtx(ctx), bson.M{"token_hash": tokenHash}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, err
	}
	return doc.toDomain(), nil
}

func (s *totpStore) IncrementTwoFactorAttempts(ctx context.Context, tokenHash []byte, maxAttempts int, now time.Time) (int, error) {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	filter := bson.M{"token_hash": tokenHash}
	update := bson.M{"$inc": bson.M{"attempts": 1}}

	var doc TwoFactorTokenDoc
	// codeql[go/sql-injection] Safe: tokenHash is a strictly-typed byte slice serialized as a BSON binary literal.
	err := s.twoFactorTokens().FindOneAndUpdate(s.store.resolveCtx(ctx), filter, update, opts).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return 0, errors.ErrTwoFactorTokenInvalid
		}
		return 0, err
	}
	if now.UTC().After(doc.ExpiresAt) {
		_, _ = s.twoFactorTokens().DeleteOne(s.store.resolveCtx(ctx), bson.M{"_id": doc.ID})
		return 0, errors.ErrTwoFactorTokenExpired
	}
	if doc.Attempts >= maxAttempts {
		_, _ = s.twoFactorTokens().DeleteOne(s.store.resolveCtx(ctx), bson.M{"_id": doc.ID})
		return doc.Attempts, errors.ErrTwoFactorMaxAttemptsExceeded
	}
	return doc.Attempts, nil
}

func (s *totpStore) ConsumeTwoFactorToken(ctx context.Context, tokenHash []byte, maxAttempts int, now time.Time) (bool, error) {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	filter := bson.M{
		"token_hash": tokenHash,
		"expires_at": bson.M{"$gt": now.UTC()},
		"attempts":   bson.M{"$lt": maxAttempts},
	}
	res, err := s.twoFactorTokens().DeleteOne(s.store.resolveCtx(ctx), filter)
	if err != nil {
		return false, err
	}
	return res.DeletedCount > 0, nil
}

func (s *totpStore) DeleteTwoFactorToken(ctx context.Context, id uuid.UUID) (int64, error) {
	res, err := s.twoFactorTokens().DeleteOne(s.store.resolveCtx(ctx), bson.M{"_id": id.String()})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

func (s *totpStore) DeleteTwoFactorTokensByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := s.twoFactorTokens().DeleteMany(s.store.resolveCtx(ctx), bson.M{"user_id": userID.String()})
	return err
}

// ==========================================
// ClaimedEmailStore implementation
// ==========================================

type claimedEmailStore struct {
	store *MongoStore
}

func (s *claimedEmailStore) collection() *mongo.Collection {
	return s.store.database.Collection("claimed_emails")
}

// Claim mirrors the SQL implementation: an upsert that cannot fail the call on a
// duplicate, followed by a read of the holder. Mongo does not abort a transaction
// on a duplicate key, but the same order keeps both backends observably equal.
func (s *claimedEmailStore) Claim(ctx context.Context, email string, ownerID uuid.UUID, verified bool) error {
	key := db.NormalizeEmail(email)
	if key == "" {
		return nil
	}
	now := time.Now().UTC()
	_, err := s.collection().UpdateOne(s.store.resolveCtx(ctx),
		bson.M{"_id": key},
		bson.M{"$setOnInsert": bson.M{
			"owner_user_id": ownerID.String(),
			"verified":      verified,
			"created_at":    now,
			"updated_at":    now,
		}},
		options.UpdateOne().SetUpsert(true),
	)
	// A concurrent upsert of the same _id can lose with a duplicate key; the read
	// below resolves the winner, which is the answer this call needs.
	if err != nil && !mongo.IsDuplicateKeyError(err) {
		return NormalizeMongoError(err)
	}
	var doc ClaimedEmailDoc
	if derr := s.collection().FindOne(s.store.resolveCtx(ctx), bson.M{"_id": key}).Decode(&doc); derr != nil {
		if errors.Is(derr, mongo.ErrNoDocuments) {
			return errors.ErrEmailClaimed
		}
		return derr
	}
	claim := doc.toDomain()
	if claim.OwnerUserID != ownerID {
		return errors.ErrEmailClaimed
	}
	if verified && !claim.Verified {
		_, uerr := s.collection().UpdateOne(s.store.resolveCtx(ctx),
			bson.M{"_id": key, "owner_user_id": ownerID.String()},
			bson.M{"$set": bson.M{"verified": true, "updated_at": now}},
		)
		return uerr
	}
	return nil
}

func (s *claimedEmailStore) Get(ctx context.Context, email string) (*db.ClaimedEmail, error) {
	key := db.NormalizeEmail(email)
	if key == "" {
		return nil, gorm.ErrRecordNotFound
	}
	var doc ClaimedEmailDoc
	if err := s.collection().FindOne(s.store.resolveCtx(ctx), bson.M{"_id": key}).Decode(&doc); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, err
	}
	return doc.toDomain(), nil
}

func (s *claimedEmailStore) Release(ctx context.Context, email string, ownerID uuid.UUID) error {
	key := db.NormalizeEmail(email)
	if key == "" {
		return nil
	}
	_, err := s.collection().DeleteOne(s.store.resolveCtx(ctx), bson.M{"_id": key, "owner_user_id": ownerID.String()})
	return err
}

func (s *claimedEmailStore) ReleaseByUserID(ctx context.Context, ownerID uuid.UUID) error {
	_, err := s.collection().DeleteMany(s.store.resolveCtx(ctx), bson.M{"owner_user_id": ownerID.String()})
	return err
}
