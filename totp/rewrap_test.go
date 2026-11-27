package totp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
	apperrors "github.com/kaiizer777/go-auth/errors"
)

// rotatedKeyring is the post-rotation ring: k2 encrypts, the old hex key stays
// available under kid "legacy".
func rotatedKeyring(t *testing.T) string {
	t.Helper()

	raw, err := hex.DecodeString(validTestHexKey())
	if err != nil {
		t.Fatalf("decode hex key: %v", err)
	}
	return testKeyringSpec("k2", 0x42) + "," + legacyKeyID + ":" + base64.StdEncoding.EncodeToString(raw)
}

func gormstoreOf(t *testing.T, database *gorm.DB) db.Store {
	t.Helper()

	store := gormstore.New(database)
	if store == nil {
		t.Fatal("gorm store is nil")
	}
	return store
}

func seedSecret(t *testing.T, database *gorm.DB, store db.Store, email string, blob []byte, enabled bool) *db.TotpSecret {
	t.Helper()

	user := createTestUser(t, database, email, true)
	return seedSecretFor(t, store, user.ID, blob, enabled)
}

func seedSecretFor(t *testing.T, store db.Store, userID uuid.UUID, blob []byte, enabled bool) *db.TotpSecret {
	t.Helper()

	record := &db.TotpSecret{
		ID:              uuid.New(),
		UserID:          userID,
		EncryptedSecret: blob,
		BackupCodes:     []byte("[]"),
		Enabled:         enabled,
	}
	if err := store.Totp().CreateSecret(context.Background(), record); err != nil {
		t.Fatalf("seed secret for %s: %v", userID, err)
	}
	return record
}

func storedBlob(t *testing.T, store db.Store, userID uuid.UUID) []byte {
	t.Helper()

	record, err := store.Totp().GetSecretByUserID(context.Background(), userID)
	if err != nil {
		t.Fatalf("load secret for %s: %v", userID, err)
	}
	return record.EncryptedSecret
}

func storedHint(t *testing.T, database *gorm.DB, secretID uuid.UUID) string {
	t.Helper()

	var hint string
	if err := database.Raw("SELECT secret_kid FROM totp_secrets WHERE id = ?", secretID.String()).Row().Scan(&hint); err != nil {
		t.Fatalf("read secret_kid: %v", err)
	}
	return hint
}

func TestRewrapSecrets_MigratesLegacyRowsAndKeepsThemReadable(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	store := gormstoreOf(t, database)
	legacyBlob := readLegacyFixture(t, "legacy_secret.hex")

	enabledRow := seedSecret(t, database, store, "rewrap-enabled@example.com", legacyBlob, true)
	pendingRow := seedSecret(t, database, store, "rewrap-pending@example.com", readLegacyFixture(t, "legacy_secret_brace.hex"), false)

	cfg := config.TOTPConfig{EncryptionKey: validTestHexKey()}
	rewritten, err := RewrapSecrets(context.Background(), store, cfg, nil)
	if err != nil {
		t.Fatalf("RewrapSecrets: %v", err)
	}
	if rewritten != 2 {
		t.Fatalf("rewritten = %d, want 2", rewritten)
	}

	crypt, err := NewCrypto(cfg)
	if err != nil {
		t.Fatalf("NewCrypto: %v", err)
	}
	for _, row := range []*db.TotpSecret{enabledRow, pendingRow} {
		blob := storedBlob(t, store, row.UserID)
		kid, ok := crypt.EnvelopeKeyID(blob)
		if !ok || kid != legacyKeyID {
			t.Fatalf("row %s = (kid %q, envelope %v), want an envelope under %q", row.ID, kid, ok, legacyKeyID)
		}
		if hint := storedHint(t, database, row.ID); hint != legacyKeyID {
			t.Errorf("row %s hint = %q, want %q", row.ID, hint, legacyKeyID)
		}
		plaintext, err := crypt.Decrypt(row.UserID, blob)
		if err != nil {
			t.Fatalf("rewrapped row %s does not open: %v", row.ID, err)
		}
		if string(plaintext) != legacyFixtureSecret {
			t.Fatalf("rewrapped row %s = %q, want %q", row.ID, plaintext, legacyFixtureSecret)
		}
		if _, err := crypt.Decrypt(uuid.New(), blob); err == nil {
			t.Fatalf("rewrapped row %s opens for another user", row.ID)
		}
	}
}

func TestRewrapSecrets_IsIdempotent(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	store := gormstoreOf(t, database)
	row := seedSecret(t, database, store, "rewrap-idempotent@example.com", readLegacyFixture(t, "legacy_secret.hex"), true)

	cfg := config.TOTPConfig{EncryptionKey: validTestHexKey()}
	if _, err := RewrapSecrets(context.Background(), store, cfg, nil); err != nil {
		t.Fatalf("first RewrapSecrets: %v", err)
	}
	afterFirst := storedBlob(t, store, row.UserID)

	rewritten, err := RewrapSecrets(context.Background(), store, cfg, nil)
	if err != nil {
		t.Fatalf("second RewrapSecrets: %v", err)
	}
	if rewritten != 0 {
		t.Fatalf("second run rewrote %d rows, want 0", rewritten)
	}
	if !bytes.Equal(storedBlob(t, store, row.UserID), afterFirst) {
		t.Fatal("second run rewrote the ciphertext")
	}
}

func TestRewrapSecrets_RotatesRetiredKid(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	store := gormstoreOf(t, database)

	oldCrypto, err := NewCrypto(config.TOTPConfig{EncryptionKey: validTestHexKey()})
	if err != nil {
		t.Fatalf("NewCrypto(old): %v", err)
	}
	if oldCrypto.ActiveKeyID() != legacyKeyID {
		t.Fatalf("old active kid = %q", oldCrypto.ActiveKeyID())
	}

	user := createTestUser(t, database, "rewrap-rotated@example.com", true)
	envelope, err := oldCrypto.Encrypt(user.ID, []byte(legacyFixtureSecret))
	if err != nil {
		t.Fatalf("seal under retired kid: %v", err)
	}
	seedSecretFor(t, store, user.ID, envelope, true)

	rotatedCfg := config.TOTPConfig{Keyring: rotatedKeyring(t)}
	rotated, err := NewCrypto(rotatedCfg)
	if err != nil {
		t.Fatalf("NewCrypto(rotated): %v", err)
	}
	if rotated.ActiveKeyID() != "k2" {
		t.Fatalf("rotated active kid = %q, want k2", rotated.ActiveKeyID())
	}

	// The retired kid still opens before the sweep runs.
	if _, err := rotated.Decrypt(user.ID, envelope); err != nil {
		t.Fatalf("retired kid does not open a stored envelope: %v", err)
	}

	rewritten, err := RewrapSecrets(context.Background(), store, rotatedCfg, nil)
	if err != nil {
		t.Fatalf("RewrapSecrets: %v", err)
	}
	if rewritten != 1 {
		t.Fatalf("rewritten = %d, want 1", rewritten)
	}

	blob := storedBlob(t, store, user.ID)
	if kid, ok := rotated.EnvelopeKeyID(blob); !ok || kid != "k2" {
		t.Fatalf("rewritten row = (kid %q, envelope %v), want k2", kid, ok)
	}
	plaintext, err := rotated.Decrypt(user.ID, blob)
	if err != nil || string(plaintext) != legacyFixtureSecret {
		t.Fatalf("rewritten row = (%q, %v)", plaintext, err)
	}

	// The key parked under the retired kid still opens rows this sweep has not
	// touched, which is what makes a partially drained rotation safe.
	late, err := oldCrypto.Encrypt(user.ID, []byte(legacyFixtureSecret))
	if err != nil {
		t.Fatalf("seal under retired kid: %v", err)
	}
	if _, err := rotated.Decrypt(user.ID, late); err != nil {
		t.Fatalf("retired kid no longer opens unrewrapped rows: %v", err)
	}
}

func TestRewrapSecrets_SkipsRowsAlreadyOnActiveKid(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	store := gormstoreOf(t, database)

	cfg := config.TOTPConfig{EncryptionKey: validTestHexKey()}
	crypt, err := NewCrypto(cfg)
	if err != nil {
		t.Fatalf("NewCrypto: %v", err)
	}
	user := createTestUser(t, database, "rewrap-skip@example.com", true)
	sealed, err := crypt.Encrypt(user.ID, []byte(legacyFixtureSecret))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	row := seedSecret(t, database, store, "rewrap-skip-2@example.com", sealed, true)

	rewritten, err := RewrapSecrets(context.Background(), store, cfg, nil)
	if err != nil {
		t.Fatalf("RewrapSecrets: %v", err)
	}
	if rewritten != 0 {
		t.Fatalf("rewritten = %d, want 0 for a row already on the active kid", rewritten)
	}
	if !bytes.Equal(storedBlob(t, store, row.UserID), sealed) {
		t.Fatal("row on the active kid was rewritten")
	}
}

func TestRewrapSecrets_UnopenableRowAbortsAndPreservesBytes(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	store := gormstoreOf(t, database)

	broken := []byte("not-a-secret-blob")
	brokenRow := seedSecret(t, database, store, "rewrap-broken@example.com", broken, true)
	goodRow := seedSecret(t, database, store, "rewrap-good@example.com", readLegacyFixture(t, "legacy_secret.hex"), true)

	cfg := config.TOTPConfig{EncryptionKey: validTestHexKey()}
	crypt, err := NewCrypto(cfg)
	if err != nil {
		t.Fatalf("NewCrypto: %v", err)
	}

	_, err = RewrapSecrets(context.Background(), store, cfg, nil)
	if err == nil {
		t.Fatal("RewrapSecrets succeeded despite an unopenable row")
	}
	if !strings.Contains(err.Error(), brokenRow.UserID.String()) {
		t.Errorf("error does not name the failing owner: %v", err)
	}

	if !bytes.Equal(storedBlob(t, store, brokenRow.UserID), broken) {
		t.Fatal("unopenable row was modified")
	}

	// A row the aborted run already reached stays migrated and readable.
	goodBlob := storedBlob(t, store, goodRow.UserID)
	if !bytes.Equal(goodBlob, readLegacyFixture(t, "legacy_secret.hex")) {
		if _, openErr := crypt.Decrypt(goodRow.UserID, goodBlob); openErr != nil {
			t.Fatalf("row left by the aborted run is unreadable: %v", openErr)
		}
	}
}

func TestRewrapSecrets_ResumesAfterCancellation(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	base := gormstoreOf(t, database)
	legacyBlob := readLegacyFixture(t, "legacy_secret.hex")

	rows := []*db.TotpSecret{
		seedSecret(t, database, base, "rewrap-cancel-1@example.com", legacyBlob, true),
		seedSecret(t, database, base, "rewrap-cancel-2@example.com", legacyBlob, true),
		seedSecret(t, database, base, "rewrap-cancel-3@example.com", legacyBlob, true),
	}

	cfg := config.TOTPConfig{EncryptionKey: validTestHexKey()}
	crypt, err := NewCrypto(cfg)
	if err != nil {
		t.Fatalf("NewCrypto: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	interrupted := &cancelAfterWriteStore{Store: base, cancel: cancel, remaining: 1}
	rewritten, err := rewrapSecrets(ctx, interrupted, crypt, 1, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted run error = %v, want context.Canceled", err)
	}
	if rewritten != 1 {
		t.Fatalf("interrupted run rewrote %d rows, want 1", rewritten)
	}

	migratedAfterInterrupt := make(map[uuid.UUID][]byte, len(rows))
	for _, row := range rows {
		migratedAfterInterrupt[row.UserID] = storedBlob(t, base, row.UserID)
	}

	rewritten, err = RewrapSecrets(context.Background(), base, cfg, nil)
	if err != nil {
		t.Fatalf("resumed RewrapSecrets: %v", err)
	}
	if rewritten != len(rows)-1 {
		t.Fatalf("resumed run rewrote %d rows, want %d", rewritten, len(rows)-1)
	}
	for _, row := range rows {
		blob := storedBlob(t, base, row.UserID)
		if kid, ok := crypt.EnvelopeKeyID(blob); !ok || kid != legacyKeyID {
			t.Fatalf("row %s not migrated: (kid %q, envelope %v)", row.ID, kid, ok)
		}
		plaintext, err := crypt.Decrypt(row.UserID, blob)
		if err != nil || string(plaintext) != legacyFixtureSecret {
			t.Fatalf("row %s = (%q, %v)", row.ID, plaintext, err)
		}
		// A row the interrupted run had already migrated must not be sealed again.
		if before := migratedAfterInterrupt[row.UserID]; !bytes.Equal(before, legacyBlob) && !bytes.Equal(before, blob) {
			t.Fatalf("row %s was sealed twice by the resume", row.ID)
		}
	}
}

func TestRewrapSecrets_CASMissSkips(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	base := gormstoreOf(t, database)
	legacyBlob := readLegacyFixture(t, "legacy_secret.hex")
	row := seedSecret(t, database, base, "rewrap-cas@example.com", legacyBlob, true)

	cfg := config.TOTPConfig{EncryptionKey: validTestHexKey()}
	rewritten, err := RewrapSecrets(context.Background(), &casMissStore{Store: base}, cfg, nil)
	if err != nil {
		t.Fatalf("RewrapSecrets: %v", err)
	}
	if rewritten != 0 {
		t.Fatalf("rewritten = %d, want 0 on a CAS miss", rewritten)
	}
	if !bytes.Equal(storedBlob(t, base, row.UserID), legacyBlob) {
		t.Fatal("CAS miss still modified the row")
	}
}

func TestRewrapSecrets_NoRows(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	store := gormstoreOf(t, database)

	rewritten, err := RewrapSecrets(context.Background(), store, config.TOTPConfig{EncryptionKey: validTestHexKey()}, nil)
	if err != nil {
		t.Fatalf("RewrapSecrets: %v", err)
	}
	if rewritten != 0 {
		t.Fatalf("rewritten = %d, want 0", rewritten)
	}
}

func TestRewrapSecrets_RequiresConfiguredKeys(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	store := gormstoreOf(t, database)

	if _, err := RewrapSecrets(context.Background(), store, config.TOTPConfig{}, nil); !errors.Is(err, apperrors.ErrTOTPEncryptionKeyInvalid) {
		t.Fatalf("RewrapSecrets without a key error = %v, want ErrTOTPEncryptionKeyInvalid", err)
	}
}

func TestRewrapSecrets_BatchBoundary(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	store := gormstoreOf(t, database)
	legacyBlob := readLegacyFixture(t, "legacy_secret.hex")

	const rows = 4
	seeded := make([]*db.TotpSecret, 0, rows)
	for i := 0; i < rows; i++ {
		seeded = append(seeded, seedSecret(t, database, store, "rewrap-batch-"+uuid.New().String()+"@example.com", legacyBlob, i%2 == 0))
	}

	cfg := config.TOTPConfig{EncryptionKey: validTestHexKey()}
	crypt, err := NewCrypto(cfg)
	if err != nil {
		t.Fatalf("NewCrypto: %v", err)
	}
	rewritten, err := rewrapSecrets(context.Background(), store, crypt, rows, nil)
	if err != nil {
		t.Fatalf("rewrapSecrets: %v", err)
	}
	if rewritten != rows {
		t.Fatalf("rewritten = %d, want %d", rewritten, rows)
	}
	for _, row := range seeded {
		if kid, ok := crypt.EnvelopeKeyID(storedBlob(t, store, row.UserID)); !ok || kid != legacyKeyID {
			t.Fatalf("row %s not migrated", row.ID)
		}
	}
}

// cancelAfterWriteStore cancels the sweep context after a successful CAS write,
// which is how the resume test interrupts a run between two committed rows.
type cancelAfterWriteStore struct {
	db.Store
	cancel    context.CancelFunc
	remaining int32
}

func (s *cancelAfterWriteStore) Totp() db.TotpStore {
	return &cancelAfterWriteTotp{TotpStore: s.Store.Totp(), parent: s}
}

type cancelAfterWriteTotp struct {
	db.TotpStore
	parent *cancelAfterWriteStore
}

func (t *cancelAfterWriteTotp) UpdateSecretForRewrap(ctx context.Context, id uuid.UUID, expectedCiphertext, newCiphertext []byte, newKid string) (bool, error) {
	wrote, err := t.TotpStore.UpdateSecretForRewrap(ctx, id, expectedCiphertext, newCiphertext, newKid)
	if wrote && atomic.AddInt32(&t.parent.remaining, -1) == 0 {
		t.parent.cancel()
	}
	return wrote, err
}

// casMissStore simulates a concurrent writer claiming every row first.
type casMissStore struct {
	db.Store
}

func (s *casMissStore) Totp() db.TotpStore {
	return casMissTotp{TotpStore: s.Store.Totp()}
}

type casMissTotp struct {
	db.TotpStore
}

func (casMissTotp) UpdateSecretForRewrap(context.Context, uuid.UUID, []byte, []byte, string) (bool, error) {
	return false, nil
}
