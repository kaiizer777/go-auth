package totp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
)

// rewrapBatchSize is the keyset page size; one statement is issued per row.
const rewrapBatchSize = 200

// RewrapSecrets rewrites every stored TOTP secret that is not sealed under the
// active key and returns how many rows it rewrote. It covers enabled and pending
// enrolments alike and touches nothing else.
//
// Run it only once every instance of the fleet can read the envelope format: a
// rewritten row is unreadable to an older binary, so rolling back after a
// partial sweep locks out the users it already migrated. That risk is why the
// sweep is an explicit call and never a startup hook.
//
// The sweep is idempotent and resumable. Rows already on the active kid are
// skipped without a write, each row commits on its own, and a row's ciphertext
// and key-id hint are written by a single CAS-guarded statement, so an
// interruption leaves every row either fully migrated or untouched. Infrastructure
// failures return an error; a row that no ring key can open aborts the run
// because that row is a future lockout, and the count of rows already rewritten
// travels with the error.
func RewrapSecrets(ctx context.Context, store db.Store, cfg config.TOTPConfig, logger *slog.Logger) (int, error) {
	if store == nil {
		panic("totp: nil db.Store")
	}
	crypt, err := NewCrypto(cfg)
	if err != nil {
		return 0, err
	}
	return rewrapSecrets(ctx, store, crypt, rewrapBatchSize, logger)
}

// rewrapSecrets is the sweep with its batch size exposed so tests can drive
// page boundaries.
func rewrapSecrets(ctx context.Context, store db.Store, crypt *Crypto, batch int, logger *slog.Logger) (int, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if batch <= 0 {
		batch = rewrapBatchSize
	}

	activeKid := crypt.ActiveKeyID()
	sweep := &secretSweeper{store: store, crypt: crypt, activeKid: activeKid}

	rewritten := 0
	cursor := uuid.Nil
	for {
		if err := ctx.Err(); err != nil {
			return rewritten, err
		}

		page, err := store.Totp().ListSecretsForRewrap(ctx, cursor, batch)
		if err != nil {
			return rewritten, fmt.Errorf("totp rewrap: list secrets after %s: %w", cursor, err)
		}

		for i := range page {
			if err := ctx.Err(); err != nil {
				return rewritten, err
			}
			wrote, err := sweep.rewrap(ctx, page[i])
			if err != nil {
				return rewritten, fmt.Errorf("totp rewrap aborted after %d rows rewritten: %w", rewritten, err)
			}
			if wrote {
				rewritten++
			}
		}

		if len(page) < batch {
			break
		}
		cursor = page[len(page)-1].ID
	}

	logger.Info("totp secrets rewrapped",
		slog.String("event", "totp_rewrap_complete"),
		slog.String("active_kid", activeKid),
		slog.Int("rewritten", rewritten))
	return rewritten, nil
}

type secretSweeper struct {
	store     db.Store
	crypt     *Crypto
	activeKid string
}

// rewrap moves one row onto the active key. A row already sealed under the
// active kid is skipped; a CAS miss means a concurrent writer (an enrolment
// recreating the pending row) owns it now, so it is skipped rather than retried.
func (s *secretSweeper) rewrap(ctx context.Context, row db.TotpSecretRewrap) (bool, error) {
	if kid, ok := s.crypt.EnvelopeKeyID(row.EncryptedSecret); ok && kid == s.activeKid {
		return false, nil
	}

	plaintext, err := s.crypt.Decrypt(row.UserID, row.EncryptedSecret)
	if err != nil {
		return false, fmt.Errorf("secret %s (user %s) cannot be opened by any ring key: %w", row.ID, row.UserID, err)
	}
	sealed, sealErr := s.crypt.Encrypt(row.UserID, plaintext)
	clear(plaintext)
	if sealErr != nil {
		return false, fmt.Errorf("seal secret %s: %w", row.ID, sealErr)
	}

	wrote, err := s.store.Totp().UpdateSecretForRewrap(ctx, row.ID, row.EncryptedSecret, sealed, s.activeKid)
	if err != nil {
		return false, fmt.Errorf("update secret %s: %w", row.ID, err)
	}
	return wrote, nil
}
