package matrix_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	ptotp "github.com/pquerna/otp/totp"

	"github.com/kaiizer777/go-auth/errors"
)

func TestMatrix_TotpSecurity(t *testing.T) {
	runMatrix(t, func(t *testing.T, adapter TestAdapter) {
		ctx := context.Background()
		app := adapter.App
		store := adapter.Store

		user := createTestUser(t, store, fmt.Sprintf("matrix_totp_%s@example.com", uuid.New().String()[:8]), "SecurePass#2026!", true)

		// 1. Enrollment
		enrollRes, err := app.TOTP.Enroll(ctx, user.ID.String())
		if err != nil {
			t.Fatalf("TOTP.Enroll failed: %v", err)
		}
		if enrollRes.Secret == "" || enrollRes.QRCode == "" {
			t.Fatal("expected non-empty secret and QR code on enrollment")
		}

		// Verify secret stored in unconfirmed state (enabled = false)
		secretDoc, err := store.Totp().GetSecretByUserID(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetSecretByUserID failed: %v", err)
		}
		if secretDoc.Enabled {
			t.Fatal("expected enrolled TOTP secret to have enabled=false before confirmation")
		}
		// Invariant: raw secret is never stored plaintext in database
		if string(secretDoc.EncryptedSecret) == enrollRes.Secret {
			t.Fatal("security violation: raw TOTP secret stored plaintext in database")
		}

		// 2. Confirmation
		validCode, err := ptotp.GenerateCode(enrollRes.Secret, time.Now().UTC())
		if err != nil {
			t.Fatalf("ptotp.GenerateCode failed: %v", err)
		}

		backupCodes, err := app.TOTP.ConfirmEnrollment(ctx, user.ID.String(), validCode)
		if err != nil {
			t.Fatalf("ConfirmEnrollment failed: %v", err)
		}
		if len(backupCodes) == 0 {
			t.Fatal("expected non-empty backup codes upon confirmation")
		}

		// Verify transition to enabled = true
		secretDoc, err = store.Totp().GetSecretByUserID(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetSecretByUserID failed: %v", err)
		}
		if !secretDoc.Enabled {
			t.Fatal("expected confirmed TOTP secret to have enabled=true")
		}

		// 3. Challenge Token
		tokenRes, err := app.TOTP.CreateChallengeToken(ctx, user.ID.String())
		if err != nil {
			t.Fatalf("CreateChallengeToken failed: %v", err)
		}
		if tokenRes == "" {
			t.Fatal("expected non-empty challenge token")
		}

		validatedToken, err := app.TOTP.ValidateChallengeToken(ctx, tokenRes)
		if err != nil {
			t.Fatalf("ValidateChallengeToken failed: %v", err)
		}
		if validatedToken.UserID != user.ID {
			t.Fatalf("token user mismatch: got %v, want %v", validatedToken.UserID, user.ID)
		}

		// 4. Single-Use Code Consumption & Replay Rejection
		// Generate code for next window (+30s) so it doesn't collide with confirmation code
		codeForAuth, err := ptotp.GenerateCode(enrollRes.Secret, time.Now().Add(30*time.Second).UTC())
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}

		// Initial verification succeeds
		err = app.TOTP.VerifyCode(ctx, user.ID.String(), codeForAuth, "127.0.0.1")
		if err != nil {
			t.Fatalf("VerifyCode failed on first use: %v", err)
		}

		// Immediate replay of identical code must be rejected with ErrTOTPCodeReplayed
		replayErr := app.TOTP.VerifyCode(ctx, user.ID.String(), codeForAuth, "127.0.0.1")
		if !errors.Is(replayErr, errors.ErrTOTPCodeReplayed) {
			t.Fatalf("expected ErrTOTPCodeReplayed on replay, got %v", replayErr)
		}

		// 5. Backup Code Recovery
		firstBackup := backupCodes[0]
		err = app.TOTP.VerifyBackupCode(ctx, user.ID.String(), firstBackup, "127.0.0.1")
		if err != nil {
			t.Fatalf("VerifyBackupCode failed on valid code: %v", err)
		}

		// Replay of consumed backup code fails
		replayBackupErr := app.TOTP.VerifyBackupCode(ctx, user.ID.String(), firstBackup, "127.0.0.1")
		if !errors.Is(replayBackupErr, errors.ErrBackupCodeInvalid) {
			t.Fatalf("expected ErrBackupCodeInvalid on consumed backup code replay, got %v", replayBackupErr)
		}
	})
}
