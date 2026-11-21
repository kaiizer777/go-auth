package matrix_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	ptotp "github.com/pquerna/otp/totp"
	"go.mongodb.org/mongo-driver/v2/bson"

	mongostore "github.com/kaiizer777/go-auth/db/mongo"
	"github.com/kaiizer777/go-auth/totp"
)

func TestMatrix_ConcurrentReplayBarrier(t *testing.T) {
	runMatrix(t, func(t *testing.T, adapter TestAdapter) {
		ctx := context.Background()
		app := adapter.App
		store := adapter.Store

		// 1. Setup verified user and enroll TOTP
		user := createTestUser(t, store, fmt.Sprintf("concurrency_barrier_%s@example.com", uuid.New().String()[:8]), "Password#2026!", true)

		enrollRes, err := app.TOTP.Enroll(ctx, user.ID.String())
		if err != nil {
			t.Fatalf("TOTP.Enroll failed: %v", err)
		}

		confirmCode, err := ptotp.GenerateCode(enrollRes.Secret, time.Now().UTC())
		if err != nil {
			t.Fatalf("generate confirm code: %v", err)
		}
		_, err = app.TOTP.ConfirmEnrollment(ctx, user.ID.String(), confirmCode)
		if err != nil {
			t.Fatalf("ConfirmEnrollment failed: %v", err)
		}

		// 2. Issue a single challenge token
		challengeToken, err := app.TOTP.CreateChallengeToken(ctx, user.ID.String())
		if err != nil {
			t.Fatalf("CreateChallengeToken failed: %v", err)
		}

		// 3. Generate currently valid RFC 6238 TOTP code (next window to avoid collision with confirmation)
		validCode, err := ptotp.GenerateCode(enrollRes.Secret, time.Now().Add(30*time.Second).UTC())
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}

		// 4. Setup 5 concurrent goroutines racing with identical code and challenge token
		const concurrency = 5
		startBarrier := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(concurrency)

		type responseResult struct {
			statusCode int
			body       string
			hasSession bool
		}
		results := make([]responseResult, concurrency)

		var successCount int32
		var failureCount int32

		for i := 0; i < concurrency; i++ {
			go func(idx int) {
				defer wg.Done()
				<-startBarrier // synchronize all 5 goroutines to hit endpoint simultaneously

				payload := map[string]string{
					"challenge_token": challengeToken,
					"code":            validCode,
				}
				bodyBytes, _ := json.Marshal(payload)

				req := httptest.NewRequest(http.MethodPost, "/auth/totp/verify", bytes.NewReader(bodyBytes))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Auth-Type", "bearer")
				// Assign distinct client IP to prevent IP-rate-limiter interference
				req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.168.10.%d", 20+idx))

				rec := httptest.NewRecorder()
				app.Handler.ServeHTTP(rec, req)

				hasSess := false
				var respMap map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &respMap); err == nil {
					if _, ok := respMap["session"]; ok {
						hasSess = true
					}
					if _, ok := respMap["token"]; ok {
						hasSess = true
					}
				}

				if rec.Code == http.StatusOK {
					atomic.AddInt32(&successCount, 1)
				} else {
					atomic.AddInt32(&failureCount, 1)
				}

				results[idx] = responseResult{
					statusCode: rec.Code,
					body:       rec.Body.String(),
					hasSession: hasSess,
				}
			}(i)
		}

		close(startBarrier) // Release all 5 goroutines simultaneously
		wg.Wait()

		// 5. Assertions:
		// Exactly 1 request succeeds (200 OK) and receives an authenticated session.
		if successCount != 1 {
			t.Fatalf("expected exactly 1 successful request (200 OK), got %d (results: %+v)", successCount, results)
		}

		// Remaining 4 requests fail (400 or 401 with replay/invalid token error)
		if failureCount != concurrency-1 {
			t.Fatalf("expected exactly %d failed requests, got %d", concurrency-1, failureCount)
		}

		for idx, res := range results {
			if res.statusCode == http.StatusOK {
				if !res.hasSession {
					t.Fatalf("successful request #%d did not receive an authenticated session: %s", idx, res.body)
				}
			} else {
				if res.statusCode != http.StatusBadRequest && res.statusCode != http.StatusUnauthorized {
					t.Fatalf("unexpected failure status code %d for request #%d: %s", res.statusCode, idx, res.body)
				}
			}
		}

		// 6. Database Verification:
		// Zero duplicate sessions: exactly 1 session exists for the user in session store
		activeSessions, err := store.Sessions().ListByUserID(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListByUserID failed: %v", err)
		}
		if len(activeSessions) != 1 {
			t.Fatalf("expected exactly 1 active session in store, got %d", len(activeSessions))
		}

		// Exactly 1 entry exists in totp_used_codes
		codeHash := totp.CodeHash(validCode, user.ID.String())
		hasUsed, err := store.Totp().HasUsedCode(ctx, user.ID, codeHash, time.Now().Add(-5*time.Minute))
		if err != nil {
			t.Fatalf("HasUsedCode query failed: %v", err)
		}
		if !hasUsed {
			t.Fatal("expected totp_used_codes to contain the consumed code")
		}

		// Verify exact count of 1 in totp_used_codes table or collection for the verified code
		if adapter.DB != nil {
			var count int64
			if err := adapter.DB.Table("totp_used_codes").Where("user_id = ? AND code_hash = ?", user.ID.String(), codeHash).Count(&count).Error; err != nil {
				t.Fatalf("failed to query totp_used_codes count: %v", err)
			} else if count != 1 {
				t.Fatalf("expected exactly 1 entry in totp_used_codes table for code, got %d", count)
			}
		} else if mStore, ok := adapter.Store.(*mongostore.MongoStore); ok {
			count, err := mStore.Database().Collection("totp_used_codes").CountDocuments(ctx, bson.M{
				"user_id":   user.ID.String(),
				"code_hash": codeHash,
			})
			if err != nil {
				t.Fatalf("failed to query totp_used_codes count in mongodb: %v", err)
			} else if count != 1 {
				t.Fatalf("expected exactly 1 entry in totp_used_codes mongodb collection, got %d", count)
			}
		} else {
			t.Fatalf("unsupported adapter storage for totp_used_codes count verification: %s", adapter.Name)
		}

		// Verify challenge token consumed (hard deleted)
		tokHash := sha256.Sum256([]byte(challengeToken))
		_, err = store.Totp().GetTwoFactorToken(ctx, tokHash[:])
		if err == nil {
			t.Fatal("expected challenge token to be hard-deleted after consumption, but found it")
		}
	})
}
