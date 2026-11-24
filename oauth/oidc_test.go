package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apperrors "github.com/kaiizer777/go-auth/errors"
)

// A superseded fetch must not authorize a kid absent from the committed set:
// caller A fetches the post-rollover document while caller B's older fetch
// commits first, superseding A's generation.
func TestJWKSManager_SupersededRefreshRejectsUncommittedKid(t *testing.T) {
	_, oldN, oldE := generateTestRSAKey(t)
	_, newN, newE := generateTestRSAKey(t)

	oldSet := JWKDoc{Keys: []JWKKey{{
		Kty: "RSA", Use: "sig", Kid: "kid_old", Alg: "RS256", N: oldN, E: oldE,
	}}}
	newSet := JWKDoc{Keys: []JWKKey{
		{Kty: "RSA", Use: "sig", Kid: "kid_old", Alg: "RS256", N: oldN, E: oldE},
		{Kty: "RSA", Use: "sig", Kid: "kid_new", Alg: "RS256", N: newN, E: newE},
	}}

	var requests atomic.Int32
	rolloverStarted := make(chan struct{})
	releaseRollover := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRollover) }) }

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch requests.Add(1) {
		case 1:
			_ = json.NewEncoder(w).Encode(oldSet)
		case 2:
			close(rolloverStarted)
			<-releaseRollover
			_ = json.NewEncoder(w).Encode(newSet)
		default:
			_ = json.NewEncoder(w).Encode(oldSet)
		}
	}))
	defer srv.Close()
	// Registered after Close so it runs first (LIFO): a Fatal must not leave a
	// handler parked on releaseRollover while Close waits for it.
	defer release()

	mgr := NewJWKSManager(srv.URL, srv.Client(), time.Hour)

	// Cache holds the pre-rollover set.
	oldPub, ok := parseRSAPublicKey(oldN, oldE)
	if !ok {
		t.Fatal("failed to parse old public key")
	}
	mgr.mu.Lock()
	mgr.keys = map[string]JWKSKey{"kid_old": {Key: oldPub}}
	mgr.expires = time.Now().Add(-time.Minute)
	mgr.mu.Unlock()

	type result struct {
		key JWKSKey
		err error
	}
	aDone := make(chan result, 1)
	go func() {
		key, err := mgr.GetKey(context.Background(), "kid_new")
		aDone <- result{key: key, err: err}
	}()

	select {
	case <-rolloverStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("rollover fetch never started")
	}

	// Force caller B's refresh to look expired while A's rollover GET is in flight.
	mgr.mu.Lock()
	mgr.expires = time.Now().Add(-time.Minute)
	mgr.mu.Unlock()

	if _, err := mgr.GetKey(context.Background(), "kid_old"); err != nil {
		t.Fatalf("caller B refresh failed: %v", err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("jwks requests before release = %d; want 3", got)
	}

	release()

	res := <-aDone
	if res.err == nil {
		t.Fatal("superseded refresh authorized a kid absent from the committed set")
	}
	var appErr *apperrors.Error
	if !apperrors.As(res.err, &appErr) || appErr.Code() != apperrors.CodeOAuthIDTokenInvalid {
		t.Fatalf("expected CodeOAuthIDTokenInvalid, got %v", res.err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("jwks requests = %d; want 3", got)
	}
}

// Same-kid rotation: caller A's fetch carries pre-rotation material for a kid
// that caller B already committed newer material for.
func TestJWKSManager_CommittedMaterialWinsSameKidRotation(t *testing.T) {
	_, otherN, otherE := generateTestRSAKey(t)
	_, oldN, oldE := generateTestRSAKey(t)
	newPriv, newN, newE := generateTestRSAKey(t)

	otherSet := JWKDoc{Keys: []JWKKey{
		{Kty: "RSA", Use: "sig", Kid: "kid_other", Alg: "RS256", N: otherN, E: otherE},
	}}
	oldSet := JWKDoc{Keys: []JWKKey{
		{Kty: "RSA", Use: "sig", Kid: "kid_rot", Alg: "RS256", N: oldN, E: oldE},
	}}
	newSet := JWKDoc{Keys: []JWKKey{
		{Kty: "RSA", Use: "sig", Kid: "kid_rot", Alg: "RS256", N: newN, E: newE},
	}}

	var requests atomic.Int32
	rolloverStarted := make(chan struct{})
	releaseRollover := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRollover) }) }

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch requests.Add(1) {
		case 1:
			_ = json.NewEncoder(w).Encode(otherSet)
		case 2:
			close(rolloverStarted)
			<-releaseRollover
			_ = json.NewEncoder(w).Encode(oldSet)
		default:
			_ = json.NewEncoder(w).Encode(newSet)
		}
	}))
	defer srv.Close()
	// Registered after Close so it runs first (LIFO): a Fatal must not leave a
	// handler parked on releaseRollover while Close waits for it.
	defer release()

	mgr := NewJWKSManager(srv.URL, srv.Client(), time.Hour)

	type result struct {
		key JWKSKey
		err error
	}
	aDone := make(chan result, 1)
	go func() {
		key, err := mgr.GetKey(context.Background(), "kid_rot")
		aDone <- result{key: key, err: err}
	}()

	select {
	case <-rolloverStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("rollover fetch never started")
	}

	// B commits post-rotation material for kid_rot while A's older fetch is in flight.
	if _, err := mgr.GetKey(context.Background(), "kid_rot"); err != nil {
		t.Fatalf("concurrent refresh failed: %v", err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("jwks requests before release = %d; want 3", got)
	}

	release()

	res := <-aDone
	if res.err != nil {
		t.Fatalf("superseded refresh failed: %v", res.err)
	}
	if res.key.Key.N.Cmp(newPriv.N) != 0 {
		t.Fatal("superseded fetch returned older material than the committed cache")
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("jwks requests = %d; want 3", got)
	}
}

// Primary-flight ordering: caller A's first fetch returns pre-rotation material for
// a kid whose newer material another flight committed before A resolved its fetch.
func TestJWKSManager_SupersededPrimaryFlightPrefersCommittedKey(t *testing.T) {
	_, otherN, otherE := generateTestRSAKey(t)
	_, oldN, oldE := generateTestRSAKey(t)
	newPriv, newN, newE := generateTestRSAKey(t)

	otherSet := JWKDoc{Keys: []JWKKey{
		{Kty: "RSA", Use: "sig", Kid: "kid_other", Alg: "RS256", N: otherN, E: otherE},
	}}
	oldSet := JWKDoc{Keys: []JWKKey{
		{Kty: "RSA", Use: "sig", Kid: "kid_rot", Alg: "RS256", N: oldN, E: oldE},
	}}
	newSet := JWKDoc{Keys: []JWKKey{
		{Kty: "RSA", Use: "sig", Kid: "kid_rot", Alg: "RS256", N: newN, E: newE},
	}}

	var requests atomic.Int32
	rolloverStarted := make(chan struct{})
	rolloverRelease := make(chan struct{})
	primaryStarted := make(chan struct{})
	primaryRelease := make(chan struct{})
	var rolloverOnce, primaryOnce sync.Once
	unblockRollover := func() { rolloverOnce.Do(func() { close(rolloverRelease) }) }
	unblockPrimary := func() { primaryOnce.Do(func() { close(primaryRelease) }) }

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch requests.Add(1) {
		case 1:
			_ = json.NewEncoder(w).Encode(otherSet)
		case 2:
			close(rolloverStarted)
			<-rolloverRelease
			_ = json.NewEncoder(w).Encode(newSet)
		case 3:
			close(primaryStarted)
			<-primaryRelease
			_ = json.NewEncoder(w).Encode(oldSet)
		default:
			_ = json.NewEncoder(w).Encode(newSet)
		}
	}))
	defer srv.Close()
	// Registered after Close so they run first (LIFO): a Fatal must not leave a
	// handler parked on a release channel while Close waits for it.
	defer unblockPrimary()
	defer unblockRollover()

	mgr := NewJWKSManager(srv.URL, srv.Client(), time.Hour)

	type result struct {
		key JWKSKey
		err error
	}

	// B parks in the rollover flight; its fetch commits the newer document.
	bDone := make(chan result, 1)
	go func() {
		key, err := mgr.GetKey(context.Background(), "kid_rot")
		bDone <- result{key: key, err: err}
	}()

	select {
	case <-rolloverStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("rollover fetch never started")
	}

	// A's primary flight is unjoined now, so its fetch can race B's commit.
	aDone := make(chan result, 1)
	go func() {
		key, err := mgr.GetKey(context.Background(), "kid_rot")
		aDone <- result{key: key, err: err}
	}()

	select {
	case <-primaryStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("primary fetch never started")
	}

	unblockRollover()
	if res := <-bDone; res.err != nil {
		t.Fatalf("rollover refresh failed: %v", res.err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("jwks requests before primary release = %d; want 3", got)
	}

	unblockPrimary()

	res := <-aDone
	if res.err != nil {
		t.Fatalf("superseded primary flight lost the key: %v", res.err)
	}
	if res.key.Key.N.Cmp(newPriv.N) != 0 {
		t.Fatal("superseded primary fetch returned older material than the committed cache")
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("jwks requests = %d; want 3", got)
	}
}

func TestJWKSManager_RolloverRefreshFailureStaysAuthError(t *testing.T) {
	_, n, e := generateTestRSAKey(t)
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			_ = json.NewEncoder(w).Encode(JWKDoc{Keys: []JWKKey{
				{Kty: "RSA", Use: "sig", Kid: "kid-1", Alg: "RS256", N: n, E: e},
			}})
			return
		}
		http.Error(w, "upstream down", http.StatusBadGateway)
	}))
	defer srv.Close()

	mgr := NewJWKSManager(srv.URL, srv.Client(), time.Hour)
	_, err := mgr.GetKey(context.Background(), "kid-missing")
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	var appErr *apperrors.Error
	if !apperrors.As(err, &appErr) || appErr.Code() != apperrors.CodeOAuthIDTokenInvalid {
		t.Fatalf("expected auth failure CodeOAuthIDTokenInvalid, got %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("jwks requests = %d; want 2", got)
	}
}

func TestJWKSManager_CachedKeyRejectsExpiredDocument(t *testing.T) {
	_, n, e := generateTestRSAKey(t)
	pub, ok := parseRSAPublicKey(n, e)
	if !ok {
		t.Fatal("failed to parse public key")
	}
	mgr := NewJWKSManager("http://unused", nil, time.Hour)
	mgr.mu.Lock()
	mgr.keys = map[string]JWKSKey{"kid-1": {Key: pub}}
	mgr.expires = time.Now().Add(time.Minute)
	mgr.mu.Unlock()

	if _, ok := mgr.cachedKey("kid-1"); !ok {
		t.Fatal("fresh cached key rejected")
	}

	mgr.mu.Lock()
	mgr.expires = time.Now().Add(-time.Second)
	mgr.mu.Unlock()
	if _, ok := mgr.cachedKey("kid-1"); ok {
		t.Fatal("expired cached key accepted")
	}
}
