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
)

// Reproduces the rollover lost-update: caller A fetches the post-rollover document
// while caller B's older fetch commits first, superseding A's generation.
func TestJWKSManager_SupersededRefreshServesRequestedKid(t *testing.T) {
	_, oldN, oldE := generateTestRSAKey(t)
	newPriv, newN, newE := generateTestRSAKey(t)

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
	defer release()

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
	if res.err != nil {
		t.Fatalf("superseded refresh lost kid_new: %v", res.err)
	}
	if res.key.Key.N.Cmp(newPriv.N) != 0 {
		t.Fatal("returned key is not the rollover key")
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
	defer release()

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
