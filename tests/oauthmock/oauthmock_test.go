package oauthmock

import (
	"context"
	"testing"

	"github.com/kaiizer777/go-auth/oauth"
)

func mustPKCE(t *testing.T) *oauth.PKCEChallenge {
	t.Helper()
	pkce, err := oauth.GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE = %v", err)
	}
	return pkce
}

func TestChallengeBoundToAuthorize(t *testing.T) {
	t.Parallel()
	m := New("google", "sub-bind", "bind@example.com", true)
	t.Cleanup(m.Close)
	pkce := mustPKCE(t)
	m.AuthURL("state-bind", pkce.Challenge)
	if _, err := m.ExchangeCode(context.Background(), "code-bind", pkce.Verifier); err != nil {
		t.Fatalf("bound verifier rejected: %v", err)
	}
}

func TestUnrelatedChallengeRejected(t *testing.T) {
	t.Parallel()
	m := New("google", "sub-unrel", "unrel@example.com", true)
	t.Cleanup(m.Close)
	m.AuthURL("state-unrel", mustPKCE(t).Challenge)
	other := mustPKCE(t)
	if _, err := m.ExchangeCode(context.Background(), "code-unrel", other.Verifier); err == nil {
		t.Fatal("verifier for an unrelated challenge accepted; want invalid_grant")
	}
}

func TestExchangeWithoutAuthorizeRejected(t *testing.T) {
	t.Parallel()
	m := New("google", "sub-noauth", "noauth@example.com", true)
	t.Cleanup(m.Close)
	pkce := mustPKCE(t)
	if _, err := m.ExchangeCode(context.Background(), "code-noauth", pkce.Verifier); err == nil {
		t.Fatal("exchange without authorize accepted; want invalid_grant")
	}
}

func TestCorruptVerifierRejectedWithoutOptIn(t *testing.T) {
	t.Parallel()
	m := New("google", "sub-corrupt", "corrupt@example.com", true)
	t.Cleanup(m.Close)
	m.CorruptVerifier = true
	pkce := mustPKCE(t)
	m.AuthURL("state-corrupt", pkce.Challenge)
	if _, err := m.ExchangeCode(context.Background(), "code-corrupt", pkce.Verifier); err == nil {
		t.Fatal("tampered verifier accepted without SetRequireVerifier; want invalid_grant")
	}
}

func TestSingleUseCodesRejectReplay(t *testing.T) {
	t.Parallel()
	m := New("google", "sub-replay", "replay@example.com", true)
	t.Cleanup(m.Close)
	m.SingleUseCodes = true
	pkce := mustPKCE(t)
	m.AuthURL("state-replay", pkce.Challenge)
	if _, err := m.ExchangeCode(context.Background(), "code-replay", pkce.Verifier); err != nil {
		t.Fatalf("first exchange = %v; want nil", err)
	}
	if _, err := m.ExchangeCode(context.Background(), "code-replay", pkce.Verifier); err == nil {
		t.Fatal("replayed code accepted; want invalid_grant")
	}
}
