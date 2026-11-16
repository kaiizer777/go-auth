package email

import (
	"context"
	"errors"
	"testing"
)

func TestHooks_Execution(t *testing.T) {
	var verifyCalled bool
	var resetCalled bool

	hooks := Hooks{
		SendVerificationEmail: func(ctx context.Context, recipient, token string) error {
			if recipient != "user@example.com" {
				t.Errorf("got recipient %q, want user@example.com", recipient)
			}
			if token != "vtok-123" {
				t.Errorf("got token %q, want vtok-123", token)
			}
			verifyCalled = true
			return nil
		},
		SendPasswordResetEmail: func(ctx context.Context, recipient, token string) error {
			if recipient != "reset@example.com" {
				t.Errorf("got recipient %q, want reset@example.com", recipient)
			}
			if token != "rtok-456" {
				t.Errorf("got token %q, want rtok-456", token)
			}
			resetCalled = true
			return errors.New("reset fail")
		},
	}

	if err := hooks.SendVerificationEmail(context.Background(), "user@example.com", "vtok-123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verifyCalled {
		t.Fatal("expected SendVerificationEmail to be called")
	}

	if err := hooks.SendPasswordResetEmail(context.Background(), "reset@example.com", "rtok-456"); err == nil {
		t.Fatal("expected error from SendPasswordResetEmail")
	}
	if !resetCalled {
		t.Fatal("expected SendPasswordResetEmail to be called")
	}
}
