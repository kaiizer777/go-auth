package session

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	apperrors "github.com/kaiizer777/go-auth/errors"
)

func TestReadBearerToken_Valid(t *testing.T) {
	rawToken := "0123456789abcdef0123456789abcdef"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)

	extracted, err := ReadBearerToken(req)
	if err != nil {
		t.Fatalf("ReadBearerToken failed: %v", err)
	}
	if extracted != rawToken {
		t.Fatalf("expected %q, got %q", rawToken, extracted)
	}
}

func TestReadBearerToken_MissingHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token, err := ReadBearerToken(req)
	if token != "" {
		t.Fatalf("expected empty token, got %q", token)
	}
	if !errors.Is(err, apperrors.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestReadBearerToken_WrongScheme(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic 0123456789abcdef0123456789abcdef")

	token, err := ReadBearerToken(req)
	if token != "" {
		t.Fatalf("expected empty token, got %q", token)
	}
	if !errors.Is(err, apperrors.ErrSessionInvalid) {
		t.Fatalf("expected ErrSessionInvalid, got %v", err)
	}
}

func TestReadBearerToken_EmptyToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")

	token, err := ReadBearerToken(req)
	if token != "" {
		t.Fatalf("expected empty token, got %q", token)
	}
	if !errors.Is(err, apperrors.ErrSessionInvalid) {
		t.Fatalf("expected ErrSessionInvalid, got %v", err)
	}
}

func TestReadBearerToken_WrongLength_Short(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcde") // 31 chars

	token, err := ReadBearerToken(req)
	if token != "" {
		t.Fatalf("expected empty token, got %q", token)
	}
	if !errors.Is(err, apperrors.ErrSessionInvalid) {
		t.Fatalf("expected ErrSessionInvalid, got %v", err)
	}
}

func TestReadBearerToken_WrongLength_Long(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef0") // 33 chars

	token, err := ReadBearerToken(req)
	if token != "" {
		t.Fatalf("expected empty token, got %q", token)
	}
	if !errors.Is(err, apperrors.ErrSessionInvalid) {
		t.Fatalf("expected ErrSessionInvalid, got %v", err)
	}
}

func TestReadBearerToken_InvalidHex(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdeg") // 'g' is not hex

	token, err := ReadBearerToken(req)
	if token != "" {
		t.Fatalf("expected empty token, got %q", token)
	}
	if !errors.Is(err, apperrors.ErrSessionInvalid) {
		t.Fatalf("expected ErrSessionInvalid, got %v", err)
	}
}

func TestReadBearerToken_UppercaseHex(t *testing.T) {
	upperToken := "0123456789ABCDEF0123456789ABCDEF"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+upperToken)

	extracted, err := ReadBearerToken(req)
	if err != nil {
		t.Fatalf("ReadBearerToken failed: %v", err)
	}
	expected := "0123456789abcdef0123456789abcdef"
	if extracted != expected {
		t.Fatalf("expected lowercase token %q, got %q", expected, extracted)
	}
}
