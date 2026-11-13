package db

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kaiizer777/go-auth/errors"
)

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		wantError bool
		wantCode  errors.Code
	}{
		{name: "valid standard email", email: "user@example.com", wantError: false},
		{name: "valid with tag and subdomain", email: "user+tag@sub.domain.co", wantError: false},
		{name: "valid with multiple subdomains", email: "alice.smith+filter@mail.internal.example.org", wantError: false},
		{name: "valid numeric local part", email: "12345@domain.com", wantError: false},
		{name: "quoted local-part with @", email: "\"foo@bar\"@example.com", wantError: false},
		{name: "empty email", email: "", wantError: true, wantCode: errors.CodeInvalidEmail},
		{name: "missing at symbol", email: "userexample.com", wantError: true, wantCode: errors.CodeInvalidEmail},
		{name: "spaces in email", email: "user @example.com", wantError: true, wantCode: errors.CodeInvalidEmail},
		{name: "spaces around email", email: " user@example.com ", wantError: true, wantCode: errors.CodeInvalidEmail},
		{name: "spaces in domain", email: "user@exam ple.com", wantError: true, wantCode: errors.CodeInvalidEmail},
		{name: "no dot in domain", email: "user@localhost", wantError: true, wantCode: errors.CodeInvalidEmail},
		{name: "trailing dot in domain", email: "user@example.", wantError: true, wantCode: errors.CodeInvalidEmail},
		{name: "leading dot in domain", email: "user@.example.com", wantError: true, wantCode: errors.CodeInvalidEmail},
		{name: "consecutive dots in domain", email: "user@example..com", wantError: true, wantCode: errors.CodeInvalidEmail},
		{name: "missing local part", email: "@example.com", wantError: true, wantCode: errors.CodeInvalidEmail},
		{name: "exceeds max length of 255", email: strings.Repeat("a", 250) + "@example.com", wantError: true, wantCode: errors.CodeInvalidEmail},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEmail(tc.email)
			if !tc.wantError {
				if err != nil {
					t.Fatalf("ValidateEmail(%q) unexpected error: %v", tc.email, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateEmail(%q) expected error, got nil", tc.email)
			}
			var appErr *errors.Error
			if !errors.As(err, &appErr) {
				t.Fatalf("ValidateEmail(%q) expected *errors.Error, got %T", tc.email, err)
			}
			if appErr.Code() != tc.wantCode {
				t.Fatalf("ValidateEmail(%q) error code = %v; want %v", tc.email, appErr.Code(), tc.wantCode)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	valid64Hex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{name: "valid 64 hex characters", token: valid64Hex, wantError: false},
		{name: "uppercase valid 64 hex characters", token: strings.ToUpper(valid64Hex), wantError: false},
		{name: "empty token", token: "", wantError: true},
		{name: "too short token (63 chars)", token: valid64Hex[:63], wantError: true},
		{name: "too long token (65 chars)", token: valid64Hex + "a", wantError: true},
		{name: "non-hex character g", token: "g" + valid64Hex[1:], wantError: true},
		{name: "non-hex character z", token: valid64Hex[:63] + "z", wantError: true},
		{name: "special symbols in token", token: valid64Hex[:60] + "!@#$", wantError: true},
		{name: "spaces in token", token: valid64Hex[:63] + " ", wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateToken(tc.token)
			if !tc.wantError {
				if err != nil {
					t.Fatalf("ValidateToken(%q) unexpected error: %v", tc.token, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateToken(%q) expected error, got nil", tc.token)
			}
			var appErr *errors.Error
			if !errors.As(err, &appErr) {
				t.Fatalf("ValidateToken(%q) expected *errors.Error, got %T", tc.token, err)
			}
			if appErr.Code() != errors.CodeInvalidToken {
				t.Fatalf("ValidateToken(%q) error code = %v; want %v", tc.token, appErr.Code(), errors.CodeInvalidToken)
			}
		})
	}
}

func TestRequestDTOValidation(t *testing.T) {
	validToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	t.Run("SignupRequest", func(t *testing.T) {
		validReq := SignupRequest{Email: "user@example.com", Password: "SecurePassword123"}
		if err := validReq.Validate(); err != nil {
			t.Fatalf("SignupRequest.Validate() unexpected error: %v", err)
		}

		invalidEmailReq := SignupRequest{Email: "invalid-email", Password: "SecurePassword123"}
		err := invalidEmailReq.Validate()
		if err == nil {
			t.Fatal("SignupRequest.Validate() expected error for invalid email")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidEmail {
			t.Fatalf("SignupRequest.Validate() got error code %v, want %v", appErr.Code(), errors.CodeInvalidEmail)
		}

		emptyPasswordReq := SignupRequest{Email: "user@example.com", Password: ""}
		err = emptyPasswordReq.Validate()
		if err == nil {
			t.Fatal("SignupRequest.Validate() expected error for empty password")
		}
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeValidationError {
			t.Fatalf("SignupRequest.Validate() got error code %v, want %v", appErr.Code(), errors.CodeValidationError)
		}
	})

	t.Run("LoginRequest", func(t *testing.T) {
		validReq := LoginRequest{Email: "user@example.com", Password: "SecurePassword123"}
		if err := validReq.Validate(); err != nil {
			t.Fatalf("LoginRequest.Validate() unexpected error: %v", err)
		}

		invalidEmailReq := LoginRequest{Email: "invalid-email", Password: "SecurePassword123"}
		err := invalidEmailReq.Validate()
		if err == nil {
			t.Fatal("LoginRequest.Validate() expected error for invalid email")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidEmail {
			t.Fatalf("LoginRequest.Validate() got error code %v, want %v", appErr.Code(), errors.CodeInvalidEmail)
		}

		emptyPasswordReq := LoginRequest{Email: "user@example.com", Password: ""}
		err = emptyPasswordReq.Validate()
		if err == nil {
			t.Fatal("LoginRequest.Validate() expected error for empty password")
		}
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeValidationError {
			t.Fatalf("LoginRequest.Validate() got error code %v, want %v", appErr.Code(), errors.CodeValidationError)
		}
	})

	t.Run("VerifyEmailRequest", func(t *testing.T) {
		validReq := VerifyEmailRequest{Token: validToken}
		if err := validReq.Validate(); err != nil {
			t.Fatalf("VerifyEmailRequest.Validate() unexpected error: %v", err)
		}

		invalidReq := VerifyEmailRequest{Token: "short-token"}
		err := invalidReq.Validate()
		if err == nil {
			t.Fatal("VerifyEmailRequest.Validate() expected error")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidToken {
			t.Fatalf("VerifyEmailRequest.Validate() got error code %v, want %v", appErr.Code(), errors.CodeInvalidToken)
		}
	})

	t.Run("PasswordResetRequest", func(t *testing.T) {
		validReq := PasswordResetRequest{Email: "user@example.com"}
		if err := validReq.Validate(); err != nil {
			t.Fatalf("PasswordResetRequest.Validate() unexpected error: %v", err)
		}

		invalidReq := PasswordResetRequest{Email: "invalid-email"}
		err := invalidReq.Validate()
		if err == nil {
			t.Fatal("PasswordResetRequest.Validate() expected error")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidEmail {
			t.Fatalf("PasswordResetRequest.Validate() got error code %v, want %v", appErr.Code(), errors.CodeInvalidEmail)
		}
	})

	t.Run("PasswordResetConfirmRequest", func(t *testing.T) {
		validReq := PasswordResetConfirmRequest{Token: validToken, NewPassword: "NewSecurePassword123"}
		if err := validReq.Validate(); err != nil {
			t.Fatalf("PasswordResetConfirmRequest.Validate() unexpected error: %v", err)
		}

		invalidTokenReq := PasswordResetConfirmRequest{Token: "bad-token", NewPassword: "NewSecurePassword123"}
		err := invalidTokenReq.Validate()
		if err == nil {
			t.Fatal("PasswordResetConfirmRequest.Validate() expected error for bad token")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidToken {
			t.Fatalf("PasswordResetConfirmRequest.Validate() got error code %v, want %v", appErr.Code(), errors.CodeInvalidToken)
		}

		emptyPasswordReq := PasswordResetConfirmRequest{Token: validToken, NewPassword: ""}
		err = emptyPasswordReq.Validate()
		if err == nil {
			t.Fatal("PasswordResetConfirmRequest.Validate() expected error for empty password")
		}
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeValidationError {
			t.Fatalf("PasswordResetConfirmRequest.Validate() got error code %v, want %v", appErr.Code(), errors.CodeValidationError)
		}
	})
}

func TestResponseDTOJSONSerialization(t *testing.T) {
	testUUID := uuid.MustParse("a0000000-0000-0000-0000-000000000001")

	t.Run("LoginResponse", func(t *testing.T) {
		res := LoginResponse{UserID: testUUID}
		data, err := json.Marshal(res)
		if err != nil {
			t.Fatalf("json.Marshal(LoginResponse) err = %v", err)
		}
		expectedJSON := `{"user_id":"a0000000-0000-0000-0000-000000000001"}`
		if string(data) != expectedJSON {
			t.Fatalf("LoginResponse JSON = %s; want %s", string(data), expectedJSON)
		}

		var decoded LoginResponse
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal(LoginResponse) err = %v", err)
		}
		if decoded.UserID != testUUID {
			t.Fatalf("decoded.UserID = %v; want %v", decoded.UserID, testUUID)
		}
	})

	t.Run("MessageResponse", func(t *testing.T) {
		res := MessageResponse{Message: "email verified"}
		data, err := json.Marshal(res)
		if err != nil {
			t.Fatalf("json.Marshal(MessageResponse) err = %v", err)
		}
		expectedJSON := `{"message":"email verified"}`
		if string(data) != expectedJSON {
			t.Fatalf("MessageResponse JSON = %s; want %s", string(data), expectedJSON)
		}

		var decoded MessageResponse
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal(MessageResponse) err = %v", err)
		}
		if decoded.Message != "email verified" {
			t.Fatalf("decoded.Message = %q; want %q", decoded.Message, "email verified")
		}
	})
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "trims leading and trailing whitespace", input: "   user@example.com  ", want: "user@example.com"},
		{name: "lowercases uppercase email", input: "USER@EXAMPLE.COM", want: "user@example.com"},
		{name: "trims whitespace and lowercases mixed case", input: " \t User.Name+Tag@Sub.Domain.Co \n ", want: "user.name+tag@sub.domain.co"},
		{name: "preserves already normalized email", input: "user@example.com", want: "user@example.com"},
		{name: "handles empty string", input: "", want: ""},
		{name: "handles whitespace-only string", input: "   \t\n  ", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeEmail(tc.input)
			if got != tc.want {
				t.Fatalf("NormalizeEmail(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestLookupKey(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "lowercases mixed case", input: "Alice@Example.COM", want: "alice@example.com"},
		{name: "trims whitespace", input: "  Bob@Example.com  ", want: "bob@example.com"},
		{name: "single policy matches NormalizeEmail", input: "User.Name+Tag@Sub.Domain.Co", want: NormalizeEmail("User.Name+Tag@Sub.Domain.Co")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := LookupKey(tc.input); got != tc.want {
				t.Fatalf("LookupKey(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestRequestDTONormalize(t *testing.T) {
	t.Run("SignupRequest", func(t *testing.T) {
		req := SignupRequest{Email: "  Alice@Example.COM  ", Password: "Password123"}
		if got := req.NormalizedEmail(); got != "alice@example.com" {
			t.Fatalf("req.NormalizedEmail() = %q; want %q", got, "alice@example.com")
		}
		req.Normalize()
		if req.Email != "alice@example.com" {
			t.Fatalf("req.Normalize() failed: got %q, want %q", req.Email, "alice@example.com")
		}
	})

	t.Run("LoginRequest", func(t *testing.T) {
		req := LoginRequest{Email: "  Bob@Example.COM  ", Password: "Password123"}
		if got := req.NormalizedEmail(); got != "bob@example.com" {
			t.Fatalf("req.NormalizedEmail() = %q; want %q", got, "bob@example.com")
		}
		req.Normalize()
		if req.Email != "bob@example.com" {
			t.Fatalf("req.Normalize() failed: got %q, want %q", req.Email, "bob@example.com")
		}
	})

	t.Run("PasswordResetRequest", func(t *testing.T) {
		req := PasswordResetRequest{Email: "  Charlie@Example.COM  "}
		if got := req.NormalizedEmail(); got != "charlie@example.com" {
			t.Fatalf("req.NormalizedEmail() = %q; want %q", got, "charlie@example.com")
		}
		req.Normalize()
		if req.Email != "charlie@example.com" {
			t.Fatalf("req.Normalize() failed: got %q, want %q", req.Email, "charlie@example.com")
		}
	})
}
