package crypto

import (
	"strings"
	"testing"
)

func TestDefaultHashParams(t *testing.T) {
	params := DefaultHashParams()

	if params.Memory != 65536 {
		t.Errorf("Memory = %d; want 65536 (64 MiB RFC 9106 default)", params.Memory)
	}
	if params.Time != 3 {
		t.Errorf("Time = %d; want 3 (RFC 9106 default)", params.Time)
	}
	if params.Parallelism != 4 {
		t.Errorf("Parallelism = %d; want 4 (RFC 9106 default)", params.Parallelism)
	}
	if params.SaltLength != 16 {
		t.Errorf("SaltLength = %d; want 16 (128-bit RFC 9106 default)", params.SaltLength)
	}
	if params.KeyLength != 32 {
		t.Errorf("KeyLength = %d; want 32 (256-bit RFC 9106 default)", params.KeyLength)
	}
}

func TestHashPassword_DefaultParams(t *testing.T) {
	params := DefaultHashParams()
	password := "SecureP@ssword2026!"

	phc, err := HashPassword(password, params)
	if err != nil {
		t.Fatalf("HashPassword with DefaultHashParams failed: %v", err)
	}

	expectedPrefix := "$argon2id$v=19$m=65536,t=3,p=4$"
	if !strings.HasPrefix(phc, expectedPrefix) {
		t.Fatalf("PHC hash = %q; want prefix %q", phc, expectedPrefix)
	}

	match, err := VerifyPassword(password, phc)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !match {
		t.Fatal("expected password to match hash generated with DefaultHashParams")
	}

	wrongMatch, err := VerifyPassword("WrongPassword!", phc)
	if err != nil {
		t.Fatalf("VerifyPassword on wrong password failed: %v", err)
	}
	if wrongMatch {
		t.Fatal("expected wrong password to not match")
	}
}

func TestHashPassword_BoundaryParams(t *testing.T) {
	tests := []struct {
		name    string
		params  HashParams
		wantErr bool
	}{
		{
			name:    "valid minimal boundary (time=1, memory=1, parallelism=1, salt=16, key=1)",
			params:  HashParams{Memory: 1, Time: 1, Parallelism: 1, SaltLength: 16, KeyLength: 1},
			wantErr: false,
		},
		{
			name:    "time zero fails",
			params:  HashParams{Memory: 1024, Time: 0, Parallelism: 1, SaltLength: 16, KeyLength: 32},
			wantErr: true,
		},
		{
			name:    "parallelism zero fails",
			params:  HashParams{Memory: 1024, Time: 1, Parallelism: 0, SaltLength: 16, KeyLength: 32},
			wantErr: true,
		},
		{
			name:    "memory zero fails",
			params:  HashParams{Memory: 0, Time: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
			wantErr: true,
		},
		{
			name:    "salt length below 16 fails",
			params:  HashParams{Memory: 1024, Time: 1, Parallelism: 1, SaltLength: 15, KeyLength: 32},
			wantErr: true,
		},
		{
			name:    "salt length exactly 16 succeeds",
			params:  HashParams{Memory: 1024, Time: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
			wantErr: false,
		},
		{
			name:    "key length zero fails",
			params:  HashParams{Memory: 1024, Time: 1, Parallelism: 1, SaltLength: 16, KeyLength: 0},
			wantErr: true,
		},
		{
			name:    "key length 1 succeeds",
			params:  HashParams{Memory: 1024, Time: 1, Parallelism: 1, SaltLength: 16, KeyLength: 1},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := HashPassword("test-password", tt.params)
			if (err != nil) != tt.wantErr {
				t.Fatalf("HashPassword(%+v) err = %v; wantErr %v", tt.params, err, tt.wantErr)
			}
		})
	}
}
