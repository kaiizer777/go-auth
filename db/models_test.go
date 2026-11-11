package db

import (
	"reflect"
	"testing"
)

func TestModelPrimaryKeyTags(t *testing.T) {
	uuidPKModels := []struct {
		name        string
		model       any
		expectedTag string
	}{
		{name: "User", model: User{}, expectedTag: "primaryKey;type:uuid;default:uuid_generate_v4()"},
		{name: "Session", model: Session{}, expectedTag: "primaryKey;type:uuid;default:uuid_generate_v4()"},
	}

	for _, tc := range uuidPKModels {
		t.Run(tc.name, func(t *testing.T) {
			field, ok := reflect.TypeOf(tc.model).FieldByName("ID")
			if !ok {
				t.Fatalf("model %s missing ID field", tc.name)
			}
			tag := field.Tag.Get("gorm")
			if tag != tc.expectedTag {
				t.Fatalf("model %s ID gorm tag = %q; want %q", tc.name, tag, tc.expectedTag)
			}
		})
	}

	byteaPKModels := []struct {
		name        string
		model       any
		expectedTag string
	}{
		{name: "VerificationToken", model: VerificationToken{}, expectedTag: "primaryKey;column:token_hash;type:bytea"},
		{name: "PasswordResetToken", model: PasswordResetToken{}, expectedTag: "primaryKey;column:token_hash;type:bytea"},
	}

	for _, tc := range byteaPKModels {
		t.Run(tc.name, func(t *testing.T) {
			field, ok := reflect.TypeOf(tc.model).FieldByName("TokenHash")
			if !ok {
				t.Fatalf("model %s missing TokenHash field", tc.name)
			}
			if field.Type != reflect.TypeOf([]byte(nil)) {
				t.Fatalf("model %s TokenHash type = %v; want []byte", tc.name, field.Type)
			}
			tag := field.Tag.Get("gorm")
			if tag != tc.expectedTag {
				t.Fatalf("model %s TokenHash gorm tag = %q; want %q", tc.name, tag, tc.expectedTag)
			}
		})
	}
}

func TestTokenModelsOmitDeprecatedFields(t *testing.T) {
	tokenModels := []struct {
		name  string
		model any
	}{
		{name: "VerificationToken", model: VerificationToken{}},
		{name: "PasswordResetToken", model: PasswordResetToken{}},
	}

	for _, tc := range tokenModels {
		t.Run(tc.name, func(t *testing.T) {
			typ := reflect.TypeOf(tc.model)
			if _, ok := typ.FieldByName("ID"); ok {
				t.Fatalf("model %s must not have an ID field", tc.name)
			}
			if _, ok := typ.FieldByName("Used"); ok {
				t.Fatalf("model %s must not have a Used field", tc.name)
			}
		})
	}
}

func TestModelTableNames(t *testing.T) {
	tests := []struct {
		name      string
		tableName string
		want      string
	}{
		{name: "User", tableName: User{}.TableName(), want: "users"},
		{name: "Session", tableName: Session{}.TableName(), want: "sessions"},
		{name: "VerificationToken", tableName: VerificationToken{}.TableName(), want: "verification_tokens"},
		{name: "PasswordResetToken", tableName: PasswordResetToken{}.TableName(), want: "password_reset_tokens"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.tableName != tc.want {
				t.Fatalf("%s.TableName() = %q; want %q", tc.name, tc.tableName, tc.want)
			}
		})
	}
}

func TestModelUserIDIndexTags(t *testing.T) {
	models := []struct {
		name        string
		model       any
		expectedTag string
	}{
		{name: "Session", model: Session{}, expectedTag: "type:uuid;not null;index:idx_sessions_user_id"},
		{name: "VerificationToken", model: VerificationToken{}, expectedTag: "type:uuid;not null;index:idx_verification_tokens_user_id"},
		{name: "PasswordResetToken", model: PasswordResetToken{}, expectedTag: "type:uuid;not null;index:idx_password_reset_tokens_user_id"},
	}

	for _, tc := range models {
		t.Run(tc.name, func(t *testing.T) {
			field, ok := reflect.TypeOf(tc.model).FieldByName("UserID")
			if !ok {
				t.Fatalf("model %s missing UserID field", tc.name)
			}
			tag := field.Tag.Get("gorm")
			if tag != tc.expectedTag {
				t.Fatalf("model %s UserID gorm tag = %q; want %q", tc.name, tag, tc.expectedTag)
			}
		})
	}
}

