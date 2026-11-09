package db

import (
	"reflect"
	"testing"
)

func TestModelPrimaryKeyTags(t *testing.T) {
	models := []struct {
		name  string
		model any
	}{
		{name: "User", model: User{}},
		{name: "Session", model: Session{}},
		{name: "VerificationToken", model: VerificationToken{}},
		{name: "PasswordResetToken", model: PasswordResetToken{}},
	}

	expectedTag := `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`

	for _, tc := range models {
		t.Run(tc.name, func(t *testing.T) {
			field, ok := reflect.TypeOf(tc.model).FieldByName("ID")
			if !ok {
				t.Fatalf("model %s missing ID field", tc.name)
			}
			tag := field.Tag.Get("gorm")
			if tag != "primaryKey;type:uuid;default:uuid_generate_v4()" {
				t.Fatalf("model %s ID gorm tag = %q; want %q", tc.name, tag, expectedTag)
			}
		})
	}
}
