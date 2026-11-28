package integration_test

import (
	"testing"

	"github.com/kaiizer777/go-auth/tests/oauthmock"
)

// TestOAuthFixtureSchemaMirrorsClaimMigration pins the sqlite fixture used by the
// OAuth HTTP tests to migration 000014: a claim must carry a cascading owner
// foreign key and the owner index. A fixture that drifts would let the suite pass
// against a schema production does not have.
func TestOAuthFixtureSchemaMirrorsClaimMigration(t *testing.T) {
	_, database, _ := setupOAuthFlow(t, map[string]*oauthmock.Mock{})

	var columns []struct {
		Name string `gorm:"column:name"`
		Type string `gorm:"column:type"`
		PK   int    `gorm:"column:pk"`
	}
	if err := database.Raw("PRAGMA table_info('claimed_emails')").Scan(&columns).Error; err != nil {
		t.Fatalf("table_info: %v", err)
	}
	wantColumns := map[string]bool{
		"email": false, "owner_user_id": false, "verified": false, "created_at": false, "updated_at": false,
	}
	for _, column := range columns {
		if _, ok := wantColumns[column.Name]; !ok {
			t.Errorf("unexpected claimed_emails column %q", column.Name)
			continue
		}
		wantColumns[column.Name] = true
		if column.Name == "email" && column.PK != 1 {
			t.Errorf("claimed_emails.email pk = %d; want 1", column.PK)
		}
	}
	for name, seen := range wantColumns {
		if !seen {
			t.Errorf("claimed_emails is missing column %q", name)
		}
	}

	var fks []struct {
		Table    string `gorm:"column:table"`
		From     string `gorm:"column:from"`
		To       string `gorm:"column:to"`
		OnDelete string `gorm:"column:on_delete"`
	}
	if err := database.Raw("PRAGMA foreign_key_list('claimed_emails')").Scan(&fks).Error; err != nil {
		t.Fatalf("foreign_key_list: %v", err)
	}
	foundFK := false
	for _, fk := range fks {
		if fk.Table == "users" && fk.From == "owner_user_id" && fk.To == "id" && fk.OnDelete == "CASCADE" {
			foundFK = true
		}
	}
	if !foundFK {
		t.Fatalf("claimed_emails has no owner_user_id -> users(id) ON DELETE CASCADE foreign key: %+v", fks)
	}

	var indexes []struct {
		Name string `gorm:"column:name"`
	}
	if err := database.Raw("PRAGMA index_list('claimed_emails')").Scan(&indexes).Error; err != nil {
		t.Fatalf("index_list: %v", err)
	}
	foundIndex := false
	for _, index := range indexes {
		if index.Name == "idx_claimed_emails_owner_user_id" {
			foundIndex = true
		}
	}
	if !foundIndex {
		t.Fatalf("claimed_emails is missing idx_claimed_emails_owner_user_id: %+v", indexes)
	}
}
