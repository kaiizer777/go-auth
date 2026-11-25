package e2e_test

import (
	_ "embed"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm/schema"

	"github.com/kaiizer777/go-auth/db"
)

// sqliteSchema is the single sqlite DDL source for this package. The production
// migrations target Postgres only; see schema_sqlite.sql for why they cannot run
// under glebarez/sqlite.
//
//go:embed schema_sqlite.sql
var sqliteSchema string

// createTablePattern captures the table name and column body of a DDL table. The
// bodies below contain no ");" of their own, so the non-greedy match is exact.
var createTablePattern = regexp.MustCompile(`(?is)CREATE TABLE(?:\s+IF NOT EXISTS)?\s+(\w+)\s*\((.*?)\)\s*;`)

// tableConstraintKeywords open DDL lines that declare constraints, not columns.
var tableConstraintKeywords = map[string]bool{
	"CONSTRAINT": true,
	"FOREIGN":    true,
	"PRIMARY":    true,
	"UNIQUE":     true,
	"CHECK":      true,
}

// TestE2E_SQLiteSchemaMatchesModels fails loudly when schema_sqlite.sql drifts
// from db/models.go: SELECT * decodes a missing column as a zero value, so the
// suite would otherwise keep passing against an incomplete schema.
func TestE2E_SQLiteSchemaMatchesModels(t *testing.T) {
	cache := &sync.Map{}
	namer := schema.NamingStrategy{}
	expected := make(map[string][]string)
	for _, model := range []any{
		&db.User{}, &db.Session{}, &db.VerificationToken{}, &db.PasswordResetToken{},
		&db.OAuthAccount{}, &db.TotpSecret{}, &db.TotpUsedCode{}, &db.TwoFactorToken{},
	} {
		parsed, err := schema.Parse(model, cache, namer)
		if err != nil {
			t.Fatalf("parse %T: %v", model, err)
		}
		columns := make([]string, 0, len(parsed.Fields))
		for _, field := range parsed.Fields {
			columns = append(columns, field.DBName)
		}
		slices.Sort(columns)
		expected[parsed.Table] = columns
	}

	tables := createTablePattern.FindAllStringSubmatch(sqliteSchema, -1)
	if len(tables) == 0 {
		t.Fatal("schema_sqlite.sql declares no tables")
	}
	foundTables := make(map[string]bool, len(tables))
	for _, match := range tables {
		table, body := match[1], match[2]
		foundTables[table] = true
		model, known := expected[table]
		if !known {
			t.Errorf("table %q has no model in db/models.go", table)
			continue
		}
		if actual := sqliteColumns(body); !slices.Equal(actual, model) {
			t.Errorf("table %q columns = %v; db/models.go declares %v", table, actual, model)
		}
	}
	for table := range expected {
		if !foundTables[table] {
			t.Errorf("table %q from db/models.go is missing in schema_sqlite.sql", table)
		}
	}
}

// sqliteColumns returns the sorted column names declared in a CREATE TABLE body.
func sqliteColumns(body string) []string {
	var columns []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSuffix(strings.TrimSpace(line), ",")
		if line == "" {
			continue
		}
		name, _, _ := strings.Cut(line, " ")
		if tableConstraintKeywords[strings.ToUpper(name)] {
			continue
		}
		columns = append(columns, name)
	}
	slices.Sort(columns)
	return columns
}
