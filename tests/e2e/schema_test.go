package e2e_test

import _ "embed"

// sqliteSchema is the single sqlite DDL source for this package. The production
// migrations target Postgres only; see schema_sqlite.sql for why they cannot run
// under glebarez/sqlite.
//
//go:embed schema_sqlite.sql
var sqliteSchema string
