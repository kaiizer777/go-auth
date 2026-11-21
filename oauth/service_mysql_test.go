package oauth

import (
	stderrors "errors"
	"testing"

	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/errors"
)

func TestIsUniqueViolation_MySQL(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "gorm ErrDuplicatedKey",
			err:  gorm.ErrDuplicatedKey,
			want: true,
		},
		{
			name: "ErrOAuthAccountAlreadyLinked domain error",
			err:  errors.ErrOAuthAccountAlreadyLinked,
			want: true,
		},
		{
			name: "mysql 1062 driver error",
			err:  &mysql.MySQLError{Number: 1062, Message: "Duplicate entry 'provider-123' for key 'uq_oauth_accounts_provider_uid'"},
			want: true,
		},
		{
			name: "mysql other error number",
			err:  &mysql.MySQLError{Number: 1064, Message: "You have an error in your SQL syntax"},
			want: false,
		},
		{
			name: "raw error containing 1062",
			err:  stderrors.New("Error 1062: Duplicate entry 'a' for key 'PRIMARY'"),
			want: true,
		},
		{
			name: "raw error containing duplicate entry",
			err:  stderrors.New("duplicate entry detected in unique constraint"),
			want: true,
		},
		{
			name: "postgres 23505",
			err:  stderrors.New("ERROR: duplicate key value violates unique constraint (SQLSTATE 23505)"),
			want: true,
		},
		{
			name: "sqlite unique constraint failed",
			err:  stderrors.New("UNIQUE constraint failed: oauth_accounts.provider_id"),
			want: true,
		},
		{
			name: "unrelated error",
			err:  stderrors.New("connection reset by peer"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUniqueViolation(tt.err)
			if got != tt.want {
				t.Errorf("isUniqueViolation() = %v; want %v", got, tt.want)
			}
		})
	}
}
