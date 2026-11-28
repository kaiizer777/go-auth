package db

import (
	"strings"
	"testing"

	gormsqlite "github.com/glebarez/sqlite"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/errors"
)

func TestClaimKey_NormalisesValidAddresses(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"User@Example.COM", "user@example.com"},
		{"  user+tag@sub.example.com\t", "user+tag@sub.example.com"},
		{"first.last@example.co", "first.last@example.co"},
		{"USER_NAME@EXAMPLE.COM", "user_name@example.com"},
		{`"jane"@example.com`, `"jane"@example.com`},
		// RFC 5322 atext the rest of the system accepts via ValidateEmail: the claim
		// key must accept it too, or those addresses can never be claimed.
		{"o'brien@example.com", "o'brien@example.com"},
		{"admin$@example.com", "admin$@example.com"},
		{"a{b@example.com", "a{b@example.com"},
		// 255 bytes after normalisation is the boundary the column holds.
		{strings.Repeat("a", 243) + "@example.com", strings.Repeat("a", 243) + "@example.com"},
	} {
		key, err := ClaimKey(tc.in)
		if err != nil {
			t.Errorf("ClaimKey(%q) = %v; want %q", tc.in, err, tc.want)
			continue
		}
		if key != tc.want {
			t.Errorf("ClaimKey(%q) = %q; want %q", tc.in, key, tc.want)
		}
	}
	// An empty address claims nothing and is not an error.
	if key, err := ClaimKey(" \t\n"); err != nil || key != "" {
		t.Errorf("ClaimKey(blank) = (%q, %v); want (\"\", nil)", key, err)
	}
}

// foldExpander is U+023A (2 bytes) whose lowercase form U+2C65 is 3 bytes, so
// NormalizeEmail can make an address longer than its stored form.
const foldExpander = "Ⱥ"

// overlongFoldedAddress is 255 bytes raw and 256 after folding: foldExpander is
// 2 bytes and its lowercase form is 3.
func overlongFoldedAddress() string {
	const domain = "@example.com"
	return strings.Repeat("a", 255-len(domain)-len(foldExpander)) + foldExpander + domain
}

// TestValidateEmailAndClaimKeyAgree pins the predicate: an address the system
// accepts is always claimable, and a key ClaimKey rejects was already rejected by
// ValidateEmail. Folding expansion is the case that used to diverge.
func TestValidateEmailAndClaimKeyAgree(t *testing.T) {
	const domain = "@example.com"
	cases := []struct {
		name     string
		addr     string
		accepted bool
	}{
		{name: "plain", addr: "user@example.com", accepted: true},
		{name: "ascii max length", addr: strings.Repeat("a", 255-len(domain)) + domain, accepted: true},
		{name: "ascii over length", addr: strings.Repeat("a", 256-len(domain)) + domain, accepted: false},
		{name: "folding expansion fits", addr: strings.Repeat("a", 254-len(domain)-len(foldExpander)) + foldExpander + domain, accepted: true},
		{name: "folding expansion crosses the limit", addr: overlongFoldedAddress(), accepted: false},
		{name: "combining characters", addr: "e\u0301milie@example.com", accepted: true},
		{name: "quoted local part", addr: `"jane"@example.com`, accepted: true},
		{name: "plus addressing", addr: "user+tag@example.com", accepted: true},
		{name: "uppercase", addr: "USER@EXAMPLE.COM", accepted: true},
		{name: "surrounding whitespace", addr: " user@example.com ", accepted: false},
		{name: "not an address", addr: "no-at.example.com", accepted: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verr := ValidateClaimableEmail(tc.addr)
			if (verr == nil) != tc.accepted {
				t.Fatalf("ValidateClaimableEmail(%q) = %v; want accepted=%v", tc.addr, verr, tc.accepted)
			}
			key, kerr := ClaimKey(tc.addr)
			if verr == nil && kerr != nil {
				t.Fatalf("accepted address %q is not claimable: %v", tc.addr, kerr)
			}
			if kerr != nil && verr == nil {
				t.Fatalf("ClaimKey(%q) failed but ValidateEmail accepted it", tc.addr)
			}
			if kerr == nil && len(key) > claimKeyMaxLength {
				t.Fatalf("claim key for %q is %d bytes; limit is %d", tc.addr, len(key), claimKeyMaxLength)
			}
		})
	}
}

func TestClaimKey_RejectsNonAddressValues(t *testing.T) {
	for _, bad := range []string{
		"user@@example.com",
		"no-at.example.com",
		"@example.com",
		"user@",
		"user@example",
		"user@.example.com",
		"user@example..com",
		"user@example.com.",
		"user name@example.com",
		"user@exa\tmple.com",
		strings.Repeat("a", 244) + "@example.com", // 256 bytes
	} {
		if _, err := ClaimKey(bad); !errors.Is(err, errors.ErrInvalidEmail) {
			t.Errorf("ClaimKey(%q) err = %v; want ErrInvalidEmail", bad, err)
		}
	}
}

// TestValidateClaimableEmailScopesTheFoldLimit pins where the folded-length rule
// applies: only paths that create a claim reject the address. Login and password
// reset requests keep accepting an existing account whose stored address no longer
// fits a new claim key.
func TestValidateClaimableEmailScopesTheFoldLimit(t *testing.T) {
	long := overlongFoldedAddress()
	if err := ValidateEmail(long); err != nil {
		t.Fatalf("ValidateEmail(%q) = %v; a stored address must still be accepted", long, err)
	}
	var appErr *errors.Error
	if err := ValidateClaimableEmail(long); !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidEmail {
		t.Fatalf("ValidateClaimableEmail(%q) = %v; want CodeInvalidEmail", long, err)
	}
	if err := (LoginRequest{Email: long, Password: "ValidPassword123#"}).Validate(); err != nil {
		t.Errorf("LoginRequest.Validate(%q) = %v; an existing account must keep logging in", long, err)
	}
	if err := (PasswordResetRequest{Email: long}).Validate(); err != nil {
		t.Errorf("PasswordResetRequest.Validate(%q) = %v; an existing account must keep requesting a reset", long, err)
	}
	if err := (SignupRequest{Email: long, Password: "ValidPassword123#"}).Validate(); !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidEmail {
		t.Errorf("SignupRequest.Validate(%q) = %v; a new claim must be rejected with CodeInvalidEmail", long, err)
	}
}

// TestClaimedEmailMySQLKeyUsesBinaryCollation pins the AutoMigrate type: MySQL's
// default collation folds case and accents, so the claim key needs an explicit
// binary collation there. PostgreSQL and SQLite compare the varchar byte for byte.
func TestClaimedEmailMySQLKeyUsesBinaryCollation(t *testing.T) {
	mysqlDB := &gorm.DB{Config: &gorm.Config{Dialector: gormmysql.New(gormmysql.Config{DSN: "user:pass@tcp(127.0.0.1:3306)/x"})}}
	if got := (ClaimedEmail{}).GormDBDataType(mysqlDB, nil); !strings.Contains(got, "COLLATE utf8mb4_bin") {
		t.Errorf("mysql claim key type = %q; want an explicit utf8mb4_bin collation", got)
	}
	sqliteDB := &gorm.DB{Config: &gorm.Config{Dialector: gormsqlite.Open(":memory:")}}
	if got := (ClaimedEmail{}).GormDBDataType(sqliteDB, nil); strings.Contains(got, "COLLATE") {
		t.Errorf("sqlite claim key type = %q; want the plain varchar type", got)
	}
}
