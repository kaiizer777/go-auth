package db

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestModelPrimaryKeyTags(t *testing.T) {
	uuidPKModels := []struct {
		name        string
		model       any
		expectedTag string
	}{
		{name: "User", model: User{}, expectedTag: "primaryKey;type:varchar(36)"},
		{name: "Session", model: Session{}, expectedTag: "primaryKey;type:varchar(36)"},
		{name: "OAuthAccount", model: OAuthAccount{}, expectedTag: "primaryKey;type:varchar(36)"},
		{name: "TotpSecret", model: TotpSecret{}, expectedTag: "primaryKey;type:varchar(36)"},
		{name: "TotpUsedCode", model: TotpUsedCode{}, expectedTag: "primaryKey;type:varchar(36)"},
		{name: "TwoFactorToken", model: TwoFactorToken{}, expectedTag: "primaryKey;type:varchar(36)"},
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
		{name: "VerificationToken", model: VerificationToken{}, expectedTag: "primaryKey;column:token_hash"},
		{name: "PasswordResetToken", model: PasswordResetToken{}, expectedTag: "primaryKey;column:token_hash"},
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
		{name: "Session", model: Session{}, expectedTag: "type:varchar(36);not null;index:idx_sessions_user_id"},
		{name: "VerificationToken", model: VerificationToken{}, expectedTag: "type:varchar(36);not null;index:idx_verification_tokens_user_id"},
		{name: "PasswordResetToken", model: PasswordResetToken{}, expectedTag: "type:varchar(36);not null;index:idx_password_reset_tokens_user_id"},
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

func TestSessionModelTagsAndDeprecatedFields(t *testing.T) {
	typ := reflect.TypeOf(Session{})

	field, ok := typ.FieldByName("IDHash")
	if !ok {
		t.Fatal("Session missing IDHash field")
	}
	expectedIDHashTag := "column:id_hash;type:char(64);uniqueIndex;not null"
	if tag := field.Tag.Get("gorm"); tag != expectedIDHashTag {
		t.Errorf("Session IDHash tag = %q; want %q", tag, expectedIDHashTag)
	}

	field, ok = typ.FieldByName("SessionType")
	if !ok {
		t.Fatal("Session missing SessionType field")
	}
	expectedSessionTypeTag := "type:varchar(10);not null;default:'cookie'"
	if tag := field.Tag.Get("gorm"); tag != expectedSessionTypeTag {
		t.Errorf("Session SessionType tag = %q; want %q", tag, expectedSessionTypeTag)
	}

	deprecated := []string{"TokenHash", "ExpiresAt", "IdleExpiresAt", "UpdatedAt", "CSRFToken"}
	for _, name := range deprecated {
		if _, exists := typ.FieldByName(name); exists {
			t.Errorf("Session must not have deprecated field %q", name)
		}
	}
}

func TestCredentialVersionModelTags(t *testing.T) {
	models := []struct {
		name        string
		model       any
		expectedTag string
	}{
		{name: "User", model: User{}, expectedTag: "not null;default:0"},
		{name: "Session", model: Session{}, expectedTag: "not null;default:0"},
	}

	for _, tc := range models {
		t.Run(tc.name, func(t *testing.T) {
			field, ok := reflect.TypeOf(tc.model).FieldByName("CredentialVersion")
			if !ok {
				t.Fatalf("model %s missing CredentialVersion field", tc.name)
			}
			if field.Type.Kind() != reflect.Int {
				t.Fatalf("model %s CredentialVersion type = %v; want int", tc.name, field.Type)
			}
			if tag := field.Tag.Get("gorm"); tag != tc.expectedTag {
				t.Errorf("model %s CredentialVersion gorm tag = %q; want %q", tc.name, tag, tc.expectedTag)
			}
		})
	}
}

func TestUserPasswordHashJSONOmissionAndLogValuer(t *testing.T) {
	field, ok := reflect.TypeOf(User{}).FieldByName("PasswordHash")
	if !ok {
		t.Fatal("User missing PasswordHash field")
	}
	if tag := field.Tag.Get("json"); tag != "-" {
		t.Fatalf("User PasswordHash json tag = %q; want \"-\"", tag)
	}

	rawHash := "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$9s"
	u := User{
		ID:                uuid.New(),
		Email:             "secure@example.com",
		PasswordHash:      rawHash,
		CredentialVersion: 1,
		EmailVerified:     true,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	data, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("json.Marshal(User) failed: %v", err)
	}
	if strings.Contains(string(data), rawHash) || strings.Contains(string(data), "password_hash") {
		t.Fatalf("json.Marshal leaked password hash: %s", string(data))
	}

	val := u.LogValue()
	attrs := val.Group()
	var foundRedacted bool
	for _, a := range attrs {
		if a.Key == "password_hash" {
			if a.Value.String() != "[REDACTED]" {
				t.Fatalf("expected [REDACTED], got %s", a.Value.String())
			}
			foundRedacted = true
		}
	}
	if !foundRedacted {
		t.Fatal("LogValue() did not contain password_hash attribute")
	}

	vt := VerificationToken{
		TokenHash: []byte("sensitive_hash"),
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	vtVal := vt.LogValue()
	for _, a := range vtVal.Group() {
		if a.Key == "token_hash" && a.Value.String() != "[REDACTED]" {
			t.Fatalf("VerificationToken LogValue expected [REDACTED], got %s", a.Value.String())
		}
	}

	prt := PasswordResetToken{
		TokenHash: []byte("sensitive_hash"),
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	prtVal := prt.LogValue()
	for _, a := range prtVal.Group() {
		if a.Key == "token_hash" && a.Value.String() != "[REDACTED]" {
			t.Fatalf("PasswordResetToken LogValue expected [REDACTED], got %s", a.Value.String())
		}
	}
}

func TestTokenAndSessionHashesJSONOmission(t *testing.T) {
	// Verify Session.IDHash json:"-"
	sessField, ok := reflect.TypeOf(Session{}).FieldByName("IDHash")
	if !ok {
		t.Fatal("Session missing IDHash field")
	}
	if tag := sessField.Tag.Get("json"); tag != "-" {
		t.Errorf("Session IDHash json tag = %q; want \"-\"", tag)
	}

	rawIDHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sess := Session{
		ID:                uuid.New(),
		UserID:            uuid.New(),
		IDHash:            rawIDHash,
		SessionType:       SessionTypeBearer,
		LastActiveAt:      time.Now(),
		AbsoluteExpiresAt: time.Now().Add(time.Hour),
	}
	sessData, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal(Session) failed: %v", err)
	}
	if strings.Contains(string(sessData), rawIDHash) || strings.Contains(string(sessData), "id_hash") || strings.Contains(string(sessData), "IDHash") {
		t.Errorf("json.Marshal(Session) leaked IDHash: %s", string(sessData))
	}

	// Verify VerificationToken.TokenHash json:"-"
	vtField, ok := reflect.TypeOf(VerificationToken{}).FieldByName("TokenHash")
	if !ok {
		t.Fatal("VerificationToken missing TokenHash field")
	}
	if tag := vtField.Tag.Get("json"); tag != "-" {
		t.Errorf("VerificationToken TokenHash json tag = %q; want \"-\"", tag)
	}

	rawVTHash := []byte("verification_token_secret_hash_bytes")
	vt := VerificationToken{
		TokenHash: rawVTHash,
		UserID:    uuid.New(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	vtData, err := json.Marshal(vt)
	if err != nil {
		t.Fatalf("json.Marshal(VerificationToken) failed: %v", err)
	}
	if strings.Contains(string(vtData), "TokenHash") || strings.Contains(string(vtData), "token_hash") {
		t.Errorf("json.Marshal(VerificationToken) leaked TokenHash: %s", string(vtData))
	}

	// Verify PasswordResetToken.TokenHash json:"-"
	prtField, ok := reflect.TypeOf(PasswordResetToken{}).FieldByName("TokenHash")
	if !ok {
		t.Fatal("PasswordResetToken missing TokenHash field")
	}
	if tag := prtField.Tag.Get("json"); tag != "-" {
		t.Errorf("PasswordResetToken TokenHash json tag = %q; want \"-\"", tag)
	}

	rawPRTHash := []byte("reset_token_secret_hash_bytes")
	prt := PasswordResetToken{
		TokenHash: rawPRTHash,
		UserID:    uuid.New(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	prtData, err := json.Marshal(prt)
	if err != nil {
		t.Fatalf("json.Marshal(PasswordResetToken) failed: %v", err)
	}
	if strings.Contains(string(prtData), "TokenHash") || strings.Contains(string(prtData), "token_hash") {
		t.Errorf("json.Marshal(PasswordResetToken) leaked TokenHash: %s", string(prtData))
	}
}

func TestTOTPModels_TableNameAndMasking(t *testing.T) {
	t.Parallel()

	// 1. TableName tests
	if (TotpSecret{}).TableName() != "totp_secrets" {
		t.Errorf("TotpSecret.TableName() = %q; want \"totp_secrets\"", (TotpSecret{}).TableName())
	}
	if (TotpUsedCode{}).TableName() != "totp_used_codes" {
		t.Errorf("TotpUsedCode.TableName() = %q; want \"totp_used_codes\"", (TotpUsedCode{}).TableName())
	}
	if (TwoFactorToken{}).TableName() != "two_factor_tokens" {
		t.Errorf("TwoFactorToken.TableName() = %q; want \"two_factor_tokens\"", (TwoFactorToken{}).TableName())
	}

	// 2. Invariant: TwoFactorToken MUST NOT have DeletedAt (hard delete only)
	if _, ok := reflect.TypeOf(TwoFactorToken{}).FieldByName("DeletedAt"); ok {
		t.Fatal("CRITICAL INVARIANT VIOLATION: TwoFactorToken contains DeletedAt; soft deletes are banned on security tokens")
	}

	// 3. JSON tags check: sensitive fields omitted
	secretField, ok := reflect.TypeOf(TotpSecret{}).FieldByName("EncryptedSecret")
	if !ok || secretField.Tag.Get("json") != "-" {
		t.Errorf("TotpSecret EncryptedSecret json tag = %q; want \"-\"", secretField.Tag.Get("json"))
	}

	backupCodesField, ok := reflect.TypeOf(TotpSecret{}).FieldByName("BackupCodes")
	if !ok || backupCodesField.Tag.Get("json") != "-" {
		t.Errorf("TotpSecret BackupCodes json tag = %q; want \"-\"", backupCodesField.Tag.Get("json"))
	}

	codeHashField, ok := reflect.TypeOf(TotpUsedCode{}).FieldByName("CodeHash")
	if !ok || codeHashField.Tag.Get("json") != "-" {
		t.Errorf("TotpUsedCode CodeHash json tag = %q; want \"-\"", codeHashField.Tag.Get("json"))
	}

	tokenHashField, ok := reflect.TypeOf(TwoFactorToken{}).FieldByName("TokenHash")
	if !ok || tokenHashField.Tag.Get("json") != "-" {
		t.Errorf("TwoFactorToken TokenHash json tag = %q; want \"-\"", tokenHashField.Tag.Get("json"))
	}

	// Verify json.Marshal does not leak EncryptedSecret or BackupCodes
	tsMarshal := TotpSecret{
		ID:              uuid.New(),
		UserID:          uuid.New(),
		EncryptedSecret: []byte("super-secret-totp-blob"),
		BackupCodes:     []byte(`["argon2id-phc-hash"]`),
		Enabled:         true,
	}
	tsData, err := json.Marshal(tsMarshal)
	if err != nil {
		t.Fatalf("json.Marshal(tsMarshal) failed: %v", err)
	}
	if strings.Contains(string(tsData), "EncryptedSecret") || strings.Contains(string(tsData), "super-secret-totp-blob") {
		t.Errorf("TotpSecret JSON marshaling leaked EncryptedSecret: %s", string(tsData))
	}
	if strings.Contains(string(tsData), "BackupCodes") || strings.Contains(string(tsData), "argon2id-phc-hash") {
		t.Errorf("TotpSecret JSON marshaling leaked BackupCodes: %s", string(tsData))
	}

	// 4. slog.LogValuer masking tests
	ts := TotpSecret{
		ID:              uuid.New(),
		UserID:          uuid.New(),
		EncryptedSecret: []byte("super-secret-totp-blob"),
		BackupCodes:     []byte(`["argon2id-phc-hash"]`),
		Enabled:         true,
	}
	for _, a := range ts.LogValue().Group() {
		if a.Key == "encrypted_secret" && a.Value.String() != "[REDACTED]" {
			t.Errorf("TotpSecret EncryptedSecret not redacted: %s", a.Value.String())
		}
		if a.Key == "backup_codes" && a.Value.String() != "[REDACTED]" {
			t.Errorf("TotpSecret BackupCodes not redacted: %s", a.Value.String())
		}
	}

	tuc := TotpUsedCode{
		ID:       uuid.New(),
		UserID:   uuid.New(),
		CodeHash: []byte("sha256-code-hash"),
		UsedAt:   time.Now(),
	}
	for _, a := range tuc.LogValue().Group() {
		if a.Key == "code_hash" && a.Value.String() != "[REDACTED]" {
			t.Errorf("TotpUsedCode CodeHash not redacted: %s", a.Value.String())
		}
	}

	tft := TwoFactorToken{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		TokenHash: []byte("sha256-two-factor-token-hash"),
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Attempts:  2,
	}
	for _, a := range tft.LogValue().Group() {
		if a.Key == "token_hash" && a.Value.String() != "[REDACTED]" {
			t.Errorf("TwoFactorToken TokenHash not redacted: %s", a.Value.String())
		}
	}
}

func TestBeforeCreateUUIDGeneration(t *testing.T) {
	t.Parallel()

	// 1. User
	u := &User{}
	if err := u.BeforeCreate(nil); err != nil || u.ID == uuid.Nil {
		t.Fatalf("User.BeforeCreate failed to generate UUID: %v, ID=%v", err, u.ID)
	}
	fixedID := uuid.New()
	u2 := &User{ID: fixedID}
	if err := u2.BeforeCreate(nil); err != nil || u2.ID != fixedID {
		t.Fatalf("User.BeforeCreate overwrote preset ID: %v", u2.ID)
	}

	// 2. Session
	s := &Session{}
	if err := s.BeforeCreate(nil); err != nil || s.ID == uuid.Nil {
		t.Fatalf("Session.BeforeCreate failed to generate UUID: %v, ID=%v", err, s.ID)
	}

	// 3. OAuthAccount
	o := &OAuthAccount{}
	if err := o.BeforeCreate(nil); err != nil || o.ID == uuid.Nil {
		t.Fatalf("OAuthAccount.BeforeCreate failed to generate UUID: %v, ID=%v", err, o.ID)
	}

	// 4. TotpSecret
	ts := &TotpSecret{}
	if err := ts.BeforeCreate(nil); err != nil || ts.ID == uuid.Nil {
		t.Fatalf("TotpSecret.BeforeCreate failed to generate UUID: %v, ID=%v", err, ts.ID)
	}

	// 5. TotpUsedCode
	tuc := &TotpUsedCode{}
	if err := tuc.BeforeCreate(nil); err != nil || tuc.ID == uuid.Nil {
		t.Fatalf("TotpUsedCode.BeforeCreate failed to generate UUID: %v, ID=%v", err, tuc.ID)
	}

	// 6. TwoFactorToken
	tft := &TwoFactorToken{}
	if err := tft.BeforeCreate(nil); err != nil || tft.ID == uuid.Nil {
		t.Fatalf("TwoFactorToken.BeforeCreate failed to generate UUID: %v, ID=%v", err, tft.ID)
	}
}
