package oauth

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

// Service orchestrates the OAuth login dance: PKCE initiation plus the
// state-validated callback that links (or creates) a user and mints a session.
type Service interface {
	// InitiateFlow generates PKCE, sets the state cookie, and returns the provider auth URL.
	InitiateFlow(w http.ResponseWriter, r *http.Request, providerID string) (string, error)

	// HandleCallback validates state/PKCE, exchanges the code, links/creates the user,
	// issues a session (cookie already set on w), and returns the session plus redirect target.
	HandleCallback(ctx context.Context, w http.ResponseWriter, r *http.Request, providerID, code, state string) (*session.Session, string, error)
}

type service struct {
	db         *gorm.DB
	sessionSvc session.Service
	providers  map[string]Provider
	cfg        *config.Config
}

// NewService wires the OAuth linking engine. cfg is the full app config: state
// helpers need cfg.OAuth while session-cookie issuance needs the session fields.
func NewService(gormDB *gorm.DB, sessionSvc session.Service, providers map[string]Provider, cfg *config.Config) Service {
	if cfg == nil {
		defaultCfg := config.DefaultConfig()
		cfg = &defaultCfg
	}
	return &service{db: gormDB, sessionSvc: sessionSvc, providers: providers, cfg: cfg}
}

// clientIP extracts the remote IP, stripping the port. Direct-connection IP for v1.
func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func (s *service) providerFor(providerID string) (Provider, error) {
	if _, ok := SupportedProviders[providerID]; !ok {
		return nil, errors.ErrOAuthProviderNotFound
	}
	p, ok := s.providers[providerID]
	if !ok || p == nil {
		return nil, errors.ErrOAuthProviderNotFound
	}
	return p, nil
}

// InitiateFlow generates PKCE, persists verifier+state in the signed state
// cookie, and returns the provider authorization URL for a 302 redirect.
func (s *service) InitiateFlow(w http.ResponseWriter, r *http.Request, providerID string) (string, error) {
	if w == nil {
		return "", errors.New(errors.CodeValidationError, "invalid oauth initiate request", nil)
	}
	p, err := s.providerFor(providerID)
	if err != nil {
		return "", err
	}
	pkce, err := GeneratePKCE()
	if err != nil {
		return "", err
	}
	redirect := ""
	logCtx := context.Background()
	ip, ua := clientIP(r), ""
	if r != nil {
		redirect = r.URL.Query().Get("redirect_url")
		logCtx = r.Context()
		ua = r.UserAgent()
	}
	state, err := SetStateCookie(w, s.cfg, providerID, pkce.Verifier, redirect)
	if err != nil {
		return "", err
	}
	slog.InfoContext(logCtx, "oauth_initiate",
		"provider", providerID,
		"ip", ip,
		"user_agent", ua,
	)
	return p.AuthURL(state, pkce.Challenge), nil
}

// HandleCallback runs the full decision tree: state validation, code exchange,
// the mandatory EmailVerified gate (before any DB lookup), account linking or
// creation, session issuance, and state-cookie cleanup.
func (s *service) HandleCallback(ctx context.Context, w http.ResponseWriter, r *http.Request, providerID, code, state string, sessType db.SessionType) (*session.Session, string, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ip, ua := clientIP(r), ""
	if r != nil {
		ua = r.UserAgent()
	}
	fail := func(reason string, err error) (*session.Session, string, error) {
		attrs := []any{
			"provider", providerID,
			"reason", reason,
			"ip", ip,
			"user_agent", ua,
		}
		if err != nil {
			// Provider/transport detail only: exchange/userinfo errors carry
			// static messages plus wrapped stdlib errors, never codes,
			// verifiers, or tokens.
			attrs = append(attrs, "error", err.Error())
		}
		slog.InfoContext(ctx, "oauth_callback_failure", attrs...)
		return nil, "", err
	}
	if w == nil || r == nil {
		return fail("invalid_request", errors.New(errors.CodeValidationError, "invalid oauth callback request", nil))
	}

	payload, err := ValidateState(w, r, s.cfg, providerID, state)
	if err != nil {
		return fail("state_invalid", err)
	}
	p, err := s.providerFor(providerID)
	if err != nil {
		return fail("provider_not_found", err)
	}
	if strings.TrimSpace(code) == "" {
		return fail("code_invalid", errors.New(errors.CodeOAuthCodeInvalid, "oauth code is invalid", nil))
	}
	tokens, err := p.ExchangeCode(ctx, code, payload.CodeVerifier)
	if err != nil {
		return fail("exchange_failed", err)
	}
	info, err := p.FetchUserInfo(ctx, tokens)
	if err != nil {
		return fail("userinfo_failed", err)
	}
	// Mandatory gate: unverified provider email aborts before any DB lookup,
	// so account existence cannot leak via timing or response.
	if info == nil || !info.EmailVerified {
		return fail("email_unverified", errors.ErrOAuthEmailUnverified)
	}
	if strings.TrimSpace(info.Email) == "" {
		return fail("userinfo_invalid", errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", nil))
	}

	user, linked, created, err := s.linkOrCreate(ctx, providerID, info)
	if err != nil {
		var appErr *errors.Error
		if errors.As(err, &appErr) {
			return fail(string(appErr.Code()), err)
		}
		return fail("link_failed", err)
	}

	sess, rawID, err := s.sessionSvc.CreateSession(ctx, user.ID, user.CredentialVersion, db.SessionTypeCookie, ip, ua)
	if err != nil {
		return fail("session_failed", err)
	}
	// The service issues the cookie because it alone holds the raw session
	// ID, which the Service interface never returns and nothing ever logs.
	// Moving issuance to the handler would widen the interface to leak the
	// raw token; w is non-nil by the entry guard above.
	session.SetSessionCookie(w, rawID, s.cfg)
	// ValidateState already cleared the state cookie single-use; clear again
	// post-issuance so no success path can leave it behind.
	ClearStateCookie(w, s.cfg)

	// Empty redirect defaults to "/". The handler applies safeOAuthRedirect
	// to both the 302 and JSON branches, so no absolute URL may pass through.
	redirect := payload.RedirectURL
	if redirect == "" {
		redirect = "/"
	}

	// Spec 2g explicitly requires session_id_hash: log ONLY the SHA-256 hex
	// (IDHash), never the raw session token. The hash is non-reversible, so
	// this stays a deliberate, narrow exception to the NEVER-logged note on
	// session.Session.IDHash.
	slog.InfoContext(ctx, "oauth_callback_success",
		"provider", providerID,
		"user_id", user.ID.String(),
		"ip", ip,
		"user_agent", ua,
		"session_id_hash", sess.IDHash,
	)
	if linked {
		slog.InfoContext(ctx, "oauth_account_linked",
			"provider", providerID,
			"user_id", user.ID.String(),
		)
	}
	if created {
		slog.InfoContext(ctx, "oauth_user_created",
			"provider", providerID,
			"user_id", user.ID.String(),
			"email", db.NormalizeEmail(user.Email),
		)
	}
	return sess, redirect, nil
}

// isUniqueViolation reports driver-agnostic unique-constraint conflicts:
// gorm.ErrDuplicatedKey where the dialector translates, sqlite's
// "UNIQUE constraint failed", postgres "duplicate key"/SQLSTATE 23505.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "23505")
}

// relinkExisting re-reads the link row that won a concurrent insert race and
// loads its owner. Used when our insert hits the unique constraint.
func (s *service) relinkExisting(ctx context.Context, providerID, providerUserID string) (db.User, bool, bool, error) {
	var link db.OAuthAccount
	if err := s.db.WithContext(ctx).
		Where("provider_id = ? AND provider_user_id = ?", providerID, providerUserID).
		First(&link).Error; err != nil {
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query oauth account", err)
	}
	var user db.User
	if err := s.db.WithContext(ctx).Where("id = ?", link.UserID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return db.User{}, false, false, errors.ErrOAuthAccountNotLinked
		}
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to load linked user", err)
	}
	return user, false, false, nil
}

// linkRacedUser converges after losing a concurrent user-create race: re-read
// the winner by normalized email, keep the pre-hijack gate, then link.
func (s *service) linkRacedUser(ctx context.Context, providerID string, info *UserInfo) (db.User, bool, bool, error) {
	var existing db.User
	if err := s.db.WithContext(ctx).Where("LOWER(email) = LOWER(?)", info.Email).First(&existing).Error; err != nil {
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query user", err)
	}
	if !existing.EmailVerified {
		return db.User{}, false, false, errors.ErrOAuthAccountLinkConflict
	}
	row := db.OAuthAccount{
		ID:             uuid.New(),
		UserID:         existing.ID,
		ProviderID:     providerID,
		ProviderUserID: info.ProviderUserID,
		Email:          info.Email,
	}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		if isUniqueViolation(err) {
			return s.relinkExisting(ctx, providerID, info.ProviderUserID)
		}
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to link oauth account", err)
	}
	return existing, true, false, nil
}

// linkOrCreate executes the linking decision tree. Returns the user plus
// whether an oauth_accounts row was inserted and whether the user was created.
// Concurrent duplicate callbacks converge idempotently: a unique-constraint
// loss re-reads the winner instead of 500ing. The EmailVerified gate above
// (in HandleCallback) runs before any DB touch and is untouched by this.
func (s *service) linkOrCreate(ctx context.Context, providerID string, info *UserInfo) (db.User, bool, bool, error) {
	var link db.OAuthAccount
	err := s.db.WithContext(ctx).
		Where("provider_id = ? AND provider_user_id = ?", providerID, info.ProviderUserID).
		First(&link).Error
	if err == nil {
		// Case A: existing link — load the owner, no new rows.
		var user db.User
		if uerr := s.db.WithContext(ctx).Where("id = ?", link.UserID).First(&user).Error; uerr != nil {
			if errors.Is(uerr, gorm.ErrRecordNotFound) {
				return db.User{}, false, false, errors.ErrOAuthAccountNotLinked
			}
			return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to load linked user", uerr)
		}
		return user, false, false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query oauth account", err)
	}

	// Case B: no link — match local account by normalized email.
	var existing db.User
	uerr := s.db.WithContext(ctx).Where("LOWER(email) = LOWER(?)", info.Email).First(&existing).Error
	if uerr == nil {
		// Pre-hijacking defense: never link onto an unverified local account.
		if !existing.EmailVerified {
			return db.User{}, false, false, errors.ErrOAuthAccountLinkConflict
		}
		row := db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         existing.ID,
			ProviderID:     providerID,
			ProviderUserID: info.ProviderUserID,
			Email:          info.Email,
		}
		if cerr := s.db.WithContext(ctx).Create(&row).Error; cerr != nil {
			if isUniqueViolation(cerr) {
				return s.relinkExisting(ctx, providerID, info.ProviderUserID)
			}
			return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to link oauth account", cerr)
		}
		return existing, true, false, nil
	}
	if !errors.Is(uerr, gorm.ErrRecordNotFound) {
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query user", uerr)
	}

	// Subcase B2: no local account — create verified user plus link row.
	user := db.User{
		ID:            uuid.New(),
		Email:         info.Email,
		PasswordHash:  "",
		EmailVerified: true,
	}
	if cerr := s.db.WithContext(ctx).Create(&user).Error; cerr != nil {
		if isUniqueViolation(cerr) {
			return s.linkRacedUser(ctx, providerID, info)
		}
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to create oauth user", cerr)
	}
	row := db.OAuthAccount{
		ID:             uuid.New(),
		UserID:         user.ID,
		ProviderID:     providerID,
		ProviderUserID: info.ProviderUserID,
		Email:          info.Email,
	}
	if cerr := s.db.WithContext(ctx).Create(&row).Error; cerr != nil {
		if isUniqueViolation(cerr) {
			return s.relinkExisting(ctx, providerID, info.ProviderUserID)
		}
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to link oauth account", cerr)
	}
	return user, true, true, nil
}
