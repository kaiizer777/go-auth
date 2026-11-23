package oauth

import (
	"context"
	stderrors "errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

// Service orchestrates the OAuth login dance: PKCE initiation plus the
// state-validated callback that links (or creates) a user and mints a session.
type Service interface {
	// InitiateFlow generates PKCE, sets the state cookie, and returns the provider auth URL.
	InitiateFlow(w http.ResponseWriter, r *http.Request, providerID string) (string, error)

	// HandleCallback validates state/PKCE, exchanges the code, links/creates the user,
	// issues a session, and returns the session, its raw ID, and the redirect target.
	// sessType selects the minted session transport: cookie sessions are set on w
	// (cookie callers ignore the raw return); bearer sessions set no cookie and the
	// caller relays the raw token out of band. Raw IDs are never logged.
	HandleCallback(ctx context.Context, w http.ResponseWriter, r *http.Request, providerID, code, state string, sessType db.SessionType) (*session.Session, string, string, error)
}

// RateLimitError wraps an upstream rate limit with its Retry-After duration in seconds.
type RateLimitError struct {
	RetryAfter int
	Err        error
}

func (e *RateLimitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return "oauth provider rate limit exceeded"
}

func (e *RateLimitError) Unwrap() error {
	if e.Err != nil {
		return e.Err
	}
	return errors.ErrOAuthRateLimitExceeded
}

// RetryAfterFromError extracts the retry-after duration in seconds if err is or wraps RateLimitError.
func RetryAfterFromError(err error) (int, bool) {
	var rle *RateLimitError
	if stderrors.As(err, &rle) && rle.RetryAfter > 0 {
		return rle.RetryAfter, true
	}
	return 0, false
}

type service struct {
	store      db.Store
	sessionSvc session.Service
	registry   Registry
	providers  map[string]Provider
	cfg        *config.Config
}

// NewServiceWithRegistry wires the OAuth linking engine using an abstract db.Store and dynamic Registry.
func NewServiceWithRegistry(store db.Store, sessionSvc session.Service, registry Registry, cfg *config.Config) Service {
	if cfg == nil {
		defaultCfg := config.DefaultConfig()
		cfg = &defaultCfg
	}
	return &service{store: store, sessionSvc: sessionSvc, registry: registry, cfg: cfg}
}

// NewServiceWithStore wires the OAuth linking engine using an abstract db.Store.
func NewServiceWithStore(store db.Store, sessionSvc session.Service, providers map[string]Provider, cfg *config.Config) Service {
	if cfg == nil {
		defaultCfg := config.DefaultConfig()
		cfg = &defaultCfg
	}
	return &service{store: store, sessionSvc: sessionSvc, providers: providers, cfg: cfg}
}

// NewService wires the OAuth linking engine. cfg is the full app config: state
// helpers need cfg.OAuth while session-cookie issuance needs the session fields.
func NewService(gormDB *gorm.DB, sessionSvc session.Service, providers map[string]Provider, cfg *config.Config) Service {
	if cfg == nil {
		defaultCfg := config.DefaultConfig()
		cfg = &defaultCfg
	}
	return NewServiceWithStore(gormstore.New(gormDB), sessionSvc, providers, cfg)
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
	if s.registry != nil {
		p, err := s.registry.Get(providerID)
		if err == nil && p != nil {
			return p, nil
		}
	}
	if s.providers != nil {
		if p, ok := s.providers[providerID]; ok && p != nil {
			return p, nil
		}
	}
	return nil, errors.ErrOAuthProviderNotFound
}

// linkQueryParam is the explicit link signal on the initiate URL. A bare
// login initiation never embeds the ambient session user; only ?link=true
// resolves the signed-in user into the state payload.
const linkQueryParam = "link"

// linkIntentRequested reports explicit account-link intent for an initiation.
// Link is opt-in per login: ambient credentials alone never trigger it.
func linkIntentRequested(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	return r.URL.Query().Get(linkQueryParam) == "true"
}

// resolveLinkUserID resolves the signed-in user for an explicit link
// initiation. Absent, invalid, or expired sessions yield "" so the flow
// degrades to plain login; store failures are hard errors so an explicit
// link never silently becomes a registration.
func (s *service) resolveLinkUserID(r *http.Request) (string, error) {
	if s.sessionSvc == nil {
		return "", errors.New(errors.CodeInternalError, "oauth link requires session service", nil)
	}
	var rawID string
	if r.Header.Get("Authorization") != "" {
		rawID, _ = session.ReadBearerToken(r)
	} else {
		rawID, _ = session.ReadSessionCookie(r, s.cfg)
	}
	if rawID != "" {
		sess, gerr := s.sessionSvc.GetSession(r.Context(), rawID)
		if gerr != nil {
			var appErr *errors.Error
			if errors.As(gerr, &appErr) && appErr.Code() == errors.CodeInternalError {
				return "", errors.New(errors.CodeInternalError, "failed to resolve session for link", gerr)
			}
			return "", nil
		}
		if sess != nil && sess.UserID != uuid.Nil {
			return sess.UserID.String(), nil
		}
		return "", nil
	}
	if v := r.Context().Value("user_id"); v != nil {
		switch id := v.(type) {
		case string:
			return id, nil
		case uuid.UUID:
			if id != uuid.Nil {
				return id.String(), nil
			}
		}
	}
	return "", nil
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
	nonce, err := GenerateNonce()
	if err != nil {
		return "", err
	}
	redirect := ""
	logCtx := context.Background()
	ip, ua := clientIP(r), ""
	var activeUserID string
	if r != nil {
		redirect = r.URL.Query().Get("redirect_url")
		logCtx = r.Context()
		ua = r.UserAgent()

		if linkIntentRequested(r) {
			uid, lerr := s.resolveLinkUserID(r)
			if lerr != nil {
				return "", lerr
			}
			activeUserID = uid
		}
	}
	state, err := SetStateCookieWithUserAndNonce(w, s.cfg, providerID, pkce.Verifier, redirect, activeUserID, nonce)
	if err != nil {
		return "", err
	}
	slog.InfoContext(logCtx, "oauth_initiate",
		"provider", providerID,
		"ip", ip,
		"user_agent", ua,
	)
	if _, ok := p.(OIDCProvider); ok {
		return p.AuthCodeURL(state, pkce.Challenge, NonceOption(nonce)), nil
	}
	return p.AuthURL(state, pkce.Challenge), nil
}

// HandleCallback runs the full decision tree: state validation, code exchange,
// account linking or creation, session issuance, and state-cookie cleanup. The
// provider-verified gate lives inside the link path so an already-linked
// identity never needs an email (Apple omits it after first consent).
func (s *service) HandleCallback(ctx context.Context, w http.ResponseWriter, r *http.Request, providerID, code, state string, sessType db.SessionType) (*session.Session, string, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ip, ua := clientIP(r), ""
	if r != nil {
		ua = r.UserAgent()
	}
	fail := func(reason string, err error) (*session.Session, string, string, error) {
		attrs := []any{
			"provider", providerID,
			"reason", reason,
			"ip", ip,
			"user_agent", ua,
		}
		if err != nil {
			// Provider/transport detail only: exchange/userinfo errors carry
			// static messages plus wrapped stdlib errors, never codes,
			// verifiers, or tokens. Link-path driver errors may embed a
			// normalized-email key from the database; that matches the
			// repo-wide logging convention and is accepted here.
			attrs = append(attrs, "error", err.Error())
		}
		slog.InfoContext(ctx, "oauth_callback_failure", attrs...)
		return nil, "", "", err
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
	// A nil profile keeps the historical 400: only the provider-verified gate
	// moved behind the link lookup, and it cannot run without a profile.
	if info == nil {
		return fail("email_unverified", errors.ErrOAuthEmailUnverified)
	}
	// OIDC replay control: re-verify the ID token against the state-stored
	// nonce. Providers already verified the signature inside FetchUserInfo;
	// this second pass binds the token to this login. Empty nonces (states
	// issued before nonce support, or token-only fallbacks) skip the check.
	if oidc, ok := p.(OIDCProvider); ok && payload.Nonce != "" && tokens.IDToken != "" {
		if _, verr := oidc.VerifyIDToken(ctx, tokens.IDToken, payload.Nonce); verr != nil {
			return fail("idtoken_invalid", verr)
		}
	}

	activeUserID := payload.UserID
	if activeUserID != "" {
		// Never link on the embedded value alone: a planted state cookie
		// would attach the victim's provider identity to the attacker's
		// account. Re-resolve the live session and require equality. A
		// missing session falls back to plain login; a different session
		// rejects the callback.
		live, rerr := s.resolveLinkUserID(r)
		if rerr != nil {
			return fail("session_failed", rerr)
		}
		if live == "" {
			activeUserID = ""
		} else if live != activeUserID {
			return fail("link_conflict", errors.ErrOAuthAccountAlreadyLinked)
		}
	}

	user, linked, created, err := s.linkOrCreate(ctx, providerID, info, activeUserID)
	if err != nil {
		// Gate sentinels map to their historical literal reasons before the
		// code-derived fallback, which stays the producer of UPPER_SNAKE
		// reasons such as OAUTH_ACCOUNT_LINK_CONFLICT.
		if errors.Is(err, errors.ErrOAuthEmailRequired) {
			return fail("email_required", err)
		}
		if errors.Is(err, errors.ErrOAuthEmailUnverified) {
			return fail("email_unverified", err)
		}
		if errors.Is(err, errors.ErrOAuthTenantInvalid) {
			return fail("tenant_invalid", err)
		}
		if errors.Is(err, errors.ErrOAuthAccountLinkConflict) {
			return fail(string(errors.CodeOAuthAccountLinkConflict), err)
		}
		if errors.Is(err, errOAuthProviderIdentityInvalid) {
			return fail("userinfo_invalid", err)
		}
		var appErr *errors.Error
		if errors.As(err, &appErr) {
			return fail(string(appErr.Code()), err)
		}
		return fail("link_failed", err)
	}

	sess, rawID, err := s.sessionSvc.CreateSession(ctx, user.ID, user.CredentialVersion, sessType, ip, ua)
	if err != nil {
		return fail("session_failed", err)
	}
	// Cookie sessions are issued here because the service alone holds the raw
	// ID (w is non-nil by the entry guard above). Bearer sessions set no
	// cookie: cookie plus declared-bearer transport is ambiguous and is
	// rejected by the CSRF middleware and the RequireAuth binding. The raw
	// token returns to the caller, which relays it in the JSON body.
	if sessType != db.SessionTypeBearer {
		session.SetSessionCookie(w, rawID, s.cfg)
	}
	// ValidateState already cleared the state cookie single-use; clear again
	// post-issuance so no success path can leave it behind.
	ClearStateCookie(w, s.cfg, providerID)

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
	logLinkAudit(ctx, providerID, user, linked, created)
	return sess, rawID, redirect, nil
}

// logLinkAudit emits the audit events implied by the (linked, created) tuple.
// The tuple is load-bearing: a converged race loser reports neither event.
func logLinkAudit(ctx context.Context, providerID string, user db.User, linked, created bool) {
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
}

// isUniqueViolation reports driver-agnostic unique-constraint conflicts:
// gorm.ErrDuplicatedKey where the dialector translates, sqlite's
// "UNIQUE constraint failed", postgres "duplicate key"/SQLSTATE 23505,
// and MySQL error 1062 / "duplicate entry".
// Substring matching is deliberate: sqlite, pgx, and mysql word these differently,
// and a missed match would turn every convergence path into a 500.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) ||
		errors.Is(err, errors.ErrOAuthAccountAlreadyLinked) ||
		errors.Is(err, errors.ErrEmailAlreadyExists) ||
		errors.Is(err, errors.ErrUserAlreadyExists) {
		return true
	}
	var myErr *mysql.MySQLError
	if stderrors.As(err, &myErr) && myErr.Number == 1062 {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "23505") ||
		strings.Contains(msg, "1062") ||
		strings.Contains(msg, "duplicate entry") ||
		strings.Contains(msg, "already exists")
}

// errLinkConflict reports a unique-constraint loss on the oauth_accounts insert.
// Callers converge on the winning row instead of duplicating it; inside
// createUserAndLink's transaction it also rolls the freshly created user back.
var errLinkConflict = errors.New(errors.CodeInternalError, "oauth link conflict", nil)

// errOAuthProviderIdentityInvalid rejects identity fields that cannot be stored.
// It is a distinct sentinel so HandleCallback logs the literal "userinfo_invalid"
// reason instead of the derived OAUTH_PROVIDER_ERROR.
var errOAuthProviderIdentityInvalid = errors.New(errors.CodeOAuthProviderError, "oauth provider returned invalid response", nil)

// providerFieldMaxLen matches the VARCHAR(255) columns behind the identity
// writes: users.email, oauth_accounts.email and oauth_accounts.provider_user_id.
const providerFieldMaxLen = 255

// validateProviderIdentity gates the no-link paths, which are the only ones that
// resolve a local account by email. Order is load-bearing: an unverified
// identity reports OAUTH_EMAIL_UNVERIFIED before any field-validity rejection.
func validateProviderIdentity(info *UserInfo) error {
	if strings.TrimSpace(info.Email) == "" {
		return errors.ErrOAuthEmailRequired
	}
	if !info.EmailVerified {
		return errors.ErrOAuthEmailUnverified
	}
	if info.ProviderUserID == "" || len(info.ProviderUserID) > providerFieldMaxLen {
		return errOAuthProviderIdentityInvalid
	}
	if len(info.Email) > providerFieldMaxLen || db.ValidateEmail(info.Email) != nil {
		return errOAuthProviderIdentityInvalid
	}
	return nil
}

// findLink loads the oauth_accounts row for a provider identity. found=false
// with a nil error is the normal no-link case; anything else is a query failure.
func (s *service) findLink(ctx context.Context, providerID, providerUserID string) (db.OAuthAccount, bool, error) {
	link, err := s.store.OAuthAccounts().GetByProvider(ctx, providerID, providerUserID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return db.OAuthAccount{}, false, nil
	}
	if err != nil {
		return db.OAuthAccount{}, false, err
	}
	if link == nil {
		return db.OAuthAccount{}, false, nil
	}
	return *link, true, nil
}

// loadLinkedUser loads the account owning link. A missing owner is a dangling
// link row and maps to OAUTH_ACCOUNT_NOT_LINKED.
func (s *service) loadLinkedUser(ctx context.Context, link db.OAuthAccount) (db.User, error) {
	user, err := s.store.Users().GetByID(ctx, link.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, errors.ErrUserNotFound) {
			return db.User{}, errors.ErrOAuthAccountNotLinked
		}
		return db.User{}, errors.New(errors.CodeInternalError, "failed to load linked user", err)
	}
	return *user, nil
}

// findUserByEmail resolves the local account owning email. gorm.ErrRecordNotFound
// is the only expected miss.
func (s *service) findUserByEmail(ctx context.Context, email string) (db.User, error) {
	user, err := s.store.Users().GetByEmail(ctx, email)
	if err != nil {
		return db.User{}, err
	}
	return *user, nil
}

// insertLink writes the oauth_accounts row for userID. errLinkConflict means a
// concurrent callback already claimed (providerID, providerUserID).
func (s *service) insertLink(ctx context.Context, accountStore db.OAuthAccountStore, userID uuid.UUID, providerID, providerUserID, email string) error {
	row := db.OAuthAccount{
		ID:             uuid.New(),
		UserID:         userID,
		ProviderID:     providerID,
		ProviderUserID: providerUserID,
		Email:          email,
	}
	if err := accountStore.Create(ctx, &row); err != nil {
		if isUniqueViolation(err) {
			return errLinkConflict
		}
		return err
	}
	return nil
}

// linkExisting attaches the provider identity to owner. Losing the unique race
// converges on the winner's row, which reports linked=false.
func (s *service) linkExisting(ctx context.Context, owner db.User, providerID string, info *UserInfo) (db.User, bool, error) {
	email := info.Email
	if email == "" {
		email = owner.Email
	}
	if err := s.insertLink(ctx, s.store.OAuthAccounts(), owner.ID, providerID, info.ProviderUserID, email); err != nil {
		if errors.Is(err, errLinkConflict) {
			user, _, _, rerr := s.relinkExisting(ctx, providerID, info.ProviderUserID)
			return user, false, rerr
		}
		if errors.Is(err, errors.ErrUserNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
			return db.User{}, false, errors.ErrUserNotFound
		}
		return db.User{}, false, errors.New(errors.CodeInternalError, "failed to link oauth account", err)
	}
	return owner, true, nil
}

// linkedUser resolves the owner of an existing provider link. found=false with
// a nil error means no link exists yet.
func (s *service) linkedUser(ctx context.Context, providerID, providerUserID string) (db.User, bool, error) {
	link, found, err := s.findLink(ctx, providerID, providerUserID)
	if err != nil {
		return db.User{}, false, errors.New(errors.CodeInternalError, "failed to query oauth account", err)
	}
	if !found {
		return db.User{}, false, nil
	}
	user, err := s.loadLinkedUser(ctx, link)
	if err != nil {
		return db.User{}, true, err
	}
	return user, true, nil
}

// relinkExisting re-reads the link row that won a concurrent insert race and
// loads its owner. Used when our insert hits the unique constraint.
func (s *service) relinkExisting(ctx context.Context, providerID, providerUserID string) (db.User, bool, bool, error) {
	user, found, err := s.linkedUser(ctx, providerID, providerUserID)
	if err != nil || !found {
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query oauth account", err)
	}
	return user, false, false, nil
}

// linkRacedUser converges after losing a concurrent user-create race: re-read
// the winner by normalized email, keep the pre-hijack gate, then link. The 409
// is permanent by design: it mirrors password signup, which refuses an
// already-registered email instead of taking it over, and no verification-mail
// or takeover flow exists here, so the address stays blocked until the squatted
// row is removed out of band.
func (s *service) linkRacedUser(ctx context.Context, providerID string, info *UserInfo) (db.User, bool, bool, error) {
	existing, err := s.findUserByEmail(ctx, info.Email)
	if err != nil {
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query user", err)
	}
	if !existing.EmailVerified {
		return db.User{}, false, false, errors.ErrOAuthAccountLinkConflict
	}
	user, linked, err := s.linkExisting(ctx, existing, providerID, info)
	if err != nil {
		return db.User{}, false, false, err
	}
	return user, linked, false, nil
}

// createUserAndLink creates the verified passwordless user and its link row in
// one transaction. Separate inserts would let a cancel land between them
// (verified user, no link) or a lost link race orphan the loser's user. Session
// creation stays post-commit: cookie issuance cannot roll back. Unique
// conflicts roll the transaction back before converging on the winner.
func (s *service) createUserAndLink(ctx context.Context, providerID string, info *UserInfo) (db.User, bool, bool, error) {
	user := db.User{
		ID:            uuid.New(),
		Email:         info.Email,
		PasswordHash:  "",
		EmailVerified: true,
	}
	userConflict, linkConflict := false, false
	op := "failed to create oauth user"
	txErr := s.store.Transaction(ctx, func(txStore db.Store) error {
		userConflict = false
		linkConflict = false
		op = "failed to create oauth user"
		if err := txStore.Users().Create(ctx, &user); err != nil {
			userConflict = errors.Is(err, errors.ErrEmailAlreadyExists) ||
				errors.Is(err, errors.ErrUserAlreadyExists) ||
				isUniqueViolation(err)
			return err
		}
		op = "failed to link oauth account"
		if err := s.insertLink(ctx, txStore.OAuthAccounts(), user.ID, providerID, info.ProviderUserID, info.Email); err != nil {
			linkConflict = errors.Is(err, errLinkConflict)
			return err
		}
		return nil
	})
	if txErr != nil {
		if userConflict {
			return s.linkRacedUser(ctx, providerID, info)
		}
		if linkConflict {
			return s.relinkExisting(ctx, providerID, info.ProviderUserID)
		}
		return db.User{}, false, false, errors.New(errors.CodeInternalError, op, txErr)
	}
	return user, true, true, nil
}

// linkOrCreate executes the linking decision tree. Returns the user plus
// whether an oauth_accounts row was inserted and whether the user was created.
// Concurrent duplicate callbacks converge idempotently: a unique-constraint
// loss re-reads the winner instead of 500ing.
func (s *service) linkOrCreate(ctx context.Context, providerID string, info *UserInfo, activeUserID string) (db.User, bool, bool, error) {
	// 1. Returning user check: if linked by (provider_id, provider_user_id), return owner
	if user, found, err := s.linkedUser(ctx, providerID, info.ProviderUserID); found || err != nil {
		if found && activeUserID != "" {
			if user.ID.String() != activeUserID {
				return db.User{}, false, false, errors.ErrOAuthAccountAlreadyLinked
			}
		}
		return user, false, false, err
	}

	// 2. Microsoft "nOauth" defense: fail closed on untrusted external tenants.
	// Runs before the active-session branch so a signed-in callback cannot
	// persist an attacker-tenant identity onto the victim's account.
	if isUntrusted, _ := info.RawClaims["untrusted_tenant"].(bool); isUntrusted {
		return db.User{}, false, false, errors.ErrOAuthTenantInvalid
	}

	// 3. Active session explicit linking: link provider to currently authenticated session user.
	// Fail closed: an unresolvable link owner never falls through to registration.
	if activeUserID != "" {
		uid, parseErr := uuid.Parse(activeUserID)
		if parseErr != nil {
			return db.User{}, false, false, errors.New(errors.CodeInternalError, "invalid link identity", parseErr)
		}
		owner, uerr := s.store.Users().GetByID(ctx, uid)
		if uerr != nil {
			return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to load link owner", uerr)
		}
		if owner == nil {
			return db.User{}, false, false, errors.New(errors.CodeInternalError, "link owner not found", nil)
		}
		if info.ProviderUserID == "" || len(info.ProviderUserID) > providerFieldMaxLen {
			return db.User{}, false, false, errOAuthProviderIdentityInvalid
		}
		user, linked, lerr := s.linkExisting(ctx, *owner, providerID, info)
		return user, linked, false, lerr
	}

	// 4. Validate provider identity for unauthenticated registration (requires verified email)
	if gerr := validateProviderIdentity(info); gerr != nil {
		return db.User{}, false, false, gerr
	}

	// 5. Existing local user check by verified email
	existing, err := s.findUserByEmail(ctx, info.Email)
	if err == nil {
		// Pre-hijacking defense: never link onto an unverified local account.
		if !existing.EmailVerified {
			return db.User{}, false, false, errors.ErrOAuthAccountLinkConflict
		}
		user, linked, lerr := s.linkExisting(ctx, existing, providerID, info)
		return user, linked, false, lerr
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) && !errors.Is(err, errors.ErrUserNotFound) {
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query user", err)
	}
	return s.createUserAndLink(ctx, providerID, info)
}
