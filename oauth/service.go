package oauth

import (
	"context"
	stderrors "errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/crypto"
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

	// LinkedAccountToken returns a usable provider access token for the user's
	// linked account, renewing it on demand. The refresh token never leaves the
	// library: the returned value holds the access token, its type, and its
	// expiry only. An account with no stored token yields an empty token.
	LinkedAccountToken(ctx context.Context, userID uuid.UUID, providerID string) (*OAuthToken, error)
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
	sealer     *crypto.TokenSealer

	// refreshFlight collapses concurrent renewals of one account. It is an
	// optimisation only: the CAS on the stored fingerprint is what keeps
	// writers safe across instances.
	refreshFlight singleflight.Group
}

// newTokenSealer builds the immutable token sealer from cfg.OAuth.TokenKEK. A
// missing or unparsable keyring yields a nil sealer, so InitiateFlow and
// HandleCallback fail closed instead of issuing an unusable login; config
// validation already rejects a malformed specification at startup.
func newTokenSealer(cfg *config.Config) *crypto.TokenSealer {
	ring, err := crypto.ParseKeyring(cfg.OAuth.TokenKEK)
	if err != nil {
		return nil
	}
	return crypto.NewTokenSealer(ring)
}

// NewServiceWithRegistry wires the OAuth linking engine using an abstract db.Store and dynamic Registry.
func NewServiceWithRegistry(store db.Store, sessionSvc session.Service, registry Registry, cfg *config.Config) Service {
	if cfg == nil {
		defaultCfg := config.DefaultConfig()
		cfg = &defaultCfg
	}
	return &service{store: store, sessionSvc: sessionSvc, registry: registry, cfg: cfg, sealer: newTokenSealer(cfg)}
}

// NewServiceWithStore wires the OAuth linking engine using an abstract db.Store.
func NewServiceWithStore(store db.Store, sessionSvc session.Service, providers map[string]Provider, cfg *config.Config) Service {
	if cfg == nil {
		defaultCfg := config.DefaultConfig()
		cfg = &defaultCfg
	}
	return &service{store: store, sessionSvc: sessionSvc, providers: providers, cfg: cfg, sealer: newTokenSealer(cfg)}
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

// CanonicalProviderSlug normalizes a provider slug for gating and dispatch. The
// registry and the static provider map key on the canonical lowercase ID, so a
// configured provider may be addressed with any casing. The returned slug is
// what must reach the store: provider_id is part of the identity key.
func CanonicalProviderSlug(providerID string) string {
	return strings.ToLower(strings.TrimSpace(providerID))
}

func (s *service) providerFor(providerID string) (Provider, error) {
	slug := CanonicalProviderSlug(providerID)
	if s.registry != nil {
		if p, err := s.registry.Get(slug); err == nil && p != nil {
			return p, nil
		}
	}
	if s.providers != nil {
		if p, ok := s.providers[slug]; ok && p != nil {
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

// ctxUserIDKey types the context slot carrying the signed-in user for a link
// initiation; a bare string key would collide with any other package's.
type ctxUserIDKey struct{}

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
	if v := r.Context().Value(ctxUserIDKey{}); v != nil {
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

// checkLinkOwnerAlive distinguishes a lapsed session from a vanished owner
// when a callback carries link intent but no live session resolves. A living
// owner degrades to a plain login (nil); a missing owner fails closed with
// ErrOAuthAccountNotLinked and a broken store with a 500, mirroring the
// active-session branch of linkOrCreate.
func (s *service) checkLinkOwnerAlive(ctx context.Context, activeUserID string) error {
	uid, perr := uuid.Parse(activeUserID)
	if perr != nil {
		return errors.ErrOAuthAccountNotLinked
	}
	owner, uerr := s.store.Users().GetByID(ctx, uid)
	if uerr != nil {
		if errors.Is(uerr, gorm.ErrRecordNotFound) || errors.Is(uerr, errors.ErrUserNotFound) {
			return errors.ErrOAuthAccountNotLinked
		}
		return errors.New(errors.CodeInternalError, "failed to load linking user", uerr)
	}
	if owner == nil {
		return errors.ErrOAuthAccountNotLinked
	}
	return nil
}

// maxTokenLifetimeSeconds is the largest expires_in that still fits a
// time.Duration: anything above it would overflow into a past timestamp.
const maxTokenLifetimeSeconds = math.MaxInt64 / int64(time.Second)

// tokenExpiry derives the absolute access-token expiry from the provider's
// relative lifetime. ExpiresIn <= 0 stores no expiry. OAuthToken.ExpiresAt is
// never populated by an adapter, so it is deliberately not consulted; an
// oversized ExpiresIn is clamped to maxTokenLifetimeSeconds.
func tokenExpiry(tokens *OAuthToken) *time.Time {
	if tokens == nil || tokens.ExpiresIn <= 0 {
		return nil
	}
	seconds := int64(tokens.ExpiresIn)
	if seconds > maxTokenLifetimeSeconds {
		seconds = maxTokenLifetimeSeconds
	}
	expiresAt := time.Now().UTC().Add(time.Duration(seconds) * time.Second)
	return &expiresAt
}

// tokenRefreshLeeway renews a stored access token this long before it expires.
// The row's expiry comes from the provider's clock, so a caller must never be
// handed a token that dies mid-request.
const tokenRefreshLeeway = 60 * time.Second

// tokenTypeBearer is the auth scheme every supported provider issues. The grant
// table stores no token type, so a stored token is reported under the scheme the
// adapters return rather than guessing per row.
const tokenTypeBearer = "Bearer"

// LinkedAccountToken returns a usable access token for the user's linked
// account, refreshing an expired one on demand. The refresh token never leaves
// this library: the returned value carries the access token, its type, and its
// expiry only.
func (s *service) LinkedAccountToken(ctx context.Context, userID uuid.UUID, providerID string) (*OAuthToken, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// No keyring means no stored grant can be opened: refuse with the same
	// configuration sentinel the login entry points report, before any read.
	if s.sealer == nil {
		return nil, errors.ErrOAuthTokenKEKMissing
	}
	link, err := s.linkedAccountFor(ctx, userID, CanonicalProviderSlug(providerID))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if tokenFresh(link.TokenExpiresAt, now) {
		return s.readStoredAccess(ctx, link, now)
	}
	return s.refreshAccessToken(ctx, link)
}

// linkedAccountFor resolves the user's row for one provider. It reads the
// account list instead of probing by provider identity: the caller is
// identified by user, and a row only resolves when it belongs to them. A user
// may hold more than one link for a provider, so the most recently updated one
// is served; the id breaks ties so the answer never depends on store order.
func (s *service) linkedAccountFor(ctx context.Context, userID uuid.UUID, providerID string) (db.OAuthAccount, error) {
	accounts, err := s.store.OAuthAccounts().GetByUserID(ctx, userID)
	if err != nil {
		return db.OAuthAccount{}, errors.New(errors.CodeInternalError, "failed to load oauth accounts", err)
	}
	var newest *db.OAuthAccount
	for _, account := range accounts {
		if account == nil || account.ProviderID != providerID {
			continue
		}
		if newest == nil || newerLink(account, newest) {
			newest = account
		}
	}
	if newest == nil {
		return db.OAuthAccount{}, errors.ErrOAuthAccountNotLinked
	}
	return *newest, nil
}

// newerLink reports whether candidate is the row a provider lookup prefers: the
// most recently updated link, with the id deciding an exact tie.
func newerLink(candidate, current *db.OAuthAccount) bool {
	if !candidate.UpdatedAt.Equal(current.UpdatedAt) {
		return candidate.UpdatedAt.After(current.UpdatedAt)
	}
	return candidate.ID.String() < current.ID.String()
}

// tokenFresh reports whether a stored token may still be served. A nil expiry
// means the provider never stated one, which is read as fresh; the leeway keeps
// a token from expiring under the caller's feet.
func tokenFresh(expiresAt *time.Time, now time.Time) bool {
	return expiresAt == nil || expiresAt.After(now.Add(tokenRefreshLeeway))
}

// readStoredAccess opens the row's access envelope. An account with no sealed
// access token yields an empty token instead of an error: linking an account is
// not a promise that the provider granted one.
func (s *service) readStoredAccess(ctx context.Context, link db.OAuthAccount, now time.Time) (*OAuthToken, error) {
	if link.AccessTokenCiphertext == "" {
		return &OAuthToken{}, nil
	}
	token, err := s.openAccessToken(link, now)
	if err == nil {
		return token, nil
	}
	if !isMalformedEnvelope(err) {
		return nil, s.decryptFailure(ctx, link, err)
	}
	return s.discardGrant(ctx, link)
}

// openAccessToken decrypts the stored access envelope and projects it onto the
// caller-facing value. Expiry is recomputed from the row, never from the
// adapter's unset field, and every credential the accessor must withhold is
// left zero: Raw holds the provider's whole token body, refresh token included.
func (s *service) openAccessToken(link db.OAuthAccount, now time.Time) (*OAuthToken, error) {
	access, err := s.sealer.OpenAccessToken(link.ProviderID, link.ID.String(), link.AccessTokenCiphertext)
	if err != nil {
		return nil, err
	}
	token := &OAuthToken{AccessToken: access, TokenType: tokenTypeBearer}
	if link.TokenExpiresAt != nil {
		token.ExpiresAt = link.TokenExpiresAt.UTC()
		if remaining := token.ExpiresAt.Sub(now); remaining > 0 {
			token.ExpiresIn = int(remaining / time.Second)
		}
	}
	return token, nil
}

// isMalformedEnvelope reports envelopes that cannot be parsed at all, as opposed
// to ones that parse and then fail authentication.
func isMalformedEnvelope(err error) bool {
	return errors.Is(err, crypto.ErrEnvelopeMalformed) || errors.Is(err, crypto.ErrEnvelopeTooLarge)
}

// decryptFailure maps a sealer error onto the accessor's taxonomy. Unknown keys
// and failed authentication never rewrite the row: a removed key is an operator
// error and a failed tag is indistinguishable from tampering, so both report a
// server-side failure and leave the stored grant untouched.
func (s *service) decryptFailure(ctx context.Context, link db.OAuthAccount, err error) error {
	switch {
	case errors.Is(err, crypto.ErrSealerUnconfigured):
		return errors.ErrOAuthTokenKEKMissing
	case errors.Is(err, crypto.ErrUnknownKeyID):
		return errors.ErrOAuthTokenKeyNotFound
	case errors.Is(err, crypto.ErrAuthenticationFailed):
		logTokenEvent(ctx, "oauth_token_decrypt_failed", link)
		return errors.ErrOAuthTokenCorrupt
	default:
		return err
	}
}

// discardGrant drops a grant that can no longer be used, guarded by a CAS on the
// fingerprint that was read. Losing the CAS means another writer rotated a live
// grant; that grant is served instead of being destroyed. This never recurses.
func (s *service) discardGrant(ctx context.Context, link db.OAuthAccount) (*OAuthToken, error) {
	if link.RefreshTokenFingerprint == "" {
		return nil, errors.ErrOAuthReauthRequired
	}
	won, err := s.store.OAuthAccounts().SaveOAuthTokensCAS(ctx, link.ID, link.RefreshTokenFingerprint, db.OAuthTokenRecord{})
	if err != nil {
		logTokenEvent(ctx, "oauth_token_clear_failed", link)
		return nil, errors.ErrOAuthReauthRequired
	}
	if won {
		return nil, errors.ErrOAuthReauthRequired
	}
	return s.converge(ctx, link)
}

// rereadOwned re-reads the identity of stale and refuses a row that no longer
// belongs to the same link and owner. The identity is unique per backend, but a
// delete plus relink can move it to another row or user while a request is in
// flight; serving that row would hand one user's credential to another caller.
func (s *service) rereadOwned(ctx context.Context, stale db.OAuthAccount) (*db.OAuthAccount, error) {
	row, err := s.store.OAuthAccounts().GetByProvider(ctx, stale.ProviderID, stale.ProviderTenantID, stale.ProviderUserID)
	if err != nil || row == nil {
		logTokenEvent(ctx, "oauth_token_reread_failed", stale)
		return nil, errors.New(errors.CodeInternalError, "failed to reload oauth account", nil)
	}
	if row.ID != stale.ID || row.UserID != stale.UserID {
		logTokenEvent(ctx, "oauth_token_owner_mismatch", stale)
		return nil, errors.ErrOAuthReauthRequired
	}
	return row, nil
}

// serveGrant serves the access token a row holds. A row that is tokenless or
// stale yields the retryable exchange failure, because the next request reads it
// afresh; a malformed envelope is as dead as a rejected grant.
func (s *service) serveGrant(ctx context.Context, row db.OAuthAccount) (*OAuthToken, error) {
	now := time.Now().UTC()
	if row.AccessTokenCiphertext == "" || !tokenFresh(row.TokenExpiresAt, now) {
		return nil, errors.ErrOAuthTokenExchangeFailed
	}
	token, oerr := s.openAccessToken(row, now)
	if oerr != nil {
		if isMalformedEnvelope(oerr) {
			return nil, errors.ErrOAuthReauthRequired
		}
		return nil, s.decryptFailure(ctx, row, oerr)
	}
	return token, nil
}

// converge re-reads the row once after a lost CAS and serves the winner's access
// token. It never mutates: a second write could destroy a grant another writer
// already proved valid. A winner that is still stale or tokenless yields the
// retryable exchange failure, because the next request will read it afresh.
func (s *service) converge(ctx context.Context, stale db.OAuthAccount) (*OAuthToken, error) {
	winner, err := s.rereadOwned(ctx, stale)
	if err != nil {
		return nil, err
	}
	return s.serveGrant(ctx, *winner)
}

// refreshFlightTimeout bounds the shared exchange. It covers the provider call
// plus the store writes that follow a successful rotation, so a bounded flight
// can never abandon a grant the provider already spent.
const refreshFlightTimeout = oauthHTTPTimeout + 5*time.Second

// refreshAccessToken renews an expired grant on demand. Concurrent callers for
// one account share a single exchange; the shared result is copied so no two
// callers receive the same mutable value. Each caller waits on its own context,
// and the shared exchange runs detached from the caller that started it: a
// canceled request may abandon its own wait, never the flight's write.
func (s *service) refreshAccessToken(ctx context.Context, link db.OAuthAccount) (*OAuthToken, error) {
	result := s.refreshFlight.DoChan(link.ID.String(), func() (any, error) {
		flightCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshFlightTimeout)
		defer cancel()
		return s.exchangeRefreshToken(flightCtx, link)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case shared := <-result:
		if shared.Err != nil {
			return nil, shared.Err
		}
		token, ok := shared.Val.(*OAuthToken)
		if !ok || token == nil {
			return nil, errors.New(errors.CodeInternalError, "oauth token refresh produced no token", nil)
		}
		view := *token
		return &view, nil
	}
}

// exchangeRefreshToken renews a grant against the provider. The request runs
// with no database transaction held, and the rotated pair is persisted with a
// CAS keyed on the fingerprint that was read: a concurrent rotation is never
// overwritten, and losing that CAS serves the winner instead.
func (s *service) exchangeRefreshToken(ctx context.Context, link db.OAuthAccount) (*OAuthToken, error) {
	if link.RefreshTokenCiphertext == "" || link.RefreshTokenFingerprint == "" {
		return nil, errors.ErrOAuthReauthRequired
	}
	// The snapshot comes from the caller's pre-read and another instance may have
	// used the grant since. X invalidates a refresh token on use, so presenting a
	// stale one is a guaranteed invalid_grant and a pointless clear attempt:
	// re-read and serve a row that already moved on.
	current, err := s.rereadOwned(ctx, link)
	if err != nil {
		return nil, err
	}
	if current.RefreshTokenFingerprint != link.RefreshTokenFingerprint ||
		current.RefreshTokenCiphertext != link.RefreshTokenCiphertext {
		return s.serveGrant(ctx, *current)
	}
	if current.AccessTokenCiphertext != "" && tokenFresh(current.TokenExpiresAt, time.Now().UTC()) {
		// The same grant was rewritten with a usable access token in the window.
		return s.serveGrant(ctx, *current)
	}
	provider, err := s.providerFor(link.ProviderID)
	if err != nil {
		return nil, err
	}
	refresher, ok := provider.(TokenRefresher)
	if !ok {
		// Re-authentication cannot install a capability the deployment lacks.
		return nil, errors.ErrOAuthRefreshUnsupported
	}
	refreshToken, err := s.sealer.OpenRefreshToken(link.ProviderID, link.ID.String(), link.RefreshTokenCiphertext)
	if err != nil {
		if isMalformedEnvelope(err) {
			return s.discardGrant(ctx, link)
		}
		return nil, s.decryptFailure(ctx, link, err)
	}

	refreshed, err := refresher.RefreshToken(ctx, refreshToken)
	if err != nil {
		return s.refreshFailure(ctx, link, err)
	}
	if refreshed == nil || refreshed.AccessToken == "" {
		return nil, errors.ErrOAuthTokenExchangeFailed
	}
	if refreshed.RefreshToken == "" {
		// Keeping the presented token is what lets the row renew again; a
		// provider that does not rotate must not erase the only credential.
		refreshed.RefreshToken = refreshToken
	}
	rec, err := s.sealedTokens(link.ProviderID, link.ID.String(), refreshed)
	if err != nil {
		return nil, err
	}
	// RFC 6749 §6: a refresh response that omits scope leaves the grant
	// unchanged, and the CAS rewrites every token column.
	if rec.TokenScope == "" {
		rec.TokenScope = link.TokenScope
	}
	won, err := s.store.OAuthAccounts().SaveOAuthTokensCAS(ctx, link.ID, link.RefreshTokenFingerprint, rec)
	if err != nil {
		logTokenEvent(ctx, "oauth_token_refresh_persist_failed", link)
		return nil, errors.ErrOAuthTokenExchangeFailed
	}
	if !won {
		return s.persistPastClear(ctx, link, rec, refreshed)
	}
	return refreshedAccess(refreshed), nil
}

// persistPastClear stores a pair the provider just issued when the persist CAS
// lost because a concurrent clear emptied the row. The provider already spent
// the presented token, so the pair in hand is the only grant left; dropping it
// would force a re-login for a rotation that succeeded. The write is guarded
// like any other first grant: a row that was filled after the reread holds the
// newer grant and is served instead of being overwritten.
func (s *service) persistPastClear(ctx context.Context, link db.OAuthAccount, rec db.OAuthTokenRecord, refreshed *OAuthToken) (*OAuthToken, error) {
	current, err := s.rereadOwned(ctx, link)
	if err != nil {
		return nil, err
	}
	if current.AccessTokenCiphertext != "" || current.RefreshTokenFingerprint != "" {
		return s.serveGrant(ctx, *current)
	}
	won, werr := s.store.OAuthAccounts().SaveOAuthTokensIfUnset(ctx, link.ID, rec)
	if werr != nil {
		logTokenEvent(ctx, "oauth_token_refresh_persist_failed", link)
		return nil, errors.ErrOAuthTokenExchangeFailed
	}
	if !won {
		return s.converge(ctx, link)
	}
	return refreshedAccess(refreshed), nil
}

// refreshFailure maps a failed exchange. Only the provider's own grant
// rejection may destroy a stored token set: a transport fault, a 5xx, a 429, or
// a bad client credential leaves the grant for the next attempt. A rejected
// client credential is not separable from a transport fault at this boundary, so
// both report the retryable exchange failure rather than a dead grant.
func (s *service) refreshFailure(ctx context.Context, link db.OAuthAccount, err error) (*OAuthToken, error) {
	if errors.Is(err, errors.ErrOAuthGrantRejected) {
		return s.discardGrant(ctx, link)
	}
	if _, ok := RetryAfterFromError(err); ok || errors.Is(err, errors.ErrOAuthRateLimitExceeded) {
		return nil, err
	}
	return nil, errors.ErrOAuthTokenExchangeFailed
}

// refreshedAccess projects a renewed grant onto the caller-facing value. Raw is
// the provider's whole response body, which carries the refresh token, so it is
// dropped along with every other credential the caller must not receive. The
// token type is normalised to the canonical scheme so the answer does not depend
// on whether a refresh happened.
func refreshedAccess(tokens *OAuthToken) *OAuthToken {
	token := &OAuthToken{
		AccessToken: tokens.AccessToken,
		TokenType:   tokenTypeBearer,
	}
	if tokens.ExpiresIn > 0 {
		token.ExpiresIn = tokens.ExpiresIn
	}
	if expiresAt := tokenExpiry(tokens); expiresAt != nil {
		token.ExpiresAt = *expiresAt
	}
	return token
}

// logTokenEvent records a failure on the token path. Identity only: the record,
// the envelopes, and the fingerprints must never reach a log line.
func logTokenEvent(ctx context.Context, event string, link db.OAuthAccount) {
	slog.ErrorContext(ctx, event,
		"provider", link.ProviderID,
		"account_id", link.ID.String(),
	)
}

// InitiateFlow generates PKCE, persists verifier+state in the signed state
// cookie, and returns the provider authorization URL for a 302 redirect.
func (s *service) InitiateFlow(w http.ResponseWriter, r *http.Request, providerID string) (string, error) {
	if w == nil {
		return "", errors.New(errors.CodeValidationError, "invalid oauth initiate request", nil)
	}
	providerID = CanonicalProviderSlug(providerID)
	p, err := s.providerFor(providerID)
	if err != nil {
		return "", err
	}
	// No keyring means no grant could ever be stored: refuse the flow before a
	// state cookie is planted rather than sending the user through a login that
	// cannot complete.
	if s.sealer == nil {
		return "", errors.ErrOAuthTokenKEKMissing
	}
	pkce, err := GeneratePKCE()
	if err != nil {
		return "", err
	}
	// Only an OIDC provider checks an ID-token nonce at callback; storing one
	// for a plain Provider would persist an unread value for the whole state TTL.
	_, isOIDC := p.(OIDCProvider)
	nonce := ""
	if isOIDC {
		nonce, err = GenerateNonce()
		if err != nil {
			return "", err
		}
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
	if isOIDC {
		return oidcAuthURL(p, state, pkce.Challenge, nonce)
	}
	return p.AuthURL(state, pkce.Challenge), nil
}

// oidcAuthURL binds the login nonce into the authorization request. A provider
// that only implements Provider has no option channel, so the nonce is appended
// to its authorize URL: the callback verifies the ID-token nonce for every OIDC
// provider, and a request that never carried one could never satisfy that check.
func oidcAuthURL(p Provider, state, codeChallenge, nonce string) (string, error) {
	if ac, ok := p.(AuthCodeURLProvider); ok {
		return ac.AuthCodeURL(state, codeChallenge, NonceOption(nonce)), nil
	}
	u, err := url.Parse(p.AuthURL(state, codeChallenge))
	if err != nil {
		return "", errors.New(errors.CodeOAuthProviderError, "oauth provider returned an unusable authorize URL", err)
	}
	q := u.Query()
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// HandleCallback runs the full decision tree: state validation, code exchange,
// account linking or creation, session issuance, and state-cookie cleanup. The
// provider-verified gate lives inside the link path so an already-linked
// identity never needs an email (Apple omits it after first consent).
func (s *service) HandleCallback(ctx context.Context, w http.ResponseWriter, r *http.Request, providerID, code, state string, sessType db.SessionType) (*session.Session, string, string, error) {
	providerID = CanonicalProviderSlug(providerID)
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
	// Fail closed before the exchange: without a keyring the grant cannot be
	// stored, and burning the authorization code for an unusable login is worse
	// than refusing the callback. No user, link, or session row is created.
	if s.sealer == nil {
		return fail("token_kek_missing", errors.ErrOAuthTokenKEKMissing)
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
			if activeUserID != "" {
				// The initiation embedded an explicit link owner but no live
				// session resolves now. A lapsed session for a living owner
				// degrades to a plain login; a vanished owner fails closed
				// instead of minting an email-based login for an owner
				// nobody selected.
				if verr := s.checkLinkOwnerAlive(ctx, activeUserID); verr != nil {
					return fail("link_owner_gone", verr)
				}
				activeUserID = ""
			}
		} else if live != activeUserID {
			return fail("link_conflict", errors.ErrOAuthAccountAlreadyLinked)
		}
	}

	user, linked, created, err := s.linkOrCreate(ctx, providerID, info, activeUserID, tokens)
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

// providerTenantMaxLen matches the VARCHAR(64) tenant column. A tenant GUID is
// 36 characters; the bound exists so a misconfigured authority cannot overflow.
const providerTenantMaxLen = 64

// validateProviderIdentity gates the account-merge paths: a merge is the only
// step allowed to attach a provider identity to an existing local account, and
// an address the provider did not verify must never pass it. Order is
// load-bearing: an unverified identity reports OAUTH_EMAIL_UNVERIFIED before
// any field-validity rejection.
func validateProviderIdentity(info *UserInfo, providerID string) error {
	if strings.TrimSpace(info.Email) == "" {
		return errors.ErrOAuthEmailRequired
	}
	if !info.EmailVerified {
		return errors.ErrOAuthEmailUnverified
	}
	return validateProviderIdentityFields(info, providerID)
}

// validateProviderIdentityFields rejects identity fields that cannot be stored
// for a fresh registration, where an address is mandatory but its attestation
// only decides the link's trust state.
func validateProviderIdentityFields(info *UserInfo, providerID string) error {
	if strings.TrimSpace(info.Email) == "" {
		return errors.ErrOAuthEmailRequired
	}
	return validateIdentityFields(info, providerID)
}

// validateLinkTarget gates every write that persists provider identity fields:
// an email must be one the provider attested and the columns can hold. A
// subject-only identity (X, Apple repeat consent) has no address to attest and
// passes.
func validateLinkTarget(info *UserInfo, providerID string) error {
	if err := validateIdentityFields(info, providerID); err != nil {
		return err
	}
	if strings.TrimSpace(info.Email) != "" && !info.EmailVerified {
		return errors.ErrOAuthEmailUnverified
	}
	return nil
}

// validateIdentityFields bounds the identity values to what the users and
// oauth_accounts columns can hold. A tenant-scoped provider must name its
// tenant: storing an identity without one would key it on the tenant-blind
// (provider, subject) pair the schema no longer enforces.
func validateIdentityFields(info *UserInfo, providerID string) error {
	if info.ProviderUserID == "" || len(info.ProviderUserID) > providerFieldMaxLen {
		return errOAuthProviderIdentityInvalid
	}
	if len(info.ProviderTenantID) > providerTenantMaxLen {
		return errOAuthProviderIdentityInvalid
	}
	if providerID == "microsoft" && info.ProviderTenantID == "" {
		return errOAuthProviderIdentityInvalid
	}
	if strings.TrimSpace(info.Email) == "" {
		return nil
	}
	if len(info.Email) > providerFieldMaxLen || db.ValidateEmail(info.Email) != nil {
		return errOAuthProviderIdentityInvalid
	}
	return nil
}

// findLink loads the oauth_accounts row for a provider identity. found=false
// with a nil error is the normal no-link case; anything else is a query failure.
// The tenant is part of the identity: a pairwise subject is only unique inside
// the tenant that issued it, so a probe never sees another tenant's row.
func (s *service) findLink(ctx context.Context, providerID, providerTenantID, providerUserID string) (db.OAuthAccount, bool, error) {
	link, err := s.store.OAuthAccounts().GetByProvider(ctx, providerID, providerTenantID, providerUserID)
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

// insertLink writes the oauth_accounts row for userID, sealed grant included.
// errLinkConflict means a concurrent callback already claimed (providerID,
// tenant, providerUserID). verified mirrors the callback's provider attestation
// and is never inferred.
func (s *service) insertLink(ctx context.Context, accountStore db.OAuthAccountStore, userID uuid.UUID, providerID, providerTenantID, providerUserID, email string, verified bool, tokens *OAuthToken) error {
	row := db.OAuthAccount{
		ID:               uuid.New(),
		UserID:           userID,
		ProviderID:       providerID,
		ProviderTenantID: providerTenantID,
		ProviderUserID:   providerUserID,
		Email:            email,
		Verified:         verified,
	}
	// Sealed per invocation: Transaction may re-run its callback with a
	// regenerated row id, and the AAD binds each envelope to the id it was
	// written for. A record sealed above the callback would become undecryptable.
	rec, err := s.sealedTokens(row.ProviderID, row.ID.String(), tokens)
	if err != nil {
		return err
	}
	applyTokenRecord(&row, rec)
	if err := accountStore.Create(ctx, &row); err != nil {
		if isUniqueViolation(err) {
			return errLinkConflict
		}
		return err
	}
	return nil
}

// sealedTokens builds the sealed grant for the row identified by accountID. The
// AAD always comes from the persisted row, never from the callback argument. A
// grant without a refresh token yields an empty refresh envelope: readers that
// must keep a stored one preserve it themselves (see writeGrant).
func (s *service) sealedTokens(providerID, accountID string, tokens *OAuthToken) (db.OAuthTokenRecord, error) {
	rec := db.OAuthTokenRecord{
		TokenExpiresAt: tokenExpiry(tokens),
		TokenScope:     tokenScope(tokens),
	}
	if tokens == nil {
		return rec, nil
	}
	access, err := s.sealer.SealAccessToken(providerID, accountID, tokens.AccessToken)
	if err != nil {
		return db.OAuthTokenRecord{}, errors.New(errors.CodeInternalError, "failed to seal oauth access token", err)
	}
	rec.AccessTokenCiphertext = access
	if tokens.RefreshToken == "" {
		return rec, nil
	}
	refresh, err := s.sealer.SealRefreshToken(providerID, accountID, tokens.RefreshToken)
	if err != nil {
		return db.OAuthTokenRecord{}, errors.New(errors.CodeInternalError, "failed to seal oauth refresh token", err)
	}
	fingerprint, err := s.sealer.RefreshTokenFingerprint(tokens.RefreshToken)
	if err != nil {
		return db.OAuthTokenRecord{}, errors.New(errors.CodeInternalError, "failed to fingerprint oauth refresh token", err)
	}
	rec.RefreshTokenCiphertext = refresh
	rec.RefreshTokenFingerprint = fingerprint
	return rec, nil
}

// tokenScope reads the granted scope the provider echoed in the token body.
func tokenScope(tokens *OAuthToken) string {
	if tokens == nil || tokens.Raw == nil {
		return ""
	}
	scope, _ := tokens.Raw["scope"].(string)
	return scope
}

// applyTokenRecord writes the sealed grant onto the row it was sealed for.
func applyTokenRecord(row *db.OAuthAccount, rec db.OAuthTokenRecord) {
	row.AccessTokenCiphertext = rec.AccessTokenCiphertext
	row.RefreshTokenCiphertext = rec.RefreshTokenCiphertext
	row.RefreshTokenFingerprint = rec.RefreshTokenFingerprint
	row.TokenScope = rec.TokenScope
	row.TokenExpiresAt = rec.TokenExpiresAt
}

// attachLink attaches the provider identity to ownerID in one transaction: the
// owner is re-read under a row lock, the claim gate is evaluated on that locked
// row, and the link insert commits inside the same transaction. A concurrent
// claim or revocation therefore either lands before the gate (and is honoured)
// or blocks until the insert commits; it can no longer slip between a stale read
// and the write. Losing the unique race converges on the winner's row, which
// reports linked=false.
func (s *service) attachLink(ctx context.Context, ownerID uuid.UUID, providerID string, info *UserInfo, tokens *OAuthToken) (db.User, bool, error) {
	var owner db.User
	linked := false
	err := s.store.Transaction(ctx, func(txStore db.Store) error {
		locked, lerr := txStore.Users().GetByIDForUpdate(ctx, ownerID)
		if lerr != nil {
			if errors.Is(lerr, gorm.ErrRecordNotFound) || errors.Is(lerr, errors.ErrUserNotFound) {
				return errors.ErrOAuthAccountNotLinked
			}
			return errors.New(errors.CodeInternalError, "failed to load linking user", lerr)
		}
		if locked == nil {
			return errors.ErrOAuthAccountNotLinked
		}
		if !isClaimedAccount(*locked) {
			return errors.ErrOAuthAccountLinkConflict
		}
		owner = *locked
		email := info.Email
		verified := info.EmailVerified
		if email == "" {
			// Subject-only identity (e.g. Apple, X) explicitly attached by
			// an authenticated owner carries no email and is trusted.
			verified = true
		}
		if ierr := s.insertLink(ctx, txStore.OAuthAccounts(), owner.ID, providerID, info.ProviderTenantID, info.ProviderUserID, email, verified, tokens); ierr != nil {
			return ierr
		}
		linked = true
		return nil
	})
	if err != nil {
		if errors.Is(err, errLinkConflict) {
			user, _, _, rerr := s.relinkExisting(ctx, providerID, info.ProviderTenantID, info.ProviderUserID)
			return user, false, rerr
		}
		if errors.Is(err, errors.ErrOAuthAccountNotLinked) || errors.Is(err, errors.ErrOAuthAccountLinkConflict) {
			return db.User{}, false, err
		}
		return db.User{}, false, errors.New(errors.CodeInternalError, "failed to link oauth account", err)
	}
	return owner, linked, nil
}

// linkedUser resolves the owner and row of an existing provider link.
// found=false with a nil error means no link exists yet.
func (s *service) linkedUser(ctx context.Context, providerID, providerTenantID, providerUserID string) (db.User, db.OAuthAccount, bool, error) {
	link, found, err := s.findLink(ctx, providerID, providerTenantID, providerUserID)
	if err != nil {
		return db.User{}, db.OAuthAccount{}, false, errors.New(errors.CodeInternalError, "failed to query oauth account", err)
	}
	if !found {
		return db.User{}, db.OAuthAccount{}, false, nil
	}
	user, err := s.loadLinkedUser(ctx, link)
	if err != nil {
		return db.User{}, link, true, err
	}
	return user, link, true, nil
}

// resolveLinkedUser resolves the owner and row of an existing provider link.
// If the primary lookup by providerUserID misses, and the provider is Microsoft
// with an oid claim present in RawClaims, it falls back to looking up by oid
// within the same tenant. When found via fallback, the link is updated to sub so
// the legacy row is migrated. Both probes carry the tenant: an unqualified
// fallback would re-open the cross-tenant match this key exists to prevent.
func (s *service) resolveLinkedUser(ctx context.Context, providerID string, info *UserInfo) (db.User, db.OAuthAccount, bool, error) {
	user, link, found, err := s.linkedUser(ctx, providerID, info.ProviderTenantID, info.ProviderUserID)
	if err != nil || found {
		return user, link, found, err
	}
	if providerID != "microsoft" || info.RawClaims == nil {
		return db.User{}, db.OAuthAccount{}, false, nil
	}
	oid, _ := info.RawClaims["oid"].(string)
	if oid == "" || oid == info.ProviderUserID {
		return db.User{}, db.OAuthAccount{}, false, nil
	}
	legacyLink, legacyFound, lerr := s.findLink(ctx, providerID, info.ProviderTenantID, oid)
	if lerr != nil {
		return db.User{}, db.OAuthAccount{}, false, errors.New(errors.CodeInternalError, "failed to query oauth account", lerr)
	}
	if !legacyFound {
		// Callback 1 may have migrated oid to sub concurrently between our
		// primary linkedUser lookup and our findLink(oid) fallback. Retry
		// linkedUser by sub before assuming the user is unlinked.
		return s.linkedUser(ctx, providerID, info.ProviderTenantID, info.ProviderUserID)
	}
	// Migrate the legacy link row's provider_user_id to the primary sub key.
	if uerr := s.store.OAuthAccounts().UpdateProviderUserID(ctx, legacyLink.ID, info.ProviderUserID); uerr != nil {
		if isUniqueViolation(uerr) {
			return s.linkedUser(ctx, providerID, info.ProviderTenantID, info.ProviderUserID)
		}
		return db.User{}, db.OAuthAccount{}, false, errors.New(errors.CodeInternalError, "failed to update provider user id", uerr)
	}
	legacyLink.ProviderUserID = info.ProviderUserID
	owner, oerr := s.loadLinkedUser(ctx, legacyLink)
	if oerr != nil {
		return db.User{}, legacyLink, true, oerr
	}
	return owner, legacyLink, true, nil
}

// relinkExisting re-reads the link row that won a concurrent insert race and
// loads its owner. Used when our insert hits the unique constraint.
func (s *service) relinkExisting(ctx context.Context, providerID, providerTenantID, providerUserID string) (db.User, bool, bool, error) {
	user, link, found, err := s.linkedUser(ctx, providerID, providerTenantID, providerUserID)
	if err != nil || !found {
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query oauth account", err)
	}
	if !link.Verified && link.Email != "" && isClaimedAccount(user) {
		s.invalidateLink(ctx, link)
		return db.User{}, false, false, errors.ErrOAuthEmailUnverified
	}
	return user, false, false, nil
}

// linkRacedUser converges after losing a concurrent user-create race: re-read
// the winner by normalized email, then decide. The 409 is permanent by design:
// it mirrors password signup, which refuses an already-registered email instead
// of taking it over, and no verification-mail or takeover flow exists here, so
// the address stays blocked until the squatted row is removed out of band.
func (s *service) linkRacedUser(ctx context.Context, providerID string, info *UserInfo, tokens *OAuthToken) (db.User, bool, bool, error) {
	existing, err := s.findUserByEmail(ctx, info.Email)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) && !errors.Is(err, errors.ErrUserNotFound) {
			return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query user", err)
		}
		// No winner is visible, so there is nothing to converge on: an unverified
		// claim stays a hard rejection.
		if !info.EmailVerified {
			return db.User{}, false, false, errors.ErrOAuthEmailUnverified
		}
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query user", err)
	}
	return s.mergeOrConverge(ctx, providerID, existing, info, tokens)
}

// mergeOrConverge decides what an address collision with a live local account
// may do. An unverified provider claim never merges into an established
// account and never resolves an account by email alone. It may only converge
// on an existing row if the provider identity
// (provider_id, provider_tenant_id, provider_user_id) already matches that row,
// ensuring an unattested email cannot take over an
// unclaimed account. The create-race path and the pre-existing-owner path share
// this rule so the outcome cannot depend on which goroutine observes the winner's
// commit first.
func (s *service) mergeOrConverge(ctx context.Context, providerID string, existing db.User, info *UserInfo, tokens *OAuthToken) (db.User, bool, bool, error) {
	if gerr := validateProviderIdentity(info, providerID); gerr != nil {
		if errors.Is(gerr, errors.ErrOAuthEmailUnverified) && !isClaimedAccount(existing) {
			link, found, err := s.findLink(ctx, providerID, info.ProviderTenantID, info.ProviderUserID)
			if err != nil {
				return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query oauth account", err)
			}
			if !found && providerID == "microsoft" && info.RawClaims != nil {
				if oid, _ := info.RawClaims["oid"].(string); oid != "" && oid != info.ProviderUserID {
					legacyLink, legacyFound, lerr := s.findLink(ctx, providerID, info.ProviderTenantID, oid)
					if lerr != nil {
						return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query oauth account", lerr)
					}
					if legacyFound {
						link = legacyLink
						found = true
						if uerr := s.store.OAuthAccounts().UpdateProviderUserID(ctx, link.ID, info.ProviderUserID); uerr != nil {
							if isUniqueViolation(uerr) {
								racedLink, rfound, rerr := s.findLink(ctx, providerID, info.ProviderTenantID, info.ProviderUserID)
								if rerr != nil {
									return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query oauth account", rerr)
								}
								if !rfound {
									return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to update provider user id", uerr)
								}
								link = racedLink
							} else {
								return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to update provider user id", uerr)
							}
						} else {
							link.ProviderUserID = info.ProviderUserID
						}
					}
				}
			}
			if found && link.UserID == existing.ID {
				// The concurrent signup wrote the row this callback converges on.
				// Its grant is the one the login just obtained, so store it — but
				// only while the row still holds no grant, or a later login's
				// token set would be overwritten by this older exchange.
				s.keepFirstGrant(ctx, link, tokens)
				return existing, false, false, nil
			}
		}
		return db.User{}, false, false, gerr
	}
	// Pre-hijacking defense: an attested provider identity attaches only to an
	// owner with local proof of the address. The check runs on the row-locked
	// owner inside attachLink, so a claim or revocation that lands mid-flight is
	// observed rather than overwritten.
	user, linked, lerr := s.attachLink(ctx, existing.ID, providerID, info, tokens)
	if lerr != nil {
		return db.User{}, false, false, lerr
	}
	// Losing the insert race converges on the winning row; handing back a
	// foreign owner would mint their session for this flow.
	if user.ID != existing.ID {
		return db.User{}, false, false, errors.ErrOAuthAccountAlreadyLinked
	}
	return user, linked, false, nil
}

// isClaimedAccount reports whether the owner holds local proof of address
// ownership. users.email_verified is set only by a flow that delivered a secret
// to the mailbox (verification) or consumed one from it (password reset). A
// password alone is not proof: anyone can set one on an unverified address, so
// it must never authorize attaching a provider identity to that account.
func isClaimedAccount(u db.User) bool {
	return u.EmailVerified
}

// invalidateLink deletes a link that must never sign in again: a spent
// unverified link, or a verified one whose tenant dropped out of the allowlist.
// The delete is best-effort by design: the refusal does not depend on it because
// link trust is re-derived from the owner and the tenant on every callback, so a
// store failure is logged rather than turning a rejected login into a 500.
func (s *service) invalidateLink(ctx context.Context, link db.OAuthAccount) {
	if err := s.store.OAuthAccounts().Delete(ctx, link.ID); err != nil {
		slog.WarnContext(ctx, "oauth_link_invalidate_failed",
			"provider", link.ProviderID,
			"user_id", link.UserID.String(),
			"error", err.Error(),
		)
	}
}

// createUserAndLink creates the user and its oauth_accounts row in one
// transaction. The row records whether the provider attested the address:
// verified rows may merge, recover, and resolve by email; unverified rows only
// sign in the account they were created on, and only while that account carries
// no local proof of the address. Separate inserts would let a cancel land
// between them (verified user, no link) or a lost link race orphan the loser's
// user. Session creation stays post-commit: cookie issuance cannot roll back.
// Unique conflicts roll the transaction back before converging on the winner.
func (s *service) createUserAndLink(ctx context.Context, providerID string, info *UserInfo, tokens *OAuthToken) (db.User, bool, bool, error) {
	user := db.User{
		ID:            uuid.New(),
		Email:         info.Email,
		PasswordHash:  "",
		EmailVerified: info.EmailVerified,
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
		if err := s.insertLink(ctx, txStore.OAuthAccounts(), user.ID, providerID, info.ProviderTenantID, info.ProviderUserID, info.Email, info.EmailVerified, tokens); err != nil {
			linkConflict = errors.Is(err, errLinkConflict)
			return err
		}
		return nil
	})
	if txErr != nil {
		if userConflict {
			return s.linkRacedUser(ctx, providerID, info, tokens)
		}
		if linkConflict {
			return s.relinkExisting(ctx, providerID, info.ProviderTenantID, info.ProviderUserID)
		}
		return db.User{}, false, false, errors.New(errors.CodeInternalError, op, txErr)
	}
	return user, info.EmailVerified, true, nil
}

// grantForRow seals the grant for link, keeping the stored scope when the
// provider omitted one (RFC 6749 §4.1.4 makes it optional on both paths).
func (s *service) grantForRow(link db.OAuthAccount, tokens *OAuthToken) (db.OAuthTokenRecord, error) {
	rec, err := s.sealedTokens(link.ProviderID, link.ID.String(), tokens)
	if err != nil {
		return db.OAuthTokenRecord{}, err
	}
	if rec.TokenScope == "" {
		rec.TokenScope = link.TokenScope
	}
	return rec, nil
}

// persistTokens stores the grant for an already-linked identity under the guard
// writeGrant applies. A failure is swallowed by design: the login's identity
// decision is already valid, so refusing it would punish a user for a transient
// store fault that the next callback repairs. The attributes stop at the
// identity — a driver error may echo row values, and no envelope, fingerprint,
// or token is ever logged.
func (s *service) persistTokens(ctx context.Context, link db.OAuthAccount, tokens *OAuthToken) {
	rec, err := s.grantForRow(link, tokens)
	if err == nil {
		err = s.writeGrant(ctx, link, rec, tokens)
	}
	if err != nil {
		slog.ErrorContext(ctx, "oauth_token_persist_failed",
			"provider", link.ProviderID,
			"account_id", link.ID.String(),
		)
	}
}

// keepFirstGrant stores the grant a login just obtained for a row a concurrent
// signup created, guarded so it wins only while that row still holds no refresh
// token. Losing the guard leaves the newer stored grant alone; a failure is
// swallowed like any other token write on the login path.
func (s *service) keepFirstGrant(ctx context.Context, link db.OAuthAccount, tokens *OAuthToken) {
	rec, err := s.grantForRow(link, tokens)
	if err == nil {
		_, err = s.store.OAuthAccounts().SaveOAuthTokensIfUnset(ctx, link.ID, rec)
	}
	if err != nil {
		slog.ErrorContext(ctx, "oauth_token_persist_failed",
			"provider", link.ProviderID,
			"account_id", link.ID.String(),
		)
	}
}

// writeGrant stores rec for an existing row, keeping a stored refresh envelope
// the new grant did not replace: providers that issue a refresh token on first
// consent only would otherwise lose the credential a re-login never re-issues.
// A grant that carries no refresh token never touches the refresh columns, so it
// cannot erase one another callback stored after this one read the row. When the
// row it read already holds a refresh envelope, that write is a CAS on the
// stored fingerprint, so a concurrent rotation wins instead of being overwritten
// by the older grant. A refresh-bearing grant for a row that held none is
// written under the same guard: a first grant that landed after the read is
// never replaced by an older exchange.
func (s *service) writeGrant(ctx context.Context, link db.OAuthAccount, rec db.OAuthTokenRecord, tokens *OAuthToken) error {
	carriesRefresh := tokens != nil && tokens.RefreshToken != ""
	if link.RefreshTokenCiphertext == "" || link.RefreshTokenFingerprint == "" {
		if !carriesRefresh {
			return s.store.OAuthAccounts().SaveOAuthAccess(ctx, link.ID, rec)
		}
		_, err := s.store.OAuthAccounts().SaveOAuthTokensIfUnset(ctx, link.ID, rec)
		return err
	}
	if !carriesRefresh {
		rec.RefreshTokenCiphertext = link.RefreshTokenCiphertext
		rec.RefreshTokenFingerprint = link.RefreshTokenFingerprint
	}
	_, err := s.store.OAuthAccounts().SaveOAuthTokensCAS(ctx, link.ID, link.RefreshTokenFingerprint, rec)
	return err
}

// linkOrCreate executes the linking decision tree. Returns the user plus
// whether an oauth_accounts row was inserted and whether the user was created.
// Concurrent duplicate callbacks converge idempotently: a unique-constraint
// loss re-reads the winner instead of 500ing.
func (s *service) linkOrCreate(ctx context.Context, providerID string, info *UserInfo, activeUserID string, tokens *OAuthToken) (db.User, bool, bool, error) {
	// 1. Returning user check: the provider identity resolves its owner. An
	// unverified link signs in only the account it was created on, and only
	// while that owner is unclaimed: once a verification or password reset
	// proves the address locally, the link is spent and is deleted here rather
	// than allowed to outlive its trust. Subject-only identities carry no email
	// and are immune to unverified-link invalidation.
	user, link, found, err := s.resolveLinkedUser(ctx, providerID, info)
	if err != nil {
		return db.User{}, false, false, err
	}

	var isUntrusted bool
	if info != nil && info.RawClaims != nil {
		isUntrusted, _ = info.RawClaims["untrusted_tenant"].(bool)
	}
	if isUntrusted {
		if found {
			s.invalidateLink(ctx, link)
		}
		return db.User{}, false, false, errors.ErrOAuthTenantInvalid
	}

	if found {
		if activeUserID != "" && user.ID.String() != activeUserID {
			return db.User{}, false, false, errors.ErrOAuthAccountAlreadyLinked
		}
		if !link.Verified && link.Email != "" && isClaimedAccount(user) {
			s.invalidateLink(ctx, link)
			return db.User{}, false, false, errors.ErrOAuthEmailUnverified
		}
		// Unconditional attempt: the provider may rotate the refresh token on
		// this grant. The identity decision above already stands, so a store
		// failure must not fail the login — the next callback repairs the row.
		// A grant that omits the refresh token keeps the stored one (see
		// persistTokens).
		s.persistTokens(ctx, link, tokens)
		return user, false, false, nil
	}

	// 2. Active session explicit linking: link provider to currently authenticated session user.
	// Fail closed: an unresolvable link owner never falls through to registration.
	if activeUserID != "" {
		uid, parseErr := uuid.Parse(activeUserID)
		if parseErr != nil {
			// A selected user that cannot be resolved must never fall through:
			// the email path would bind the identity to whoever owns the
			// provider address (or create a fresh account) instead of the
			// requested owner.
			return db.User{}, false, false, errors.ErrOAuthAccountNotLinked
		}
		owner, uerr := s.store.Users().GetByID(ctx, uid)
		if uerr != nil {
			if errors.Is(uerr, gorm.ErrRecordNotFound) || errors.Is(uerr, errors.ErrUserNotFound) {
				return db.User{}, false, false, errors.ErrOAuthAccountNotLinked
			}
			return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to load linking user", uerr)
		}
		// Store is pluggable: (nil, nil) violates the miss contract but must
		// fail closed rather than panic on the dereference below.
		if owner == nil {
			return db.User{}, false, false, errors.ErrOAuthAccountNotLinked
		}
		// An explicit link is a merge: the provider email may only be persisted
		// when the provider attests it, and no field may exceed its column. A
		// subject-only identity still binds without an address.
		if verr := validateLinkTarget(info, providerID); verr != nil {
			return db.User{}, false, false, verr
		}
		// Pre-hijacking defense, mirroring mergeOrConverge: only an owner with
		// local proof of the address may take a provider identity, and the gate
		// plus the insert are one transactional decision on the row-locked owner.
		// A password does not count as proof: a squatter can set one on an
		// address they do not own, and the link would outlive the owner's
		// recovery. The user must verify or reset first.
		user, linked, lerr := s.attachLink(ctx, owner.ID, providerID, info, tokens)
		if lerr != nil {
			return db.User{}, false, false, lerr
		}
		// Losing the insert race converges on the winning row; handing back a
		// foreign owner would mint their session for this flow.
		if user.ID != owner.ID {
			return db.User{}, false, false, errors.ErrOAuthAccountAlreadyLinked
		}
		return user, linked, false, nil
	}

	// 3. Validate the identity fields for unauthenticated registration. A
	// present-but-unverified address may register its own account: the link row
	// is always inserted, and its verified flag carries the provider's
	// attestation as-is, so the row grants no trust the claim did not have.
	if gerr := validateProviderIdentityFields(info, providerID); gerr != nil {
		return db.User{}, false, false, gerr
	}

	// 4. Existing local user check by email. Merging stays fail-closed through
	// mergeOrConverge: an unverified provider claim never resolves to or attaches
	// to an owner, only converging on the row a concurrent unverified signup left.
	existing, err := s.findUserByEmail(ctx, info.Email)
	if err == nil {
		return s.mergeOrConverge(ctx, providerID, existing, info, tokens)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) && !errors.Is(err, errors.ErrUserNotFound) {
		return db.User{}, false, false, errors.New(errors.CodeInternalError, "failed to query user", err)
	}
	return s.createUserAndLink(ctx, providerID, info, tokens)
}
