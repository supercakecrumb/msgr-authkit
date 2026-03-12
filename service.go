package authkit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/supercakecrumb/msgr-authkit/internal/cloneutil"
	"github.com/supercakecrumb/msgr-authkit/internal/timeutil"
)

// Clock abstracts time source for deterministic tests.
type Clock interface {
	// Now returns current time.
	Now() time.Time
}

// IDGenerator creates stable unique identifiers for entities.
type IDGenerator interface {
	// NewID returns a new non-empty identifier string.
	NewID() string
}

// CodeGenerator creates auth intent codes.
type CodeGenerator interface {
	// NewCode returns a new non-empty code string.
	NewCode() (string, error)
}

// Config controls default authkit behavior.
type Config struct {
	// DefaultIntentTTL is applied when CreateIntentInput.ExpiresAt is nil.
	// Zero or negative means "no default expiration".
	DefaultIntentTTL time.Duration
	// DefaultRedemptionMode is used when input redemption mode is empty.
	DefaultRedemptionMode IntentRedemptionMode
	// DefaultReusableMaxRedemptions is used when reusable mode is requested
	// with MaxRedemptions == 0. Zero means unlimited.
	DefaultReusableMaxRedemptions int
	// DefaultLoginLinkTTL is applied when CreateLoginLinkInput.LinkExpiresAt is
	// nil. Zero means use intent expiration (if any).
	DefaultLoginLinkTTL time.Duration
}

// DefaultConfig returns practical secure defaults:
//  1. intents expire in 15 minutes,
//  2. intents are one-time by default,
//  3. reusable intents are unlimited unless explicitly capped,
//  4. login-link tokens expire in 5 minutes.
func DefaultConfig() Config {
	return Config{
		DefaultIntentTTL:              15 * time.Minute,
		DefaultRedemptionMode:         IntentOneTime,
		DefaultReusableMaxRedemptions: 0, // unlimited
		DefaultLoginLinkTTL:           5 * time.Minute,
	}
}

// Option configures AuthService behavior.
type Option func(*AuthService) error

// WithClock overrides the time source used by AuthService.
// Useful for deterministic tests.
func WithClock(clock Clock) Option {
	return func(s *AuthService) error {
		if clock == nil {
			return fmt.Errorf("%w: nil clock", ErrInvalidInput)
		}
		s.clock = clock
		return nil
	}
}

// WithIDGenerator overrides internal ID generation for intents.
func WithIDGenerator(gen IDGenerator) Option {
	return func(s *AuthService) error {
		if gen == nil {
			return fmt.Errorf("%w: nil id generator", ErrInvalidInput)
		}
		s.idGenerator = gen
		return nil
	}
}

// WithCodeGenerator overrides auth-code generation for intents.
func WithCodeGenerator(gen CodeGenerator) Option {
	return func(s *AuthService) error {
		if gen == nil {
			return fmt.Errorf("%w: nil code generator", ErrInvalidInput)
		}
		s.codeGenerator = gen
		return nil
	}
}

// WithConfig overrides service defaults.
//
// Validation rules:
//  1. TTL values must be >= 0.
//  2. reusable max redemptions must be >= 0.
//  3. redemption mode must be one of IntentOneTime/IntentReusable.
func WithConfig(cfg Config) Option {
	return func(s *AuthService) error {
		if cfg.DefaultIntentTTL < 0 {
			return fmt.Errorf("%w: default ttl must be >= 0", ErrInvalidInput)
		}
		if cfg.DefaultLoginLinkTTL < 0 {
			return fmt.Errorf("%w: default login-link ttl must be >= 0", ErrInvalidInput)
		}
		if cfg.DefaultReusableMaxRedemptions < 0 {
			return fmt.Errorf("%w: default reusable max redemptions must be >= 0", ErrInvalidInput)
		}
		if cfg.DefaultRedemptionMode == "" {
			cfg.DefaultRedemptionMode = IntentOneTime
		}
		if cfg.DefaultRedemptionMode != IntentOneTime && cfg.DefaultRedemptionMode != IntentReusable {
			return fmt.Errorf("%w: unsupported default redemption mode %q", ErrInvalidInput, cfg.DefaultRedemptionMode)
		}
		s.cfg = cfg
		return nil
	}
}

// WithLoginTokenCodec configures token signing/parsing for bot-first login
// links. Requires WithLoginLinkBuilder (or WithSignedQueryLoginLinks) for
// CreateLoginLink to work.
func WithLoginTokenCodec(codec LoginTokenCodec) Option {
	return func(s *AuthService) error {
		if codec == nil {
			return fmt.Errorf("%w: nil login token codec", ErrInvalidInput)
		}
		s.loginTokenCodec = codec
		return nil
	}
}

// WithLoginLinkBuilder configures URL construction for bot-first login links.
// Requires WithLoginTokenCodec (or WithSignedQueryLoginLinks) for
// CreateLoginLink to work.
func WithLoginLinkBuilder(builder LoginLinkBuilder) Option {
	return func(s *AuthService) error {
		if builder == nil {
			return fmt.Errorf("%w: nil login link builder", ErrInvalidInput)
		}
		s.loginLinkBuilder = builder
		return nil
	}
}

// WithAudienceResolver configures dynamic audience derivation when
// CreateLoginLinkInput.Audience is empty.
func WithAudienceResolver(resolver AudienceResolver) Option {
	return func(s *AuthService) error {
		if resolver == nil {
			return fmt.Errorf("%w: nil audience resolver", ErrInvalidInput)
		}
		s.audienceResolver = resolver
		return nil
	}
}

// WithMissingIdentityLinkMode configures behavior when CreateLoginLink receives
// identity data but LinkStore has no mapping for that identity.
//
// Empty mode defaults to MissingIdentityLinkDeferred.
func WithMissingIdentityLinkMode(mode MissingIdentityLinkMode) Option {
	return func(s *AuthService) error {
		if mode == "" {
			mode = MissingIdentityLinkDeferred
		}
		switch mode {
		case MissingIdentityLinkDeferred, MissingIdentityLinkStrict, MissingIdentityLinkAutoProvision:
			s.missingIdentityLinkMode = mode
			return nil
		default:
			return fmt.Errorf("%w: unsupported missing identity link mode %q", ErrInvalidInput, mode)
		}
	}
}

// WithLinkProvisioner configures auto-provision hook used only when
// MissingIdentityLinkMode is MissingIdentityLinkAutoProvision.
func WithLinkProvisioner(provisioner LinkProvisioner) Option {
	return func(s *AuthService) error {
		if provisioner == nil {
			return fmt.Errorf("%w: nil link provisioner", ErrInvalidInput)
		}
		s.linkProvisioner = provisioner
		return nil
	}
}

// WithSignedQueryLoginLinks is a convenience option for bot-first flow setup.
// It configures an HMAC token codec and query-parameter link builder.
func WithSignedQueryLoginLinks(baseURL string, signingKey []byte, tokenQueryParam string) Option {
	return func(s *AuthService) error {
		if strings.TrimSpace(baseURL) == "" {
			return fmt.Errorf("%w: login-link base url is required", ErrInvalidInput)
		}
		if len(signingKey) == 0 {
			return fmt.Errorf("%w: login-link signing key is required", ErrInvalidInput)
		}
		keyCopy := make([]byte, len(signingKey))
		copy(keyCopy, signingKey)

		s.loginLinkBuilder = QueryLoginLinkBuilder{
			BaseURL:         strings.TrimSpace(baseURL),
			TokenQueryParam: strings.TrimSpace(tokenQueryParam),
		}
		s.loginTokenCodec = HMACLoginTokenCodec{SigningKey: keyCopy}
		return nil
	}
}

// AuthService is the default implementation of Service and BotFirstService.
type AuthService struct {
	intentStore             IntentStore
	linkStore               LinkStore
	sessionIssuer           SessionIssuer
	clock                   Clock
	idGenerator             IDGenerator
	codeGenerator           CodeGenerator
	loginTokenCodec         LoginTokenCodec
	loginLinkBuilder        LoginLinkBuilder
	audienceResolver        AudienceResolver
	missingIdentityLinkMode MissingIdentityLinkMode
	linkProvisioner         LinkProvisioner
	cfg                     Config
}

// NewAuthService creates an AuthService with required dependencies and options.
//
// Required dependencies:
//  1. IntentStore
//  2. SessionIssuer
//
// LinkStore is optional, but required for identity->subject resolution when
// SubjectID is not provided.
func NewAuthService(
	intentStore IntentStore,
	linkStore LinkStore,
	sessionIssuer SessionIssuer,
	opts ...Option,
) (*AuthService, error) {
	if intentStore == nil {
		return nil, fmt.Errorf("%w: nil intent store", ErrInvalidInput)
	}
	if sessionIssuer == nil {
		return nil, fmt.Errorf("%w: nil session issuer", ErrInvalidInput)
	}

	s := &AuthService{
		intentStore:             intentStore,
		linkStore:               linkStore,
		sessionIssuer:           sessionIssuer,
		clock:                   timeutil.SystemClock{},
		idGenerator:             UUIDGenerator{},
		codeGenerator:           SecureCodeGenerator{NumBytes: 16},
		missingIdentityLinkMode: MissingIdentityLinkDeferred,
		cfg:                     DefaultConfig(),
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// CreateIntent validates input, normalizes identity/messenger, applies default
// policy values, and persists an auth intent.
func (s *AuthService) CreateIntent(ctx context.Context, in CreateIntentInput) (AuthIntent, error) {
	if err := ctx.Err(); err != nil {
		return AuthIntent{}, err
	}

	now := s.clock.Now().UTC()
	messenger, err := resolveMessenger(in.Messenger, in.Identity)
	if err != nil {
		return AuthIntent{}, err
	}

	identity, err := normalizeIdentity(in.Identity, messenger)
	if err != nil {
		return AuthIntent{}, err
	}

	redemptionMode, maxRedemptions, err := s.resolveRedemptionPolicy(in.RedemptionMode, in.MaxRedemptions)
	if err != nil {
		return AuthIntent{}, err
	}

	expiresAt, err := s.resolveExpiresAt(in.ExpiresAt, now)
	if err != nil {
		return AuthIntent{}, err
	}

	intentID := strings.TrimSpace(s.idGenerator.NewID())
	if intentID == "" {
		return AuthIntent{}, ErrIDGenerationFailed
	}

	code, err := s.codeGenerator.NewCode()
	if err != nil {
		return AuthIntent{}, fmt.Errorf("%w: %v", ErrCodeGenerationFailed, err)
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return AuthIntent{}, ErrCodeGenerationFailed
	}

	intent := AuthIntent{
		ID:              intentID,
		Code:            code,
		Messenger:       messenger,
		Audience:        strings.TrimSpace(in.Audience),
		SubjectID:       strings.TrimSpace(in.SubjectID),
		State:           IntentActive,
		Identity:        identity,
		Metadata:        cloneutil.StringMap(in.Metadata),
		RedemptionMode:  redemptionMode,
		MaxRedemptions:  maxRedemptions,
		RedemptionCount: 0,
		ExpiresAt:       expiresAt,
		CreatedAt:       now,
	}

	if err := s.intentStore.Create(ctx, intent); err != nil {
		return AuthIntent{}, fmt.Errorf("authkit: create intent: %w", err)
	}

	return copyIntent(intent), nil
}

// RedeemIntent validates an existing intent, resolves subject id (direct or
// via LinkStore), records redemption, and issues a web session.
//
// Redemptions are consumed before session issuance to prioritize replay safety.
func (s *AuthService) RedeemIntent(ctx context.Context, in RedeemIntentInput) (WebSession, error) {
	if err := ctx.Err(); err != nil {
		return WebSession{}, err
	}

	code := strings.TrimSpace(in.Code)
	if code == "" {
		return WebSession{}, fmt.Errorf("%w: code is required", ErrInvalidInput)
	}

	messenger, err := resolveMessenger(in.Messenger, in.Identity)
	if err != nil {
		return WebSession{}, err
	}

	incomingIdentity, err := normalizeIdentity(in.Identity, messenger)
	if err != nil {
		return WebSession{}, err
	}

	intent, err := s.intentStore.FindByCode(ctx, messenger, code)
	if err != nil {
		if errors.Is(err, ErrIntentNotFound) {
			return WebSession{}, ErrIntentNotFound
		}
		return WebSession{}, fmt.Errorf("authkit: find intent: %w", err)
	}

	now := s.clock.Now().UTC()
	if err := validateIntentForRedemption(intent, now); err != nil {
		return WebSession{}, err
	}

	subjectID, err := s.resolveSubjectID(ctx, intent, incomingIdentity)
	if err != nil {
		return WebSession{}, err
	}

	// Security-first ordering: consume intent before issuing web session.
	// If session issuance fails, caller can create a new intent.
	if err := s.intentStore.RecordRedemption(ctx, intent.ID, now); err != nil {
		switch {
		case errors.Is(err, ErrIntentExpired):
			return WebSession{}, ErrIntentExpired
		case errors.Is(err, ErrIntentNotActive):
			return WebSession{}, ErrIntentNotActive
		case errors.Is(err, ErrIntentAlreadyRedeemed):
			return WebSession{}, ErrIntentAlreadyRedeemed
		case errors.Is(err, ErrIntentRedemptionLimitReached):
			return WebSession{}, ErrIntentRedemptionLimitReached
		case errors.Is(err, ErrIntentNotFound):
			return WebSession{}, ErrIntentNotFound
		default:
			return WebSession{}, fmt.Errorf("authkit: record redemption: %w", err)
		}
	}

	session, err := s.sessionIssuer.Issue(ctx, subjectID)
	if err != nil {
		return WebSession{}, fmt.Errorf("authkit: issue session: %w", err)
	}

	return session, nil
}

// CreateLoginLink creates an underlying intent and returns a signed short-lived
// login URL for bot-initiated flows.
//
// Requires both LoginTokenCodec and LoginLinkBuilder to be configured.
func (s *AuthService) CreateLoginLink(ctx context.Context, in CreateLoginLinkInput) (CreateLoginLinkOutput, error) {
	if err := ctx.Err(); err != nil {
		return CreateLoginLinkOutput{}, err
	}
	if s.loginTokenCodec == nil || s.loginLinkBuilder == nil {
		return CreateLoginLinkOutput{}, ErrLoginLinkNotConfigured
	}

	messenger, err := resolveMessenger(in.Messenger, in.Identity)
	if err != nil {
		return CreateLoginLinkOutput{}, err
	}
	identity, err := normalizeIdentity(in.Identity, messenger)
	if err != nil {
		return CreateLoginLinkOutput{}, err
	}

	audience := strings.TrimSpace(in.Audience)
	if audience == "" && s.audienceResolver != nil {
		resolvedAudience, resolveErr := s.audienceResolver.ResolveAudience(ctx, messenger, identity)
		if resolveErr != nil {
			return CreateLoginLinkOutput{}, fmt.Errorf("authkit: resolve audience: %w", resolveErr)
		}
		audience = strings.TrimSpace(resolvedAudience)
	}

	subjectID := strings.TrimSpace(in.SubjectID)
	if subjectID == "" {
		resolvedSubject, resolveErr := s.resolveCreateSubjectID(ctx, messenger, identity)
		if resolveErr != nil {
			return CreateLoginLinkOutput{}, resolveErr
		}
		subjectID = resolvedSubject
	}

	intent, err := s.CreateIntent(ctx, CreateIntentInput{
		Messenger:      messenger,
		Audience:       audience,
		SubjectID:      subjectID,
		Metadata:       in.Metadata,
		Identity:       identity,
		RedemptionMode: in.RedemptionMode,
		MaxRedemptions: in.MaxRedemptions,
		ExpiresAt:      in.IntentExpiresAt,
	})
	if err != nil {
		return CreateLoginLinkOutput{}, err
	}

	now := s.clock.Now().UTC()
	linkExpiresAt, err := s.resolveLoginLinkExpiresAt(in.LinkExpiresAt, intent.ExpiresAt, now)
	if err != nil {
		return CreateLoginLinkOutput{}, err
	}

	token, err := s.loginTokenCodec.Encode(ctx, LoginTokenClaims{
		IntentCode: intent.Code,
		Messenger:  intent.Messenger,
		ExpiresAt:  linkExpiresAt,
	})
	if err != nil {
		return CreateLoginLinkOutput{}, fmt.Errorf("authkit: encode login-link token: %w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return CreateLoginLinkOutput{}, ErrLoginLinkInvalid
	}

	loginURL, err := s.loginLinkBuilder.BuildURL(ctx, token)
	if err != nil {
		return CreateLoginLinkOutput{}, fmt.Errorf("authkit: build login-link url: %w", err)
	}
	loginURL = strings.TrimSpace(loginURL)
	if loginURL == "" {
		return CreateLoginLinkOutput{}, ErrLoginLinkInvalid
	}

	return CreateLoginLinkOutput{
		Intent:    intent,
		LoginURL:  loginURL,
		LinkToken: token,
		ExpiresAt: linkExpiresAt,
	}, nil
}

// RedeemLoginLink verifies the signed login-link token and then delegates to
// RedeemIntent to issue a web session.
func (s *AuthService) RedeemLoginLink(ctx context.Context, in RedeemLoginLinkInput) (WebSession, error) {
	if err := ctx.Err(); err != nil {
		return WebSession{}, err
	}
	if s.loginTokenCodec == nil {
		return WebSession{}, ErrLoginLinkNotConfigured
	}

	token := strings.TrimSpace(in.LinkToken)
	if token == "" {
		return WebSession{}, fmt.Errorf("%w: login link token is required", ErrInvalidInput)
	}

	claims, err := s.loginTokenCodec.Decode(ctx, token)
	if err != nil {
		if errors.Is(err, ErrLoginLinkInvalid) {
			return WebSession{}, ErrLoginLinkInvalid
		}
		return WebSession{}, fmt.Errorf("%w: %v", ErrLoginLinkInvalid, err)
	}

	intentCode := strings.TrimSpace(claims.IntentCode)
	messenger := NewMessenger(claims.Messenger.ID)
	if intentCode == "" || messenger.ID == "" || claims.ExpiresAt.IsZero() {
		return WebSession{}, ErrLoginLinkInvalid
	}

	now := s.clock.Now().UTC()
	if !claims.ExpiresAt.UTC().After(now) {
		return WebSession{}, ErrLoginLinkExpired
	}

	return s.RedeemIntent(ctx, RedeemIntentInput{
		Code:      intentCode,
		Messenger: messenger,
		Identity:  in.Identity,
	})
}

func (s *AuthService) resolveLoginLinkExpiresAt(input *time.Time, intentExpiresAt *time.Time, now time.Time) (time.Time, error) {
	if input != nil {
		if !input.UTC().After(now) {
			return time.Time{}, fmt.Errorf("%w: link_expires_at must be in the future", ErrInvalidInput)
		}
		return input.UTC(), nil
	}

	if s.cfg.DefaultLoginLinkTTL > 0 {
		expiresAt := now.Add(s.cfg.DefaultLoginLinkTTL)
		if intentExpiresAt != nil && intentExpiresAt.UTC().Before(expiresAt) {
			expiresAt = intentExpiresAt.UTC()
		}
		if !expiresAt.After(now) {
			return time.Time{}, ErrLoginLinkExpired
		}
		return expiresAt, nil
	}

	if intentExpiresAt != nil && intentExpiresAt.UTC().After(now) {
		return intentExpiresAt.UTC(), nil
	}

	return time.Time{}, ErrLoginLinkNotConfigured
}

func (s *AuthService) resolveCreateSubjectID(ctx context.Context, messenger Messenger, identity *Identity) (string, error) {
	if identity == nil {
		return "", nil
	}

	identity = ensureIdentityMessenger(identity, messenger)
	if strings.TrimSpace(identity.MessengerUserID) == "" {
		return "", nil
	}

	findLink := func() (AccountLink, error) {
		if s.linkStore == nil {
			return AccountLink{}, ErrIdentityLinkNotFound
		}
		link, err := s.linkStore.FindByIdentity(ctx, *identity)
		if err != nil {
			if errors.Is(err, ErrIdentityLinkNotFound) {
				return AccountLink{}, ErrIdentityLinkNotFound
			}
			return AccountLink{}, fmt.Errorf("authkit: resolve identity link on create: %w", err)
		}
		return link, nil
	}

	link, err := findLink()
	switch {
	case err == nil:
		subjectID := strings.TrimSpace(link.AppUserID)
		if subjectID == "" {
			return "", fmt.Errorf("%w: account link has empty app user id", ErrSubjectUnresolved)
		}
		return subjectID, nil
	case !errors.Is(err, ErrIdentityLinkNotFound):
		return "", err
	}

	switch s.missingIdentityLinkMode {
	case MissingIdentityLinkDeferred:
		return "", nil
	case MissingIdentityLinkStrict:
		return "", ErrIdentityLinkNotFound
	case MissingIdentityLinkAutoProvision:
		if s.linkProvisioner == nil {
			return "", ErrLoginLinkNotConfigured
		}
		provisioned, provisionErr := s.linkProvisioner.ProvisionLink(ctx, *identity)
		if provisionErr != nil {
			return "", fmt.Errorf("authkit: provision identity link: %w", provisionErr)
		}
		subjectID := strings.TrimSpace(provisioned.AppUserID)
		if subjectID == "" {
			return "", fmt.Errorf("%w: provisioned account link has empty app user id", ErrSubjectUnresolved)
		}
		if s.linkStore != nil {
			if upsertErr := s.linkStore.Upsert(ctx, provisioned); upsertErr != nil {
				return "", fmt.Errorf("authkit: persist provisioned identity link: %w", upsertErr)
			}
		}
		return subjectID, nil
	default:
		return "", fmt.Errorf("%w: unsupported missing identity link mode %q", ErrInvalidInput, s.missingIdentityLinkMode)
	}
}

func (s *AuthService) resolveRedemptionPolicy(mode IntentRedemptionMode, max int) (IntentRedemptionMode, int, error) {
	if mode == "" {
		mode = s.cfg.DefaultRedemptionMode
	}

	switch mode {
	case IntentOneTime:
		return IntentOneTime, 1, nil
	case IntentReusable:
		if max < 0 {
			return "", 0, fmt.Errorf("%w: max redemptions must be >= 0", ErrInvalidInput)
		}
		if max == 0 {
			max = s.cfg.DefaultReusableMaxRedemptions
		}
		return IntentReusable, max, nil
	default:
		return "", 0, fmt.Errorf("%w: unsupported redemption mode %q", ErrInvalidInput, mode)
	}
}

func (s *AuthService) resolveExpiresAt(in *time.Time, now time.Time) (*time.Time, error) {
	if in != nil {
		if !in.UTC().After(now) {
			return nil, fmt.Errorf("%w: expires_at must be in the future", ErrInvalidInput)
		}
		t := in.UTC()
		return &t, nil
	}

	if s.cfg.DefaultIntentTTL <= 0 {
		return nil, nil
	}
	t := now.Add(s.cfg.DefaultIntentTTL)
	return &t, nil
}

func (s *AuthService) resolveSubjectID(ctx context.Context, intent AuthIntent, inputIdentity *Identity) (string, error) {
	if subjectID := strings.TrimSpace(intent.SubjectID); subjectID != "" {
		return subjectID, nil
	}

	if s.linkStore == nil {
		return "", fmt.Errorf("%w: no subject id and no link store", ErrSubjectUnresolved)
	}

	identity := mergeIdentity(intent.Identity, inputIdentity)
	if identity == nil {
		return "", fmt.Errorf("%w: identity is missing", ErrSubjectUnresolved)
	}

	identity = ensureIdentityMessenger(identity, intent.Messenger)
	if strings.TrimSpace(identity.MessengerUserID) == "" {
		return "", fmt.Errorf("%w: messenger user id is required to resolve subject", ErrSubjectUnresolved)
	}

	link, err := s.linkStore.FindByIdentity(ctx, *identity)
	if err != nil {
		if errors.Is(err, ErrIdentityLinkNotFound) {
			return "", ErrIdentityLinkNotFound
		}
		return "", fmt.Errorf("authkit: resolve identity link: %w", err)
	}

	subjectID := strings.TrimSpace(link.AppUserID)
	if subjectID == "" {
		return "", fmt.Errorf("%w: account link has empty app user id", ErrSubjectUnresolved)
	}

	return subjectID, nil
}

func validateIntentForRedemption(intent AuthIntent, now time.Time) error {
	switch intent.RedemptionMode {
	case IntentOneTime:
		if intent.RedemptionCount >= 1 || intent.ConsumedAt != nil {
			return ErrIntentAlreadyRedeemed
		}
	case IntentReusable:
		if intent.MaxRedemptions > 0 && intent.RedemptionCount >= intent.MaxRedemptions {
			return ErrIntentRedemptionLimitReached
		}
	default:
		return fmt.Errorf("%w: unsupported intent redemption mode %q", ErrInvalidInput, intent.RedemptionMode)
	}

	if intent.State != IntentActive {
		return ErrIntentNotActive
	}

	if intent.ExpiresAt != nil && now.After(intent.ExpiresAt.UTC()) {
		return ErrIntentExpired
	}

	return nil
}

func resolveMessenger(m Messenger, identity *Identity) (Messenger, error) {
	resolved := NewMessenger(m.ID)
	if resolved.ID == "" && identity != nil {
		resolved = NewMessenger(identity.Messenger.ID)
	}
	if resolved.ID == "" {
		return Messenger{}, fmt.Errorf("%w: messenger is required", ErrInvalidInput)
	}
	return resolved, nil
}

func normalizeIdentity(identity *Identity, messenger Messenger) (*Identity, error) {
	if identity == nil {
		return nil, nil
	}

	out := *identity
	out.Messenger = NewMessenger(out.Messenger.ID)
	if out.Messenger.ID == "" {
		out.Messenger = messenger
	}
	if messenger.ID != "" && out.Messenger.ID != messenger.ID {
		return nil, fmt.Errorf("%w: identity messenger %q does not match request messenger %q", ErrInvalidInput, out.Messenger.ID, messenger.ID)
	}

	out.MessengerUserID = strings.TrimSpace(out.MessengerUserID)
	out.Username = strings.TrimSpace(out.Username)
	out.Name = strings.TrimSpace(out.Name)
	out.Surname = strings.TrimSpace(out.Surname)
	out.Attributes = cloneutil.StringMap(out.Attributes)
	out.BirthDate = cloneutil.TimePtr(out.BirthDate)

	return &out, nil
}

func mergeIdentity(primary *Identity, secondary *Identity) *Identity {
	if primary == nil && secondary == nil {
		return nil
	}
	if primary == nil {
		out := *secondary
		out.Attributes = cloneutil.StringMap(out.Attributes)
		out.BirthDate = cloneutil.TimePtr(out.BirthDate)
		return &out
	}
	if secondary == nil {
		out := *primary
		out.Attributes = cloneutil.StringMap(out.Attributes)
		out.BirthDate = cloneutil.TimePtr(out.BirthDate)
		return &out
	}

	out := *primary
	out.Attributes = cloneutil.StringMap(primary.Attributes)
	out.BirthDate = cloneutil.TimePtr(primary.BirthDate)

	if strings.TrimSpace(secondary.Messenger.ID) != "" {
		out.Messenger = NewMessenger(secondary.Messenger.ID)
	}
	if strings.TrimSpace(secondary.MessengerUserID) != "" {
		out.MessengerUserID = strings.TrimSpace(secondary.MessengerUserID)
	}
	if strings.TrimSpace(secondary.Username) != "" {
		out.Username = strings.TrimSpace(secondary.Username)
	}
	if strings.TrimSpace(secondary.Name) != "" {
		out.Name = strings.TrimSpace(secondary.Name)
	}
	if strings.TrimSpace(secondary.Surname) != "" {
		out.Surname = strings.TrimSpace(secondary.Surname)
	}
	if secondary.BirthDate != nil {
		out.BirthDate = cloneutil.TimePtr(secondary.BirthDate)
	}
	if len(secondary.Attributes) > 0 {
		if out.Attributes == nil {
			out.Attributes = make(map[string]string, len(secondary.Attributes))
		}
		for k, v := range secondary.Attributes {
			out.Attributes[k] = v
		}
	}

	return &out
}

func ensureIdentityMessenger(identity *Identity, messenger Messenger) *Identity {
	out := *identity
	if strings.TrimSpace(out.Messenger.ID) == "" {
		out.Messenger = messenger
	}
	out.Messenger = NewMessenger(out.Messenger.ID)
	out.Attributes = cloneutil.StringMap(out.Attributes)
	out.BirthDate = cloneutil.TimePtr(out.BirthDate)
	return &out
}

func copyIntent(intent AuthIntent) AuthIntent {
	out := intent
	out.Metadata = cloneutil.StringMap(intent.Metadata)
	out.ExpiresAt = cloneutil.TimePtr(intent.ExpiresAt)
	out.ConsumedAt = cloneutil.TimePtr(intent.ConsumedAt)
	if intent.Identity != nil {
		copiedIdentity := *intent.Identity
		copiedIdentity.Attributes = cloneutil.StringMap(intent.Identity.Attributes)
		copiedIdentity.BirthDate = cloneutil.TimePtr(intent.Identity.BirthDate)
		out.Identity = &copiedIdentity
	}
	return out
}

// QueryLoginLinkBuilder builds URLs by placing token into a query parameter.
// Example: https://example.com/auth/complete?auth_token=...
type QueryLoginLinkBuilder struct {
	// BaseURL is the destination endpoint that receives token query parameter.
	// Example: https://example.com/auth/complete
	BaseURL string
	// TokenQueryParam is the query parameter name for the token.
	// Empty value defaults to "auth_token".
	TokenQueryParam string
}

// BuildURL appends token as query parameter to BaseURL and returns final URL.
func (b QueryLoginLinkBuilder) BuildURL(ctx context.Context, token string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("%w: login-link token is required", ErrInvalidInput)
	}

	baseURL := strings.TrimSpace(b.BaseURL)
	if baseURL == "" {
		return "", ErrLoginLinkNotConfigured
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("%w: invalid login-link base url", ErrInvalidInput)
	}

	param := strings.TrimSpace(b.TokenQueryParam)
	if param == "" {
		param = "auth_token"
	}
	query := parsedURL.Query()
	query.Set(param, token)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

// HMACLoginTokenCodec signs/verifies login-link tokens with HMAC-SHA256.
type HMACLoginTokenCodec struct {
	// SigningKey is the shared secret used for HMAC signing.
	// The key must be non-empty.
	SigningKey []byte
}

type hmacLoginTokenPayload struct {
	IntentCode string `json:"intent_code"`
	Messenger  string `json:"messenger"`
	ExpiresAt  int64  `json:"expires_at"`
}

// Encode serializes claims and returns signed compact token in
// "<payload>.<signature>" format (both base64url without padding).
func (c HMACLoginTokenCodec) Encode(ctx context.Context, claims LoginTokenClaims) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(c.SigningKey) == 0 {
		return "", ErrLoginLinkNotConfigured
	}

	intentCode := strings.TrimSpace(claims.IntentCode)
	messenger := NewMessenger(claims.Messenger.ID).ID
	if intentCode == "" || messenger == "" || claims.ExpiresAt.IsZero() {
		return "", fmt.Errorf("%w: incomplete login-link claims", ErrInvalidInput)
	}

	payload := hmacLoginTokenPayload{
		IntentCode: intentCode,
		Messenger:  messenger,
		ExpiresAt:  claims.ExpiresAt.UTC().Unix(),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := loginTokenSignature(c.SigningKey, encodedPayload)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return encodedPayload + "." + encodedSignature, nil
}

// Decode verifies token signature and returns parsed claims.
// Returns ErrLoginLinkInvalid when token cannot be trusted.
func (c HMACLoginTokenCodec) Decode(ctx context.Context, token string) (LoginTokenClaims, error) {
	if err := ctx.Err(); err != nil {
		return LoginTokenClaims{}, err
	}
	if len(c.SigningKey) == 0 {
		return LoginTokenClaims{}, ErrLoginLinkNotConfigured
	}

	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return LoginTokenClaims{}, ErrLoginLinkInvalid
	}

	encodedPayload := strings.TrimSpace(parts[0])
	encodedSignature := strings.TrimSpace(parts[1])
	if encodedPayload == "" || encodedSignature == "" {
		return LoginTokenClaims{}, ErrLoginLinkInvalid
	}

	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return LoginTokenClaims{}, ErrLoginLinkInvalid
	}
	expectedSignature := loginTokenSignature(c.SigningKey, encodedPayload)
	if !hmac.Equal(signature, expectedSignature) {
		return LoginTokenClaims{}, ErrLoginLinkInvalid
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return LoginTokenClaims{}, ErrLoginLinkInvalid
	}
	var payload hmacLoginTokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return LoginTokenClaims{}, ErrLoginLinkInvalid
	}

	intentCode := strings.TrimSpace(payload.IntentCode)
	messenger := NewMessenger(payload.Messenger)
	if intentCode == "" || messenger.ID == "" || payload.ExpiresAt <= 0 {
		return LoginTokenClaims{}, ErrLoginLinkInvalid
	}

	return LoginTokenClaims{
		IntentCode: intentCode,
		Messenger:  messenger,
		ExpiresAt:  time.Unix(payload.ExpiresAt, 0).UTC(),
	}, nil
}

func loginTokenSignature(signingKey []byte, encodedPayload string) []byte {
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write([]byte(encodedPayload))
	return mac.Sum(nil)
}

// UUIDGenerator is default IDGenerator based on RFC4122 random UUIDs.
type UUIDGenerator struct{}

// NewID returns a new UUID string.
func (UUIDGenerator) NewID() string {
	return uuid.NewString()
}

// SecureCodeGenerator creates cryptographically secure hex auth codes.
type SecureCodeGenerator struct {
	// NumBytes is entropy size before hex encoding.
	// If NumBytes <= 0, 16 bytes are used.
	NumBytes int
}

// NewCode returns a cryptographically secure hex string.
func (g SecureCodeGenerator) NewCode() (string, error) {
	numBytes := g.NumBytes
	if numBytes <= 0 {
		numBytes = 16
	}
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
