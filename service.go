package authkit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Clock abstracts time source for deterministic tests.
type Clock interface {
	Now() time.Time
}

// IDGenerator creates stable unique identifiers for entities.
type IDGenerator interface {
	NewID() string
}

// CodeGenerator creates auth intent codes.
type CodeGenerator interface {
	NewCode() (string, error)
}

// Config controls default authkit behavior.
type Config struct {
	DefaultIntentTTL              time.Duration
	DefaultRedemptionMode         IntentRedemptionMode
	DefaultReusableMaxRedemptions int
}

// DefaultConfig returns secure defaults while remaining practical.
func DefaultConfig() Config {
	return Config{
		DefaultIntentTTL:              15 * time.Minute,
		DefaultRedemptionMode:         IntentOneTime,
		DefaultReusableMaxRedemptions: 0, // unlimited
	}
}

type Option func(*AuthService) error

func WithClock(clock Clock) Option {
	return func(s *AuthService) error {
		if clock == nil {
			return fmt.Errorf("%w: nil clock", ErrInvalidInput)
		}
		s.clock = clock
		return nil
	}
}

func WithIDGenerator(gen IDGenerator) Option {
	return func(s *AuthService) error {
		if gen == nil {
			return fmt.Errorf("%w: nil id generator", ErrInvalidInput)
		}
		s.idGenerator = gen
		return nil
	}
}

func WithCodeGenerator(gen CodeGenerator) Option {
	return func(s *AuthService) error {
		if gen == nil {
			return fmt.Errorf("%w: nil code generator", ErrInvalidInput)
		}
		s.codeGenerator = gen
		return nil
	}
}

func WithConfig(cfg Config) Option {
	return func(s *AuthService) error {
		if cfg.DefaultIntentTTL < 0 {
			return fmt.Errorf("%w: default ttl must be >= 0", ErrInvalidInput)
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

// AuthService is the default implementation of Service.
type AuthService struct {
	intentStore   IntentStore
	linkStore     LinkStore
	sessionIssuer SessionIssuer
	clock         Clock
	idGenerator   IDGenerator
	codeGenerator CodeGenerator
	cfg           Config
}

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
		intentStore:   intentStore,
		linkStore:     linkStore,
		sessionIssuer: sessionIssuer,
		clock:         systemClock{},
		idGenerator:   UUIDGenerator{},
		codeGenerator: SecureCodeGenerator{NumBytes: 16},
		cfg:           DefaultConfig(),
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
		Metadata:        copyStringMap(in.Metadata),
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
	out.Attributes = copyStringMap(out.Attributes)
	out.BirthDate = copyTime(out.BirthDate)

	return &out, nil
}

func mergeIdentity(primary *Identity, secondary *Identity) *Identity {
	if primary == nil && secondary == nil {
		return nil
	}
	if primary == nil {
		out := *secondary
		out.Attributes = copyStringMap(out.Attributes)
		out.BirthDate = copyTime(out.BirthDate)
		return &out
	}
	if secondary == nil {
		out := *primary
		out.Attributes = copyStringMap(out.Attributes)
		out.BirthDate = copyTime(out.BirthDate)
		return &out
	}

	out := *primary
	out.Attributes = copyStringMap(primary.Attributes)
	out.BirthDate = copyTime(primary.BirthDate)

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
		out.BirthDate = copyTime(secondary.BirthDate)
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
	out.Attributes = copyStringMap(out.Attributes)
	out.BirthDate = copyTime(out.BirthDate)
	return &out
}

func copyIntent(intent AuthIntent) AuthIntent {
	out := intent
	out.Metadata = copyStringMap(intent.Metadata)
	out.ExpiresAt = copyTime(intent.ExpiresAt)
	out.ConsumedAt = copyTime(intent.ConsumedAt)
	if intent.Identity != nil {
		copiedIdentity := *intent.Identity
		copiedIdentity.Attributes = copyStringMap(intent.Identity.Attributes)
		copiedIdentity.BirthDate = copyTime(intent.Identity.BirthDate)
		out.Identity = &copiedIdentity
	}
	return out
}

func copyTime(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	t := *in
	return &t
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now()
}

type UUIDGenerator struct{}

func (UUIDGenerator) NewID() string {
	return uuid.NewString()
}

// SecureCodeGenerator creates cryptographically secure hex auth codes.
type SecureCodeGenerator struct {
	NumBytes int
}

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
