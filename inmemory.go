package authkit

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/supercakecrumb/msgr-authkit/internal/cloneutil"
	"github.com/supercakecrumb/msgr-authkit/internal/timeutil"
)

// InMemoryIntentStore is a concurrency-safe intent store for local/dev use.
type InMemoryIntentStore struct {
	mu     sync.RWMutex
	byID   map[string]AuthIntent
	byCode map[string]string
}

func NewInMemoryIntentStore() *InMemoryIntentStore {
	return &InMemoryIntentStore{
		byID:   make(map[string]AuthIntent),
		byCode: make(map[string]string),
	}
}

func (s *InMemoryIntentStore) Create(ctx context.Context, intent AuthIntent) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	intentID := strings.TrimSpace(intent.ID)
	if intentID == "" {
		return fmt.Errorf("%w: intent id is required", ErrInvalidInput)
	}
	if strings.TrimSpace(intent.Code) == "" {
		return fmt.Errorf("%w: intent code is required", ErrInvalidInput)
	}
	if strings.TrimSpace(intent.Messenger.ID) == "" {
		return fmt.Errorf("%w: intent messenger is required", ErrInvalidInput)
	}

	key := intentCodeKey(intent.Messenger, intent.Code)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[intentID]; exists {
		return fmt.Errorf("%w: duplicate intent id", ErrInvalidInput)
	}
	if _, exists := s.byCode[key]; exists {
		return fmt.Errorf("%w: duplicate intent code for messenger", ErrInvalidInput)
	}

	copied := copyIntent(intent)
	s.byID[intentID] = copied
	s.byCode[key] = intentID
	return nil
}

func (s *InMemoryIntentStore) FindByCode(ctx context.Context, messenger Messenger, code string) (AuthIntent, error) {
	if err := ctx.Err(); err != nil {
		return AuthIntent{}, err
	}

	key := intentCodeKey(messenger, code)

	s.mu.RLock()
	intentID, exists := s.byCode[key]
	if !exists {
		s.mu.RUnlock()
		return AuthIntent{}, ErrIntentNotFound
	}
	intent, exists := s.byID[intentID]
	s.mu.RUnlock()
	if !exists {
		return AuthIntent{}, ErrIntentNotFound
	}

	return copyIntent(intent), nil
}

func (s *InMemoryIntentStore) RecordRedemption(ctx context.Context, intentID string, redeemedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	intentID = strings.TrimSpace(intentID)
	if intentID == "" {
		return fmt.Errorf("%w: intent id is required", ErrInvalidInput)
	}

	now := redeemedAt.UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	intent, exists := s.byID[intentID]
	if !exists {
		return ErrIntentNotFound
	}

	if intent.State != IntentActive {
		return ErrIntentNotActive
	}

	if intent.ExpiresAt != nil && now.After(intent.ExpiresAt.UTC()) {
		intent.State = IntentExpired
		s.byID[intentID] = intent
		return ErrIntentExpired
	}

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
		return fmt.Errorf("%w: unsupported redemption mode %q", ErrInvalidInput, intent.RedemptionMode)
	}

	intent.RedemptionCount++
	intent.ConsumedAt = &now

	if intent.RedemptionMode == IntentOneTime {
		intent.State = IntentRevoked
	}
	if intent.RedemptionMode == IntentReusable && intent.MaxRedemptions > 0 && intent.RedemptionCount >= intent.MaxRedemptions {
		intent.State = IntentRevoked
	}

	s.byID[intentID] = intent
	return nil
}

func (s *InMemoryIntentStore) DeleteExpired(ctx context.Context, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	at := now.UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, intent := range s.byID {
		if intent.ExpiresAt == nil {
			continue
		}
		if at.After(intent.ExpiresAt.UTC()) {
			delete(s.byID, id)
			delete(s.byCode, intentCodeKey(intent.Messenger, intent.Code))
		}
	}

	return nil
}

func intentCodeKey(messenger Messenger, code string) string {
	return NewMessenger(messenger.ID).ID + "|" + strings.TrimSpace(code)
}

// InMemoryLinkStore is a concurrency-safe identity link store.
type InMemoryLinkStore struct {
	mu    sync.RWMutex
	links map[string]AccountLink
}

func NewInMemoryLinkStore() *InMemoryLinkStore {
	return &InMemoryLinkStore{
		links: make(map[string]AccountLink),
	}
}

func (s *InMemoryLinkStore) FindByIdentity(ctx context.Context, identity Identity) (AccountLink, error) {
	if err := ctx.Err(); err != nil {
		return AccountLink{}, err
	}

	key, err := identityKey(identity)
	if err != nil {
		return AccountLink{}, err
	}

	s.mu.RLock()
	link, exists := s.links[key]
	s.mu.RUnlock()
	if !exists {
		return AccountLink{}, ErrIdentityLinkNotFound
	}
	return copyLink(link), nil
}

func (s *InMemoryLinkStore) Upsert(ctx context.Context, link AccountLink) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(link.AppUserID) == "" {
		return fmt.Errorf("%w: app user id is required", ErrInvalidInput)
	}
	key, err := identityKey(link.Identity)
	if err != nil {
		return err
	}
	if link.LinkedAt.IsZero() {
		link.LinkedAt = time.Now().UTC()
	}

	s.mu.Lock()
	s.links[key] = copyLink(link)
	s.mu.Unlock()
	return nil
}

func identityKey(identity Identity) (string, error) {
	messenger := NewMessenger(identity.Messenger.ID)
	if messenger.ID == "" {
		return "", fmt.Errorf("%w: identity messenger is required", ErrInvalidInput)
	}
	userID := strings.TrimSpace(identity.MessengerUserID)
	if userID == "" {
		return "", fmt.Errorf("%w: identity messenger user id is required", ErrInvalidInput)
	}
	return messenger.ID + "|" + userID, nil
}

func copyLink(in AccountLink) AccountLink {
	out := in
	out.Identity = Identity{
		Messenger:       in.Identity.Messenger,
		MessengerUserID: in.Identity.MessengerUserID,
		Username:        in.Identity.Username,
		Name:            in.Identity.Name,
		Surname:         in.Identity.Surname,
		BirthDate:       cloneutil.TimePtr(in.Identity.BirthDate),
		Attributes:      cloneutil.StringMap(in.Identity.Attributes),
	}
	return out
}

// InMemorySessionIssuer issues opaque sessions and validates them in-memory.
type InMemorySessionIssuer struct {
	mu       sync.RWMutex
	ttl      time.Duration
	clock    Clock
	tokenGen CodeGenerator
	idGen    IDGenerator
	byToken  map[string]WebSession
}

const maxSessionTokenGenerationAttempts = 5

type SessionIssuerOption func(*InMemorySessionIssuer) error

func WithSessionClock(clock Clock) SessionIssuerOption {
	return func(s *InMemorySessionIssuer) error {
		if clock == nil {
			return fmt.Errorf("%w: nil clock", ErrInvalidInput)
		}
		s.clock = clock
		return nil
	}
}

func WithSessionIDGenerator(gen IDGenerator) SessionIssuerOption {
	return func(s *InMemorySessionIssuer) error {
		if gen == nil {
			return fmt.Errorf("%w: nil id generator", ErrInvalidInput)
		}
		s.idGen = gen
		return nil
	}
}

func WithSessionTokenGenerator(gen CodeGenerator) SessionIssuerOption {
	return func(s *InMemorySessionIssuer) error {
		if gen == nil {
			return fmt.Errorf("%w: nil token generator", ErrInvalidInput)
		}
		s.tokenGen = gen
		return nil
	}
}

func NewInMemorySessionIssuer(ttl time.Duration, opts ...SessionIssuerOption) (*InMemorySessionIssuer, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("%w: session ttl must be > 0", ErrInvalidInput)
	}

	issuer := &InMemorySessionIssuer{
		ttl:      ttl,
		clock:    timeutil.SystemClock{},
		tokenGen: SecureCodeGenerator{NumBytes: 24},
		idGen:    UUIDGenerator{},
		byToken:  make(map[string]WebSession),
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(issuer); err != nil {
			return nil, err
		}
	}

	return issuer, nil
}

func (s *InMemorySessionIssuer) Issue(ctx context.Context, appUserID string) (WebSession, error) {
	if err := ctx.Err(); err != nil {
		return WebSession{}, err
	}
	subject := strings.TrimSpace(appUserID)
	if subject == "" {
		return WebSession{}, fmt.Errorf("%w: app user id is required", ErrInvalidInput)
	}

	sessionID := strings.TrimSpace(s.idGen.NewID())
	if sessionID == "" {
		return WebSession{}, ErrIDGenerationFailed
	}
	now := s.clock.Now().UTC()
	for i := 0; i < maxSessionTokenGenerationAttempts; i++ {
		token, err := s.tokenGen.NewCode()
		if err != nil {
			return WebSession{}, fmt.Errorf("%w: %v", ErrCodeGenerationFailed, err)
		}
		token = strings.TrimSpace(token)
		if token == "" {
			return WebSession{}, ErrCodeGenerationFailed
		}

		session := WebSession{
			SessionID: sessionID,
			SubjectID: subject,
			Token:     token,
			IssuedAt:  now,
			ExpiresAt: now.Add(s.ttl),
		}

		s.mu.Lock()
		if _, exists := s.byToken[token]; !exists {
			s.byToken[token] = session
			s.mu.Unlock()
			return session, nil
		}
		s.mu.Unlock()
	}

	return WebSession{}, fmt.Errorf("%w: unable to generate unique session token", ErrCodeGenerationFailed)
}

func (s *InMemorySessionIssuer) Validate(ctx context.Context, token string) (WebSession, error) {
	if err := ctx.Err(); err != nil {
		return WebSession{}, err
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return WebSession{}, fmt.Errorf("%w: token is required", ErrInvalidInput)
	}

	s.mu.RLock()
	session, exists := s.byToken[token]
	s.mu.RUnlock()
	if !exists {
		return WebSession{}, ErrSessionNotFound
	}

	now := s.clock.Now().UTC()
	if now.After(session.ExpiresAt) {
		s.mu.Lock()
		delete(s.byToken, token)
		s.mu.Unlock()
		return WebSession{}, ErrSessionExpired
	}

	return session, nil
}
