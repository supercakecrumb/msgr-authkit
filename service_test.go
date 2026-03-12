package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"
)

type mutableClock struct {
	now time.Time
}

func (c *mutableClock) Now() time.Time { return c.now }

type staticIDGenerator struct {
	id string
}

func (g staticIDGenerator) NewID() string { return g.id }

type staticCodeGenerator struct {
	code string
	err  error
}

func (g staticCodeGenerator) NewCode() (string, error) {
	if g.err != nil {
		return "", g.err
	}
	return g.code, nil
}

type sequenceCodeGenerator struct {
	codes []string
	idx   int
}

func (g *sequenceCodeGenerator) NewCode() (string, error) {
	if len(g.codes) == 0 {
		return "", nil
	}
	if g.idx >= len(g.codes) {
		return g.codes[len(g.codes)-1], nil
	}
	code := g.codes[g.idx]
	g.idx++
	return code, nil
}

type fakeSessionIssuer struct {
	issueErr error
}

func (f *fakeSessionIssuer) Issue(ctx context.Context, appUserID string) (WebSession, error) {
	if f.issueErr != nil {
		return WebSession{}, f.issueErr
	}
	now := time.Now().UTC()
	return WebSession{
		SessionID: "session-" + appUserID,
		SubjectID: appUserID,
		Token:     "token-" + appUserID,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}, nil
}

func (f *fakeSessionIssuer) Validate(ctx context.Context, token string) (WebSession, error) {
	return WebSession{}, ErrSessionNotFound
}

type failingLinkStore struct {
	err error
}

func (f failingLinkStore) FindByIdentity(ctx context.Context, identity Identity) (AccountLink, error) {
	if err := ctx.Err(); err != nil {
		return AccountLink{}, err
	}
	return AccountLink{}, f.err
}

func (f failingLinkStore) Upsert(ctx context.Context, link AccountLink) error {
	return nil
}

type staticLinkProvisioner struct {
	link AccountLink
	err  error
}

func (p staticLinkProvisioner) ProvisionLink(ctx context.Context, identity Identity) (AccountLink, error) {
	if err := ctx.Err(); err != nil {
		return AccountLink{}, err
	}
	if p.err != nil {
		return AccountLink{}, p.err
	}
	return p.link, nil
}

func TestAuthService_CreateAndRedeem_OneTimeIntent(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}
	store := NewInMemoryIntentStore()
	issuer := &fakeSessionIssuer{}

	service, err := NewAuthService(
		store,
		nil,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-1"}),
		WithCodeGenerator(staticCodeGenerator{code: "code-1"}),
		WithConfig(Config{
			DefaultIntentTTL:      0,
			DefaultRedemptionMode: IntentOneTime,
		}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	intent, err := service.CreateIntent(context.Background(), CreateIntentInput{
		Messenger: NewMessenger(" TeLeGrAm "),
		SubjectID: "user-123",
		Audience:  "web",
	})
	if err != nil {
		t.Fatalf("CreateIntent() error = %v", err)
	}

	if intent.Messenger.ID != "telegram" {
		t.Fatalf("expected normalized messenger telegram, got %q", intent.Messenger.ID)
	}
	if intent.RedemptionMode != IntentOneTime {
		t.Fatalf("expected one-time intent, got %q", intent.RedemptionMode)
	}
	if intent.MaxRedemptions != 1 {
		t.Fatalf("expected max redemptions 1, got %d", intent.MaxRedemptions)
	}

	session, err := service.RedeemIntent(context.Background(), RedeemIntentInput{
		Code:      intent.Code,
		Messenger: intent.Messenger,
	})
	if err != nil {
		t.Fatalf("RedeemIntent() first call error = %v", err)
	}
	if session.SubjectID != "user-123" {
		t.Fatalf("expected subject user-123, got %q", session.SubjectID)
	}

	_, err = service.RedeemIntent(context.Background(), RedeemIntentInput{
		Code:      intent.Code,
		Messenger: intent.Messenger,
	})
	if !errors.Is(err, ErrIntentAlreadyRedeemed) {
		t.Fatalf("expected ErrIntentAlreadyRedeemed, got %v", err)
	}
}

func TestAuthService_Redeem_UsesLinkStoreWhenSubjectIsMissing(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}
	store := NewInMemoryIntentStore()
	linkStore := NewInMemoryLinkStore()
	issuer := &fakeSessionIssuer{}

	err := linkStore.Upsert(context.Background(), AccountLink{
		AppUserID: "app-user-42",
		Identity: Identity{
			Messenger:       NewMessenger("telegram"),
			MessengerUserID: "42",
			Username:        "john",
			Name:            "John",
			Surname:         "Doe",
		},
		LinkedAt: clock.now,
	})
	if err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}

	service, err := NewAuthService(
		store,
		linkStore,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-2"}),
		WithCodeGenerator(staticCodeGenerator{code: "code-2"}),
		WithConfig(Config{DefaultIntentTTL: 0}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	intent, err := service.CreateIntent(context.Background(), CreateIntentInput{
		Messenger: NewMessenger("telegram"),
		Audience:  "web",
	})
	if err != nil {
		t.Fatalf("CreateIntent() error = %v", err)
	}

	session, err := service.RedeemIntent(context.Background(), RedeemIntentInput{
		Code:      intent.Code,
		Messenger: NewMessenger("telegram"),
		Identity: &Identity{
			MessengerUserID: "42",
		},
	})
	if err != nil {
		t.Fatalf("RedeemIntent() error = %v", err)
	}
	if session.SubjectID != "app-user-42" {
		t.Fatalf("expected app-user-42 subject, got %q", session.SubjectID)
	}
}

func TestAuthService_Redeem_MergesSecondaryAttributesWithoutPanic(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}
	store := NewInMemoryIntentStore()
	linkStore := NewInMemoryLinkStore()
	issuer := &fakeSessionIssuer{}

	err := linkStore.Upsert(context.Background(), AccountLink{
		AppUserID: "app-user-merged",
		Identity: Identity{
			Messenger:       NewMessenger("telegram"),
			MessengerUserID: "42",
		},
		LinkedAt: clock.now,
	})
	if err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}

	service, err := NewAuthService(
		store,
		linkStore,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-merge-1"}),
		WithCodeGenerator(staticCodeGenerator{code: "code-merge-1"}),
		WithConfig(Config{DefaultIntentTTL: 0}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	intent, err := service.CreateIntent(context.Background(), CreateIntentInput{
		Messenger: NewMessenger("telegram"),
		Identity: &Identity{
			MessengerUserID: "42",
		},
	})
	if err != nil {
		t.Fatalf("CreateIntent() error = %v", err)
	}

	session, err := service.RedeemIntent(context.Background(), RedeemIntentInput{
		Code:      intent.Code,
		Messenger: NewMessenger("telegram"),
		Identity: &Identity{
			Attributes: map[string]string{
				"locale": "en-US",
			},
		},
	})
	if err != nil {
		t.Fatalf("RedeemIntent() error = %v", err)
	}
	if session.SubjectID != "app-user-merged" {
		t.Fatalf("expected app-user-merged subject, got %q", session.SubjectID)
	}
}

func TestAuthService_Redeem_DoesNotMaskUnexpectedLinkStoreErrors(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}
	store := NewInMemoryIntentStore()
	issuer := &fakeSessionIssuer{}
	linkErr := fmt.Errorf("db unavailable")

	service, err := NewAuthService(
		store,
		failingLinkStore{err: linkErr},
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-link-err-1"}),
		WithCodeGenerator(staticCodeGenerator{code: "code-link-err-1"}),
		WithConfig(Config{DefaultIntentTTL: 0}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	intent, err := service.CreateIntent(context.Background(), CreateIntentInput{
		Messenger: NewMessenger("telegram"),
	})
	if err != nil {
		t.Fatalf("CreateIntent() error = %v", err)
	}

	_, err = service.RedeemIntent(context.Background(), RedeemIntentInput{
		Code:      intent.Code,
		Messenger: NewMessenger("telegram"),
		Identity: &Identity{
			MessengerUserID: "42",
		},
	})
	if !errors.Is(err, linkErr) {
		t.Fatalf("expected wrapped link store error, got %v", err)
	}
	if errors.Is(err, ErrIdentityLinkNotFound) {
		t.Fatalf("expected non-not-found error classification, got %v", err)
	}
}

func TestAuthService_Redeem_ReusableIntentWithLimit(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}
	store := NewInMemoryIntentStore()
	issuer := &fakeSessionIssuer{}

	service, err := NewAuthService(
		store,
		nil,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-3"}),
		WithCodeGenerator(staticCodeGenerator{code: "code-3"}),
		WithConfig(Config{DefaultIntentTTL: 0}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	intent, err := service.CreateIntent(context.Background(), CreateIntentInput{
		Messenger:      NewMessenger("discord"),
		SubjectID:      "user-xyz",
		RedemptionMode: IntentReusable,
		MaxRedemptions: 2,
	})
	if err != nil {
		t.Fatalf("CreateIntent() error = %v", err)
	}

	for i := 0; i < 2; i++ {
		if _, err := service.RedeemIntent(context.Background(), RedeemIntentInput{
			Code:      intent.Code,
			Messenger: intent.Messenger,
		}); err != nil {
			t.Fatalf("RedeemIntent() call %d error = %v", i+1, err)
		}
	}

	_, err = service.RedeemIntent(context.Background(), RedeemIntentInput{
		Code:      intent.Code,
		Messenger: intent.Messenger,
	})
	if !errors.Is(err, ErrIntentRedemptionLimitReached) {
		t.Fatalf("expected ErrIntentRedemptionLimitReached, got %v", err)
	}
}

func TestAuthService_Redeem_ExpiredIntent(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}
	store := NewInMemoryIntentStore()
	issuer := &fakeSessionIssuer{}

	service, err := NewAuthService(
		store,
		nil,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-4"}),
		WithCodeGenerator(staticCodeGenerator{code: "code-4"}),
		WithConfig(Config{DefaultIntentTTL: 0}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	expires := clock.now.Add(30 * time.Second)
	intent, err := service.CreateIntent(context.Background(), CreateIntentInput{
		Messenger: NewMessenger("signal"),
		SubjectID: "subject",
		ExpiresAt: &expires,
	})
	if err != nil {
		t.Fatalf("CreateIntent() error = %v", err)
	}

	clock.now = clock.now.Add(31 * time.Second)
	_, err = service.RedeemIntent(context.Background(), RedeemIntentInput{
		Code:      intent.Code,
		Messenger: intent.Messenger,
	})
	if !errors.Is(err, ErrIntentExpired) {
		t.Fatalf("expected ErrIntentExpired, got %v", err)
	}
}

func TestAuthService_Redeem_MissingSubjectAndIdentity(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}
	store := NewInMemoryIntentStore()
	issuer := &fakeSessionIssuer{}

	service, err := NewAuthService(
		store,
		nil,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-5"}),
		WithCodeGenerator(staticCodeGenerator{code: "code-5"}),
		WithConfig(Config{DefaultIntentTTL: 0}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	intent, err := service.CreateIntent(context.Background(), CreateIntentInput{
		Messenger: NewMessenger("slack"),
	})
	if err != nil {
		t.Fatalf("CreateIntent() error = %v", err)
	}

	_, err = service.RedeemIntent(context.Background(), RedeemIntentInput{
		Code:      intent.Code,
		Messenger: intent.Messenger,
	})
	if !errors.Is(err, ErrSubjectUnresolved) {
		t.Fatalf("expected ErrSubjectUnresolved, got %v", err)
	}
}

func TestAuthService_CreateIntent_IdentityFieldsAreOptionalAndCarried(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}
	store := NewInMemoryIntentStore()
	issuer := &fakeSessionIssuer{}

	service, err := NewAuthService(
		store,
		nil,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-6"}),
		WithCodeGenerator(staticCodeGenerator{code: "code-6"}),
		WithConfig(Config{DefaultIntentTTL: 0}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	birthDate := time.Date(1991, 7, 23, 0, 0, 0, 0, time.UTC)
	intent, err := service.CreateIntent(context.Background(), CreateIntentInput{
		Messenger: NewMessenger("custom-chat"),
		Identity: &Identity{
			MessengerUserID: "u-1",
			Username:        "neo",
			Name:            "Thomas",
			Surname:         "Anderson",
			BirthDate:       &birthDate,
			Attributes: map[string]string{
				"locale": "en-US",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateIntent() error = %v", err)
	}
	if intent.Identity == nil {
		t.Fatal("expected identity to be present")
	}
	if intent.Identity.Name != "Thomas" || intent.Identity.Surname != "Anderson" {
		t.Fatalf("unexpected identity name data: %+v", intent.Identity)
	}
	if intent.Identity.BirthDate == nil || !intent.Identity.BirthDate.Equal(birthDate) {
		t.Fatalf("unexpected birth date: %+v", intent.Identity.BirthDate)
	}
}

func TestAuthService_CreateIntent_CodeGeneratorFailure(t *testing.T) {
	t.Parallel()

	store := NewInMemoryIntentStore()
	issuer := &fakeSessionIssuer{}
	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}

	service, err := NewAuthService(
		store,
		nil,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-7"}),
		WithCodeGenerator(staticCodeGenerator{err: fmt.Errorf("boom")}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	_, err = service.CreateIntent(context.Background(), CreateIntentInput{
		Messenger: NewMessenger("telegram"),
		SubjectID: "subject",
	})
	if !errors.Is(err, ErrCodeGenerationFailed) {
		t.Fatalf("expected ErrCodeGenerationFailed, got %v", err)
	}
}

func TestAuthService_CreateAndRedeemLoginLink_BotFirst(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 13, 0, 0, 0, time.UTC)}
	intentStore := NewInMemoryIntentStore()
	linkStore := NewInMemoryLinkStore()
	issuer := &fakeSessionIssuer{}

	err := linkStore.Upsert(context.Background(), AccountLink{
		AppUserID: "app-user-42",
		Identity: Identity{
			Messenger:       NewMessenger("telegram"),
			MessengerUserID: "42",
			Username:        "neo",
			Name:            "Thomas",
			Surname:         "Anderson",
		},
		LinkedAt: clock.now,
	})
	if err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}

	service, err := NewAuthService(
		intentStore,
		linkStore,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-link-1"}),
		WithCodeGenerator(staticCodeGenerator{code: "intent-code-1"}),
		WithConfig(Config{DefaultIntentTTL: 0, DefaultLoginLinkTTL: 10 * time.Minute}),
		WithLoginTokenCodec(HMACLoginTokenCodec{SigningKey: []byte("dev-signing-key")}),
		WithLoginLinkBuilder(QueryLoginLinkBuilder{
			BaseURL:         "https://app.example/auth/complete",
			TokenQueryParam: "login_token",
		}),
		WithMissingIdentityLinkMode(MissingIdentityLinkStrict),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	out, err := service.CreateLoginLink(context.Background(), CreateLoginLinkInput{
		Messenger: NewMessenger("telegram"),
		Identity: &Identity{
			MessengerUserID: "42",
		},
	})
	if err != nil {
		t.Fatalf("CreateLoginLink() error = %v", err)
	}
	if out.Intent.SubjectID != "app-user-42" {
		t.Fatalf("expected resolved subject app-user-42, got %q", out.Intent.SubjectID)
	}
	if out.LinkToken == "" {
		t.Fatal("expected non-empty link token")
	}
	parsed, err := url.Parse(out.LoginURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	if got := parsed.Query().Get("login_token"); got != out.LinkToken {
		t.Fatalf("expected login_token query param to equal output token, got %q", got)
	}

	session, err := service.RedeemLoginLink(context.Background(), RedeemLoginLinkInput{
		LinkToken: out.LinkToken,
	})
	if err != nil {
		t.Fatalf("RedeemLoginLink() error = %v", err)
	}
	if session.SubjectID != "app-user-42" {
		t.Fatalf("expected subject app-user-42, got %q", session.SubjectID)
	}
}

func TestAuthService_CreateLoginLink_UsesAudienceResolver(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 13, 30, 0, 0, time.UTC)}
	intentStore := NewInMemoryIntentStore()
	issuer := &fakeSessionIssuer{}

	service, err := NewAuthService(
		intentStore,
		nil,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-link-2"}),
		WithCodeGenerator(staticCodeGenerator{code: "intent-code-2"}),
		WithConfig(Config{DefaultIntentTTL: 0, DefaultLoginLinkTTL: 5 * time.Minute}),
		WithLoginTokenCodec(HMACLoginTokenCodec{SigningKey: []byte("dev-signing-key")}),
		WithLoginLinkBuilder(QueryLoginLinkBuilder{BaseURL: "https://app.example/auth/complete"}),
		WithAudienceResolver(AudienceResolverFunc(func(ctx context.Context, messenger Messenger, identity *Identity) (string, error) {
			return "bot-start", nil
		})),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	out, err := service.CreateLoginLink(context.Background(), CreateLoginLinkInput{
		Messenger: NewMessenger("telegram"),
		SubjectID: "user-1",
	})
	if err != nil {
		t.Fatalf("CreateLoginLink() error = %v", err)
	}
	if out.Intent.Audience != "bot-start" {
		t.Fatalf("expected audience bot-start, got %q", out.Intent.Audience)
	}
}

func TestAuthService_CreateLoginLink_StrictMissingLinkFails(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 14, 0, 0, 0, time.UTC)}
	intentStore := NewInMemoryIntentStore()
	linkStore := NewInMemoryLinkStore()
	issuer := &fakeSessionIssuer{}

	service, err := NewAuthService(
		intentStore,
		linkStore,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-link-3"}),
		WithCodeGenerator(staticCodeGenerator{code: "intent-code-3"}),
		WithConfig(Config{DefaultIntentTTL: 0, DefaultLoginLinkTTL: 5 * time.Minute}),
		WithLoginTokenCodec(HMACLoginTokenCodec{SigningKey: []byte("dev-signing-key")}),
		WithLoginLinkBuilder(QueryLoginLinkBuilder{BaseURL: "https://app.example/auth/complete"}),
		WithMissingIdentityLinkMode(MissingIdentityLinkStrict),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	_, err = service.CreateLoginLink(context.Background(), CreateLoginLinkInput{
		Messenger: NewMessenger("telegram"),
		Identity: &Identity{
			MessengerUserID: "missing",
		},
	})
	if !errors.Is(err, ErrIdentityLinkNotFound) {
		t.Fatalf("expected ErrIdentityLinkNotFound, got %v", err)
	}
}

func TestAuthService_CreateLoginLink_AutoProvisionMissingLink(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 14, 30, 0, 0, time.UTC)}
	intentStore := NewInMemoryIntentStore()
	linkStore := NewInMemoryLinkStore()
	issuer := &fakeSessionIssuer{}

	provisioned := AccountLink{
		AppUserID: "auto-user-99",
		Identity: Identity{
			Messenger:       NewMessenger("telegram"),
			MessengerUserID: "99",
		},
		LinkedAt: clock.now,
	}

	service, err := NewAuthService(
		intentStore,
		linkStore,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-link-4"}),
		WithCodeGenerator(staticCodeGenerator{code: "intent-code-4"}),
		WithConfig(Config{DefaultIntentTTL: 0, DefaultLoginLinkTTL: 5 * time.Minute}),
		WithLoginTokenCodec(HMACLoginTokenCodec{SigningKey: []byte("dev-signing-key")}),
		WithLoginLinkBuilder(QueryLoginLinkBuilder{BaseURL: "https://app.example/auth/complete"}),
		WithMissingIdentityLinkMode(MissingIdentityLinkAutoProvision),
		WithLinkProvisioner(staticLinkProvisioner{link: provisioned}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	out, err := service.CreateLoginLink(context.Background(), CreateLoginLinkInput{
		Messenger: NewMessenger("telegram"),
		Identity: &Identity{
			MessengerUserID: "99",
		},
	})
	if err != nil {
		t.Fatalf("CreateLoginLink() error = %v", err)
	}
	if out.Intent.SubjectID != "auto-user-99" {
		t.Fatalf("expected resolved subject auto-user-99, got %q", out.Intent.SubjectID)
	}

	persisted, err := linkStore.FindByIdentity(context.Background(), Identity{
		Messenger:       NewMessenger("telegram"),
		MessengerUserID: "99",
	})
	if err != nil {
		t.Fatalf("FindByIdentity() error = %v", err)
	}
	if persisted.AppUserID != "auto-user-99" {
		t.Fatalf("expected persisted app user id auto-user-99, got %q", persisted.AppUserID)
	}
}

func TestAuthService_CreateLoginLink_NotConfigured(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 15, 0, 0, 0, time.UTC)}
	intentStore := NewInMemoryIntentStore()
	issuer := &fakeSessionIssuer{}

	service, err := NewAuthService(
		intentStore,
		nil,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-link-5"}),
		WithCodeGenerator(staticCodeGenerator{code: "intent-code-5"}),
		WithConfig(Config{DefaultIntentTTL: 0}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	_, err = service.CreateLoginLink(context.Background(), CreateLoginLinkInput{
		Messenger: NewMessenger("telegram"),
		SubjectID: "user-1",
	})
	if !errors.Is(err, ErrLoginLinkNotConfigured) {
		t.Fatalf("expected ErrLoginLinkNotConfigured, got %v", err)
	}
}

func TestAuthService_RedeemLoginLink_InvalidToken(t *testing.T) {
	t.Parallel()

	store := NewInMemoryIntentStore()
	issuer := &fakeSessionIssuer{}
	clock := &mutableClock{now: time.Date(2026, 3, 12, 15, 10, 0, 0, time.UTC)}

	service, err := NewAuthService(
		store,
		nil,
		issuer,
		WithClock(clock),
		WithLoginTokenCodec(HMACLoginTokenCodec{SigningKey: []byte("dev-signing-key")}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	_, err = service.RedeemLoginLink(context.Background(), RedeemLoginLinkInput{
		LinkToken: "broken.token.parts",
	})
	if !errors.Is(err, ErrLoginLinkInvalid) {
		t.Fatalf("expected ErrLoginLinkInvalid, got %v", err)
	}
}

func TestAuthService_RedeemLoginLink_ExpiredToken(t *testing.T) {
	t.Parallel()

	store := NewInMemoryIntentStore()
	issuer := &fakeSessionIssuer{}
	clock := &mutableClock{now: time.Date(2026, 3, 12, 15, 20, 0, 0, time.UTC)}

	service, err := NewAuthService(
		store,
		nil,
		issuer,
		WithClock(clock),
		WithIDGenerator(staticIDGenerator{id: "intent-link-6"}),
		WithCodeGenerator(staticCodeGenerator{code: "intent-code-6"}),
		WithLoginTokenCodec(HMACLoginTokenCodec{SigningKey: []byte("dev-signing-key")}),
	)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}

	_, err = service.CreateIntent(context.Background(), CreateIntentInput{
		Messenger: NewMessenger("telegram"),
		SubjectID: "subject-6",
	})
	if err != nil {
		t.Fatalf("CreateIntent() error = %v", err)
	}

	expiredToken, err := (HMACLoginTokenCodec{SigningKey: []byte("dev-signing-key")}).Encode(context.Background(), LoginTokenClaims{
		IntentCode: "intent-code-6",
		Messenger:  NewMessenger("telegram"),
		ExpiresAt:  clock.now.Add(-1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	_, err = service.RedeemLoginLink(context.Background(), RedeemLoginLinkInput{
		LinkToken: expiredToken,
	})
	if !errors.Is(err, ErrLoginLinkExpired) {
		t.Fatalf("expected ErrLoginLinkExpired, got %v", err)
	}
}

func TestInMemorySessionIssuer_IssueAndValidate(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}
	issuer, err := NewInMemorySessionIssuer(
		5*time.Minute,
		WithSessionClock(clock),
		WithSessionIDGenerator(staticIDGenerator{id: "sid-1"}),
		WithSessionTokenGenerator(staticCodeGenerator{code: "tok-1"}),
	)
	if err != nil {
		t.Fatalf("NewInMemorySessionIssuer() error = %v", err)
	}

	session, err := issuer.Issue(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if session.SessionID != "sid-1" {
		t.Fatalf("expected sid-1 session id, got %q", session.SessionID)
	}
	if session.Token != "tok-1" {
		t.Fatalf("expected tok-1 token, got %q", session.Token)
	}

	validated, err := issuer.Validate(context.Background(), session.Token)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if validated.SubjectID != "user-1" {
		t.Fatalf("expected subject user-1, got %q", validated.SubjectID)
	}
}

func TestInMemorySessionIssuer_ValidateExpired(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}
	issuer, err := NewInMemorySessionIssuer(
		1*time.Minute,
		WithSessionClock(clock),
		WithSessionIDGenerator(staticIDGenerator{id: "sid-2"}),
		WithSessionTokenGenerator(staticCodeGenerator{code: "tok-2"}),
	)
	if err != nil {
		t.Fatalf("NewInMemorySessionIssuer() error = %v", err)
	}

	session, err := issuer.Issue(context.Background(), "user-2")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	clock.now = clock.now.Add(2 * time.Minute)
	_, err = issuer.Validate(context.Background(), session.Token)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestInMemorySessionIssuer_IssueFailsWhenTokenCollidesRepeatedly(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}
	issuer, err := NewInMemorySessionIssuer(
		5*time.Minute,
		WithSessionClock(clock),
		WithSessionIDGenerator(staticIDGenerator{id: "sid-collision"}),
		WithSessionTokenGenerator(staticCodeGenerator{code: "tok-collision"}),
	)
	if err != nil {
		t.Fatalf("NewInMemorySessionIssuer() error = %v", err)
	}

	_, err = issuer.Issue(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("Issue() first call error = %v", err)
	}

	_, err = issuer.Issue(context.Background(), "user-2")
	if !errors.Is(err, ErrCodeGenerationFailed) {
		t.Fatalf("expected ErrCodeGenerationFailed, got %v", err)
	}
}

func TestInMemorySessionIssuer_IssueRetriesOnTokenCollision(t *testing.T) {
	t.Parallel()

	clock := &mutableClock{now: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)}
	tokenGen := &sequenceCodeGenerator{codes: []string{"tok-dup", "tok-dup", "tok-new"}}
	issuer, err := NewInMemorySessionIssuer(
		5*time.Minute,
		WithSessionClock(clock),
		WithSessionIDGenerator(staticIDGenerator{id: "sid-retry"}),
		WithSessionTokenGenerator(tokenGen),
	)
	if err != nil {
		t.Fatalf("NewInMemorySessionIssuer() error = %v", err)
	}

	first, err := issuer.Issue(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("Issue() first call error = %v", err)
	}
	if first.Token != "tok-dup" {
		t.Fatalf("expected tok-dup for first session, got %q", first.Token)
	}

	second, err := issuer.Issue(context.Background(), "user-2")
	if err != nil {
		t.Fatalf("Issue() second call error = %v", err)
	}
	if second.Token != "tok-new" {
		t.Fatalf("expected tok-new after retry, got %q", second.Token)
	}
}

func TestInMemoryLinkStore_FindByIdentity_NotFound(t *testing.T) {
	t.Parallel()

	store := NewInMemoryLinkStore()
	_, err := store.FindByIdentity(context.Background(), Identity{
		Messenger:       NewMessenger("telegram"),
		MessengerUserID: "missing",
	})
	if !errors.Is(err, ErrIdentityLinkNotFound) {
		t.Fatalf("expected ErrIdentityLinkNotFound, got %v", err)
	}
}
