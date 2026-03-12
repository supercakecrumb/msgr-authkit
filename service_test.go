package authkit

import (
	"context"
	"errors"
	"fmt"
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
