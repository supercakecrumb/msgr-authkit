package authkit

import (
	"context"
	"errors"
	"testing"
	"time"
)

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
