package authkit

import (
	"context"
	"strings"
	"time"
)

// IntentState describes the lifecycle of a one-time auth intent.
type IntentState string

const (
	IntentActive  IntentState = "active"
	IntentExpired IntentState = "expired"
	IntentRevoked IntentState = "revoked"
)

// IntentRedemptionMode controls whether an intent is single-use or reusable.
type IntentRedemptionMode string

const (
	IntentOneTime  IntentRedemptionMode = "one_time"
	IntentReusable IntentRedemptionMode = "reusable"
)

// Messenger identifies any external messenger/channel type.
// Examples: "telegram", "discord", "whatsapp", "signal", "slack", "custom-x".
type Messenger struct {
	ID string
}

// NewMessenger creates a normalized messenger identifier.
func NewMessenger(id string) Messenger {
	return Messenger{ID: strings.TrimSpace(strings.ToLower(id))}
}

// Identity carries user details from an external channel.
// All fields are optional; callers may pass nil identity.
type Identity struct {
	Messenger       Messenger
	MessengerUserID string
	Username        string
	Name            string
	Surname         string
	BirthDate       *time.Time
	Attributes      map[string]string
}

// AccountLink maps external identity to an internal app user.
type AccountLink struct {
	AppUserID string
	Identity  Identity
	LinkedAt  time.Time
}

// AuthIntent is an auth challenge that can be one-time or reusable/static.
type AuthIntent struct {
	ID              string
	Code            string
	Messenger       Messenger
	Audience        string
	SubjectID       string
	State           IntentState
	Identity        *Identity
	Metadata        map[string]string
	RedemptionMode  IntentRedemptionMode
	MaxRedemptions  int
	RedemptionCount int
	ExpiresAt       *time.Time
	CreatedAt       time.Time
	ConsumedAt      *time.Time
}

// WebSession is the web auth artifact issued after successful intent redemption.
type WebSession struct {
	SessionID string
	SubjectID string
	Token     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type CreateIntentInput struct {
	Messenger      Messenger
	Audience       string
	SubjectID      string
	Metadata       map[string]string
	Identity       *Identity
	RedemptionMode IntentRedemptionMode
	MaxRedemptions int
	ExpiresAt      *time.Time
}

type RedeemIntentInput struct {
	Code      string
	Messenger Messenger
	Identity  *Identity
}

// IntentStore persists auth intents.
type IntentStore interface {
	Create(ctx context.Context, intent AuthIntent) error
	FindByCode(ctx context.Context, messenger Messenger, code string) (AuthIntent, error)
	RecordRedemption(ctx context.Context, intentID string, redeemedAt time.Time) error
	DeleteExpired(ctx context.Context, now time.Time) error
}

// LinkStore persists external identity <-> app user mappings.
type LinkStore interface {
	FindByIdentity(ctx context.Context, identity Identity) (AccountLink, error)
	Upsert(ctx context.Context, link AccountLink) error
}

// ChannelAdapter abstracts delivery/verification for any external channel.
type ChannelAdapter interface {
	DeliverIntent(ctx context.Context, identity Identity, intent AuthIntent) error
}

// SessionIssuer abstracts web-session format (JWT, opaque token, etc.).
type SessionIssuer interface {
	Issue(ctx context.Context, appUserID string) (WebSession, error)
	Validate(ctx context.Context, token string) (WebSession, error)
}

// Service is the high-level authkit contract used by applications.
type Service interface {
	CreateIntent(ctx context.Context, in CreateIntentInput) (AuthIntent, error)
	RedeemIntent(ctx context.Context, in RedeemIntentInput) (WebSession, error)
}
