package authkit

import (
	"context"
	"strings"
	"time"
)

// IntentState describes the lifecycle of an auth intent.
type IntentState string

const (
	// IntentActive means the intent can still be redeemed.
	IntentActive IntentState = "active"
	// IntentExpired means the intent passed its expiration time and can no
	// longer be redeemed.
	IntentExpired IntentState = "expired"
	// IntentRevoked means the intent was explicitly consumed/closed before
	// natural expiration (for example after one-time redemption).
	IntentRevoked IntentState = "revoked"
)

// IntentRedemptionMode controls whether an intent is single-use or reusable.
type IntentRedemptionMode string

const (
	// IntentOneTime allows exactly one successful redemption.
	IntentOneTime IntentRedemptionMode = "one_time"
	// IntentReusable allows multiple redemptions until MaxRedemptions is hit.
	// When MaxRedemptions is zero, redemptions are unlimited.
	IntentReusable IntentRedemptionMode = "reusable"
)

// Messenger identifies any external messenger/channel type.
// Examples: "telegram", "discord", "whatsapp", "signal", "slack", "custom-x".
type Messenger struct {
	// ID is a normalized messenger identifier such as "telegram" or "discord".
	// Use NewMessenger to normalize user-provided values.
	ID string
}

// NewMessenger creates a normalized messenger identifier.
func NewMessenger(id string) Messenger {
	return Messenger{ID: strings.TrimSpace(strings.ToLower(id))}
}

// Identity carries user details from an external channel.
// All fields are optional; callers may pass nil identity.
type Identity struct {
	// Messenger identifies where this identity came from.
	Messenger Messenger
	// MessengerUserID is a stable external user identifier in the messenger.
	// Example: Telegram numeric user id.
	MessengerUserID string
	// Username is the messenger handle when available.
	Username string
	// Name is given/first name.
	Name string
	// Surname is family/last name.
	Surname string
	// BirthDate is optional and messenger-dependent.
	BirthDate *time.Time
	// Attributes stores additional messenger-specific key-value data.
	// Callers should keep keys stable for easier downstream processing.
	Attributes map[string]string
}

// AccountLink maps external identity to an internal app user.
type AccountLink struct {
	// AppUserID is the internal application user id.
	AppUserID string
	// Identity is the linked external messenger identity.
	Identity Identity
	// LinkedAt records when the mapping was created or last refreshed.
	LinkedAt time.Time
}

// AuthIntent is an auth challenge that can be one-time or reusable/static.
type AuthIntent struct {
	// ID is an internal unique identifier for persistence.
	ID string
	// Code is the user-facing (or transport-facing) redemption code.
	Code string
	// Messenger scopes the code to a specific external channel.
	Messenger Messenger
	// Audience is optional context such as "web", "mobile", or "admin".
	// Applications may use it to route auth completion behavior.
	Audience string
	// SubjectID is the internal user id if already known at create time.
	// When empty, subject can be resolved from LinkStore during redemption.
	SubjectID string
	// State tracks whether the intent can still be redeemed.
	State IntentState
	// Identity is optional profile data captured at intent creation.
	// It can help resolve SubjectID later.
	Identity *Identity
	// Metadata stores application-defined key-value context.
	// Authkit stores and returns it but does not interpret values.
	Metadata map[string]string
	// RedemptionMode controls one-time vs reusable redemption behavior.
	RedemptionMode IntentRedemptionMode
	// MaxRedemptions is used for reusable intents.
	// Zero means unlimited redemptions.
	MaxRedemptions int
	// RedemptionCount is incremented after each successful redemption.
	RedemptionCount int
	// ExpiresAt is optional absolute expiration time (UTC).
	// Nil means no expiration.
	ExpiresAt *time.Time
	// CreatedAt is intent creation timestamp (UTC).
	CreatedAt time.Time
	// ConsumedAt is timestamp of the latest successful redemption.
	// For one-time intents this is the single redemption timestamp.
	ConsumedAt *time.Time
}

// WebSession is the web auth artifact issued after successful intent redemption.
type WebSession struct {
	// SessionID is an internal session identifier.
	SessionID string
	// SubjectID is the internal authenticated user id.
	SubjectID string
	// Token is the bearer credential returned to clients.
	Token string
	// IssuedAt is session creation time (UTC).
	IssuedAt time.Time
	// ExpiresAt is session expiration time (UTC).
	ExpiresAt time.Time
}

// CreateIntentInput configures creation of an auth intent.
//
// This is the baseline (non bot-first) entrypoint used by Service.CreateIntent.
type CreateIntentInput struct {
	// Messenger identifies the external channel.
	// Required, unless Identity.Messenger is provided.
	Messenger Messenger
	// Audience optionally labels intended consumer/context for this intent.
	Audience string
	// SubjectID optionally prebinds the intent to a known internal user id.
	SubjectID string
	// Metadata stores application-defined key-value context.
	Metadata map[string]string
	// Identity is optional external profile data captured at creation time.
	Identity *Identity
	// RedemptionMode chooses one-time vs reusable behavior.
	// Empty value uses Config.DefaultRedemptionMode.
	RedemptionMode IntentRedemptionMode
	// MaxRedemptions applies only to IntentReusable.
	// Zero uses Config.DefaultReusableMaxRedemptions.
	MaxRedemptions int
	// ExpiresAt overrides expiration for this intent.
	// Nil uses Config.DefaultIntentTTL (or no expiration when default TTL is 0).
	ExpiresAt *time.Time
}

// RedeemIntentInput contains data required to redeem an existing intent.
type RedeemIntentInput struct {
	// Code is the intent redemption code.
	Code string
	// Messenger scopes code lookup to a specific channel.
	// Required, unless Identity.Messenger is provided.
	Messenger Messenger
	// Identity optionally provides fresh profile data at redemption time.
	// It is merged with stored intent identity for subject resolution.
	Identity *Identity
}

// CreateLoginLinkInput controls bot-first login-link creation.
//
// The typical flow is:
//  1. user starts auth in messenger (for example /start in Telegram),
//  2. application calls CreateLoginLink,
//  3. application sends returned LoginURL back to messenger,
//  4. user opens link in browser and backend calls RedeemLoginLink.
//
// CreateLoginLinkInput mirrors CreateIntentInput, but also allows configuring
// login-link token expiration independently from intent expiration.
type CreateLoginLinkInput struct {
	// Messenger identifies the external channel for the created intent.
	// Required, unless Identity.Messenger is provided.
	Messenger Messenger
	// Audience optionally tags the created intent with app-specific context
	// (for example "web", "mobile", "admin"). If empty and AudienceResolver
	// is configured, resolver output is used.
	Audience string
	// SubjectID is the known internal app user id. When empty, authkit can
	// resolve it from LinkStore depending on MissingIdentityLinkMode.
	SubjectID string
	// Metadata stores optional caller-defined key-value context on the intent.
	Metadata map[string]string
	// Identity is optional user profile from messenger. When SubjectID is empty,
	// identity can be used to resolve or provision an account link.
	Identity *Identity
	// RedemptionMode controls one-time vs reusable behavior of the underlying
	// intent. Empty means Config.DefaultRedemptionMode.
	RedemptionMode IntentRedemptionMode
	// MaxRedemptions applies only to reusable intents. Zero means
	// Config.DefaultReusableMaxRedemptions.
	MaxRedemptions int
	// IntentExpiresAt overrides the intent expiration timestamp.
	// If nil, intent expiration is derived from Config.DefaultIntentTTL.
	IntentExpiresAt *time.Time
	// LinkExpiresAt overrides login-link token expiration timestamp.
	// If nil, token expiration is derived from Config.DefaultLoginLinkTTL and
	// clamped to IntentExpiresAt when needed.
	LinkExpiresAt *time.Time
}

// CreateLoginLinkOutput contains the created intent and login-link artifacts.
type CreateLoginLinkOutput struct {
	// Intent is the persisted auth intent used during final redemption.
	Intent AuthIntent
	// LoginURL is the final user-facing URL built by LoginLinkBuilder.
	LoginURL string
	// LinkToken is the signed token built by LoginTokenCodec.
	// Applications may store/log this carefully as a short-lived secret.
	LinkToken string
	// ExpiresAt is the token expiration instant (UTC).
	ExpiresAt time.Time
}

// RedeemLoginLinkInput is used to redeem a signed login-link token.
type RedeemLoginLinkInput struct {
	// LinkToken is the signed token previously returned from CreateLoginLink.
	LinkToken string
	// Identity optionally provides fresh messenger profile data during redeem.
	// It is merged with intent identity when subject resolution needs LinkStore.
	Identity *Identity
}

// LoginTokenClaims are serialized and signed by LoginTokenCodec.
type LoginTokenClaims struct {
	// IntentCode points to the underlying auth intent.
	IntentCode string
	// Messenger scopes redemption to a specific messenger id.
	Messenger Messenger
	// ExpiresAt is absolute token expiration (UTC).
	ExpiresAt time.Time
}

// LoginTokenCodec signs and verifies login-link tokens.
//
// Implementations should treat tokens as short-lived bearer credentials.
// Decode must reject malformed/forged tokens.
type LoginTokenCodec interface {
	// Encode produces a signed/encoded token from claims.
	Encode(ctx context.Context, claims LoginTokenClaims) (string, error)
	// Decode verifies and parses token claims.
	// Implementations should return ErrLoginLinkInvalid for malformed/forged
	// tokens when possible.
	Decode(ctx context.Context, token string) (LoginTokenClaims, error)
}

// LoginLinkBuilder builds a final user-facing URL from a signed token.
// Implementations can use query parameters, path segments, or custom transports.
type LoginLinkBuilder interface {
	// BuildURL returns the final user-facing login URL for a signed token.
	BuildURL(ctx context.Context, token string) (string, error)
}

// AudienceResolver derives audience/context when caller omitted it in
// CreateLoginLinkInput.
type AudienceResolver interface {
	// ResolveAudience derives audience when CreateLoginLinkInput.Audience is
	// empty. Empty resolver output is allowed.
	ResolveAudience(ctx context.Context, messenger Messenger, identity *Identity) (string, error)
}

// AudienceResolverFunc adapts a function to AudienceResolver.
type AudienceResolverFunc func(ctx context.Context, messenger Messenger, identity *Identity) (string, error)

// ResolveAudience calls f(ctx, messenger, identity).
func (f AudienceResolverFunc) ResolveAudience(ctx context.Context, messenger Messenger, identity *Identity) (string, error) {
	return f(ctx, messenger, identity)
}

// MissingIdentityLinkMode controls how CreateLoginLink behaves when identity is
// present but LinkStore has no account mapping for it.
type MissingIdentityLinkMode string

const (
	// MissingIdentityLinkDeferred keeps subject unresolved during create and
	// allows LinkStore resolution later at redeem time.
	MissingIdentityLinkDeferred MissingIdentityLinkMode = "deferred"
	// MissingIdentityLinkStrict fails CreateLoginLink immediately with
	// ErrIdentityLinkNotFound.
	MissingIdentityLinkStrict MissingIdentityLinkMode = "strict"
	// MissingIdentityLinkAutoProvision asks LinkProvisioner to create/fetch the
	// link and optionally persists it via LinkStore.Upsert.
	MissingIdentityLinkAutoProvision MissingIdentityLinkMode = "auto_provision"
)

// LinkProvisioner creates or fetches an account link when LinkStore lookup
// misses and mode is MissingIdentityLinkAutoProvision.
type LinkProvisioner interface {
	// ProvisionLink creates or fetches an account link for the given identity.
	// The returned AccountLink.AppUserID must be non-empty.
	ProvisionLink(ctx context.Context, identity Identity) (AccountLink, error)
}

// LinkProvisionerFunc adapts a function to LinkProvisioner.
type LinkProvisionerFunc func(ctx context.Context, identity Identity) (AccountLink, error)

// ProvisionLink calls f(ctx, identity).
func (f LinkProvisionerFunc) ProvisionLink(ctx context.Context, identity Identity) (AccountLink, error) {
	return f(ctx, identity)
}

// IntentStore persists auth intents.
type IntentStore interface {
	// Create inserts a new intent.
	Create(ctx context.Context, intent AuthIntent) error
	// FindByCode returns intent by messenger+code pair.
	FindByCode(ctx context.Context, messenger Messenger, code string) (AuthIntent, error)
	// RecordRedemption applies redemption state transition atomically.
	// Implementations should enforce mode limits and return ErrIntent* values.
	RecordRedemption(ctx context.Context, intentID string, redeemedAt time.Time) error
	// DeleteExpired removes intents expired before the provided time.
	DeleteExpired(ctx context.Context, now time.Time) error
}

// LinkStore persists external identity <-> app user mappings.
type LinkStore interface {
	// FindByIdentity resolves internal user mapping for external identity.
	FindByIdentity(ctx context.Context, identity Identity) (AccountLink, error)
	// Upsert creates or updates identity mapping.
	Upsert(ctx context.Context, link AccountLink) error
}

// ChannelAdapter abstracts delivery/verification for any external channel.
type ChannelAdapter interface {
	// DeliverIntent sends intent details to an external channel/user.
	// This abstraction is optional and app-specific.
	DeliverIntent(ctx context.Context, identity Identity, intent AuthIntent) error
}

// SessionIssuer abstracts web-session format (JWT, opaque token, etc.).
type SessionIssuer interface {
	// Issue creates a new web session for internal user id.
	Issue(ctx context.Context, appUserID string) (WebSession, error)
	// Validate parses and verifies a previously issued session token.
	Validate(ctx context.Context, token string) (WebSession, error)
}

// Service is the high-level authkit contract used by applications.
type Service interface {
	// CreateIntent creates and persists a new auth intent.
	CreateIntent(ctx context.Context, in CreateIntentInput) (AuthIntent, error)
	// RedeemIntent validates intent state and returns issued web session.
	RedeemIntent(ctx context.Context, in RedeemIntentInput) (WebSession, error)
}

// BotFirstService extends Service with bot-first login-link methods.
//
// AuthService implements this interface.
type BotFirstService interface {
	Service
	// CreateLoginLink creates an intent, signs a short-lived token, and returns
	// a user-facing URL for bot-initiated login flows.
	CreateLoginLink(ctx context.Context, in CreateLoginLinkInput) (CreateLoginLinkOutput, error)
	// RedeemLoginLink verifies the login-link token and performs standard intent
	// redemption to issue a web session.
	RedeemLoginLink(ctx context.Context, in RedeemLoginLinkInput) (WebSession, error)
}
