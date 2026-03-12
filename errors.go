package authkit

import "errors"

// Package-level sentinel errors returned by authkit public APIs.
var (
	// ErrInvalidInput indicates caller-provided data failed validation.
	ErrInvalidInput = errors.New("authkit: invalid input")
	// ErrIntentNotFound indicates the requested intent does not exist.
	ErrIntentNotFound = errors.New("authkit: intent not found")
	// ErrIntentNotActive indicates intent state is not redeemable.
	ErrIntentNotActive = errors.New("authkit: intent is not active")
	// ErrIntentExpired indicates intent expiration has passed.
	ErrIntentExpired = errors.New("authkit: intent expired")
	// ErrIntentAlreadyRedeemed indicates one-time intent was already used.
	ErrIntentAlreadyRedeemed = errors.New("authkit: intent already redeemed")
	// ErrIntentRedemptionLimitReached indicates reusable intent hit max count.
	ErrIntentRedemptionLimitReached = errors.New("authkit: intent redemption limit reached")
	// ErrSubjectUnresolved indicates authkit could not determine internal user id.
	ErrSubjectUnresolved = errors.New("authkit: subject unresolved")
	// ErrIdentityLinkNotFound indicates no identity->user mapping exists.
	ErrIdentityLinkNotFound = errors.New("authkit: identity link not found")
	// ErrCodeGenerationFailed indicates code/token generator failure.
	ErrCodeGenerationFailed = errors.New("authkit: code generation failed")
	// ErrIDGenerationFailed indicates ID generator failure.
	ErrIDGenerationFailed = errors.New("authkit: id generation failed")
	// ErrSessionNotFound indicates provided session token is unknown.
	ErrSessionNotFound = errors.New("authkit: session not found")
	// ErrSessionExpired indicates session token exists but is expired.
	ErrSessionExpired = errors.New("authkit: session expired")
	// ErrLoginLinkNotConfigured indicates bot-first login-link dependencies are
	// not configured on AuthService.
	ErrLoginLinkNotConfigured = errors.New("authkit: login link is not configured")
	// ErrLoginLinkInvalid indicates login-link token or URL payload is malformed
	// or failed signature verification.
	ErrLoginLinkInvalid = errors.New("authkit: login link is invalid")
	// ErrLoginLinkExpired indicates login-link token is no longer valid by time.
	ErrLoginLinkExpired = errors.New("authkit: login link expired")
)
