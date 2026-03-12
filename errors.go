package authkit

import "errors"

var (
	ErrInvalidInput                 = errors.New("authkit: invalid input")
	ErrIntentNotFound               = errors.New("authkit: intent not found")
	ErrIntentNotActive              = errors.New("authkit: intent is not active")
	ErrIntentExpired                = errors.New("authkit: intent expired")
	ErrIntentAlreadyRedeemed        = errors.New("authkit: intent already redeemed")
	ErrIntentRedemptionLimitReached = errors.New("authkit: intent redemption limit reached")
	ErrSubjectUnresolved            = errors.New("authkit: subject unresolved")
	ErrIdentityLinkNotFound         = errors.New("authkit: identity link not found")
	ErrCodeGenerationFailed         = errors.New("authkit: code generation failed")
	ErrIDGenerationFailed           = errors.New("authkit: id generation failed")
	ErrSessionNotFound              = errors.New("authkit: session not found")
	ErrSessionExpired               = errors.New("authkit: session expired")
)
