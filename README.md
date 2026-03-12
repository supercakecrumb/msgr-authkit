# authkit

`authkit` is a transport-agnostic Go library for passwordless auth driven by messenger identity.

Design goals:
- no HTTP framework dependency
- no Telegram/Discord coupling in core
- works in monoliths and microservices
- explicit interfaces for persistence/session issuance

## Who This README Is For

If you are an AI agent (or a developer) integrating this package, this file is intended to be enough to implement a working auth flow without reading package internals.

## Import Path

```go
import authkit "github.com/supercakecrumb/msgr-authkit"
```

## Fast Mental Model

`authkit` has two primary flows:

1. **Intent flow (code-first)**
- create auth intent (`CreateIntent`)
- deliver intent code by any channel
- redeem code (`RedeemIntent`)
- get `WebSession`

2. **Bot-first login-link flow**
- user starts in messenger (`/start`, `/login`)
- app creates signed login link (`CreateLoginLink`)
- user opens link in browser
- backend redeems token (`RedeemLoginLink`)
- get `WebSession`

## Core Types You Need

- `Messenger`: normalized messenger identifier
- `Identity`: messenger user profile data
- `AuthIntent`: challenge/token state with redemption policy
- `AccountLink`: mapping `messenger identity -> internal app user id`
- `WebSession`: result returned by your `SessionIssuer`

## Required Interfaces (Production)

You must provide:
- `IntentStore`
- `SessionIssuer`

You usually provide:
- `LinkStore` (needed when subject is not known at create time)

Optional for bot-first:
- `LoginTokenCodec`, `LoginLinkBuilder` (or just use `WithSignedQueryLoginLinks`)
- `AudienceResolver`
- `LinkProvisioner`

## What authkit Guarantees

- input normalization/validation
- one-time or reusable intent policy enforcement
- expiration checks (intent + login-link token)
- deterministic behavior via injectable clock/code/id generators
- security-first redeem ordering (consume intent before issuing session)

## Integration Protocol (Agent Checklist)

1. Choose flow:
- `CreateIntent/RedeemIntent` if your UI starts in web.
- `CreateLoginLink/RedeemLoginLink` if your UI starts in messenger.

2. Decide subject resolution strategy:
- known `SubjectID` at create time, or
- resolve via `LinkStore`, or
- auto-provision via `WithMissingIdentityLinkMode(MissingIdentityLinkAutoProvision)` + `WithLinkProvisioner`.

3. Wire service:
- instantiate stores + session issuer
- call `NewAuthService(...)`
- apply `WithConfig(...)`
- for bot-first add `WithSignedQueryLoginLinks(...)`

4. Implement error mapping:
- map sentinel errors to HTTP statuses / user-visible messages with `errors.Is`.

5. Add tests:
- intent create/redeem happy path
- replay and expiration cases
- missing link behavior by mode

## Minimal In-Memory Example

```go
package main

import (
	"context"
	"fmt"
	"time"

	authkit "github.com/supercakecrumb/msgr-authkit"
)

func main() {
	ctx := context.Background()

	intentStore := authkit.NewInMemoryIntentStore()
	linkStore := authkit.NewInMemoryLinkStore()
	sessionIssuer, _ := authkit.NewInMemorySessionIssuer(24 * time.Hour)

	service, _ := authkit.NewAuthService(intentStore, linkStore, sessionIssuer)

	_ = linkStore.Upsert(ctx, authkit.AccountLink{
		AppUserID: "user-42",
		Identity: authkit.Identity{
			Messenger:       authkit.NewMessenger("telegram"),
			MessengerUserID: "123456",
		},
		LinkedAt: time.Now().UTC(),
	})

	intent, _ := service.CreateIntent(ctx, authkit.CreateIntentInput{
		Messenger: authkit.NewMessenger("telegram"),
		Audience:  "web",
	})

	session, _ := service.RedeemIntent(ctx, authkit.RedeemIntentInput{
		Code:      intent.Code,
		Messenger: authkit.NewMessenger("telegram"),
		Identity:  &authkit.Identity{MessengerUserID: "123456"},
	})

	fmt.Println(session.Token)
}
```

## Bot-First (Recommended Minimal Setup)

```go
service, _ := authkit.NewAuthService(
	intentStore,
	linkStore,
	sessionIssuer,
	authkit.WithSignedQueryLoginLinks(
		"https://app.example/auth/redeem", // public URL
		[]byte("replace-with-long-random-secret"),
		"auth_token",
	),
	authkit.WithMissingIdentityLinkMode(authkit.MissingIdentityLinkAutoProvision),
	authkit.WithLinkProvisioner(authkit.LinkProvisionerFunc(
		func(ctx context.Context, identity authkit.Identity) (authkit.AccountLink, error) {
			return authkit.AccountLink{
				AppUserID: "tg:" + identity.MessengerUserID,
				Identity:  identity,
				LinkedAt:  time.Now().UTC(),
			}, nil
		},
	)),
)

login, _ := service.CreateLoginLink(ctx, authkit.CreateLoginLinkInput{
	Messenger: authkit.NewMessenger("telegram"),
	Identity: &authkit.Identity{
		Messenger:       authkit.NewMessenger("telegram"),
		MessengerUserID: "123456",
	},
})

// send login.LoginURL via bot
session, _ := service.RedeemLoginLink(ctx, authkit.RedeemLoginLinkInput{LinkToken: login.LinkToken})
_ = session
```

## Config Defaults

`DefaultConfig()` currently means:
- `DefaultIntentTTL = 15m`
- `DefaultRedemptionMode = IntentOneTime`
- `DefaultReusableMaxRedemptions = 0` (unlimited if reusable)
- `DefaultLoginLinkTTL = 5m`

Override with `WithConfig(...)`.

## Missing Identity Link Modes

When creating login links with identity but no existing `LinkStore` mapping:

- `MissingIdentityLinkDeferred`
  - allow create now, resolve subject later during redeem
- `MissingIdentityLinkStrict`
  - fail immediately with `ErrIdentityLinkNotFound`
- `MissingIdentityLinkAutoProvision`
  - call `LinkProvisioner`, optional `LinkStore.Upsert`

## Error Handling Contract

Use `errors.Is(err, ...)` with sentinels:
- `ErrInvalidInput`
- `ErrIntentNotFound`
- `ErrIntentNotActive`
- `ErrIntentExpired`
- `ErrIntentAlreadyRedeemed`
- `ErrIntentRedemptionLimitReached`
- `ErrSubjectUnresolved`
- `ErrIdentityLinkNotFound`
- `ErrCodeGenerationFailed`
- `ErrIDGenerationFailed`
- `ErrSessionNotFound`
- `ErrSessionExpired`
- `ErrLoginLinkNotConfigured`
- `ErrLoginLinkInvalid`
- `ErrLoginLinkExpired`

Suggested HTTP mapping:
- invalid input: `400`
- not found/invalid token: `404`/`401`
- expired/redeemed: `409` or `401` depending on UX
- unresolved subject/link missing: `422` or `401`

## Production Implementation Notes

- `IntentStore.RecordRedemption` should be atomic (transaction/compare-and-swap) to prevent replay races.
- Normalize messenger IDs with `NewMessenger` everywhere.
- Keep login-link signing key long/random and rotated.
- Keep login-link TTL short.
- Prefer one-time intents for auth links.
- Ensure bot-to-web internal endpoint is authenticated.
- For Telegram URL buttons, prefer public `https` URLs.

## Testing Matrix (Minimum)

1. one-time intent can be redeemed once
2. second redeem returns `ErrIntentAlreadyRedeemed`
3. expired intent returns `ErrIntentExpired`
4. missing subject and missing link returns `ErrSubjectUnresolved`/`ErrIdentityLinkNotFound`
5. bot-first invalid token returns `ErrLoginLinkInvalid`
6. bot-first expired token returns `ErrLoginLinkExpired`

## Package Map

- `types.go`: domain models + interfaces
- `service.go`: `AuthService` + options + bot-first helpers
- `inmemory.go`: in-memory adapters for demos/tests
- `errors.go`: sentinel errors for `errors.Is`

## Quick FAQ

**Do I need to use Telegram?**
No. Messenger is just a normalized string ID.

**Can I use JWT sessions?**
Yes. Implement `SessionIssuer` with JWT issuance/validation.

**Can I skip LinkStore?**
Yes if you always pass `SubjectID` during create.

**Can I keep intents reusable?**
Yes via `IntentReusable`, but one-time is safer for login.
