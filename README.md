# authkit

`authkit` is a small Go package for passwordless web authentication via messenger-driven identity.

It is transport-agnostic and framework-agnostic:
- no HTTP dependency
- no Telegram/Discord hardcoding
- works in monoliths and microservices

## Purpose

Use `authkit` when you want this flow:
1. Create an auth intent (`code`) for a messenger context.
2. Deliver that code through any channel.
3. Redeem the code once (or multiple times, if configured).
4. Issue a web session token.

Bot-first flow is also supported:
1. User starts in messenger (`/start` / `/login`).
2. App creates signed login link via `CreateLoginLink`.
3. User opens link and backend redeems via `RedeemLoginLink`.

## Core Concepts

- `Messenger`: normalized messenger identifier (string-based, fully configurable).
- `Identity`: optional profile from messenger (`Username`, `Name`, `Surname`, `BirthDate`, custom `Attributes`).
- `AuthIntent`: redeemable challenge with TTL and redemption policy.
- `AccountLink`: mapping from messenger identity to internal app user.
- `WebSession`: auth result issued by your `SessionIssuer`.

## What authkit guarantees

- Input normalization/validation.
- One-time or reusable intent policies.
- Optional expiry (`ExpiresAt`) with default TTL support.
- Replay prevention based on store redemption state.
- Deterministic behavior via injectable clock/id/code generators.

## Package Structure

- `types.go`: domain structs and interfaces.
- `service.go`: core auth logic (`NewAuthService`, `CreateIntent`, `RedeemIntent`).
- `inmemory.go`: ready-to-use in-memory adapters for local/dev/tests.
- `errors.go`: typed sentinel errors for `errors.Is`.

## Quick Start (in-memory)

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/supercakecrumb/adhd-game-bot/authkit"
)

func main() {
	ctx := context.Background()

	intentStore := authkit.NewInMemoryIntentStore()
	linkStore := authkit.NewInMemoryLinkStore()
	sessionIssuer, _ := authkit.NewInMemorySessionIssuer(24 * time.Hour)

	service, _ := authkit.NewAuthService(intentStore, linkStore, sessionIssuer)

	// Link messenger identity -> your internal user id.
	_ = linkStore.Upsert(ctx, authkit.AccountLink{
		AppUserID: "user-42",
		Identity: authkit.Identity{
			Messenger:       authkit.NewMessenger("telegram"),
			MessengerUserID: "123456",
			Username:        "jane",
		},
		LinkedAt: time.Now().UTC(),
	})

	intent, _ := service.CreateIntent(ctx, authkit.CreateIntentInput{
		Messenger: authkit.NewMessenger("telegram"),
		Audience:  "web",
		// SubjectID optional: if omitted, authkit resolves it from LinkStore.
	})

	session, err := service.RedeemIntent(ctx, authkit.RedeemIntentInput{
		Code:      intent.Code,
		Messenger: authkit.NewMessenger("telegram"),
		Identity: &authkit.Identity{
			MessengerUserID: "123456",
		},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("session token:", session.Token)

	// Redeeming again fails for one-time intents.
	_, err = service.RedeemIntent(ctx, authkit.RedeemIntentInput{
		Code:      intent.Code,
		Messenger: authkit.NewMessenger("telegram"),
		Identity: &authkit.Identity{
			MessengerUserID: "123456",
		},
	})
	if errors.Is(err, authkit.ErrIntentAlreadyRedeemed) {
		fmt.Println("already redeemed")
	}
}
```

## Known Subject Flow (no identity needed)

If your app already knows internal user ID at intent creation time:

```go
intent, _ := service.CreateIntent(ctx, authkit.CreateIntentInput{
	Messenger: authkit.NewMessenger("discord"),
	SubjectID: "internal-user-99",
})

session, _ := service.RedeemIntent(ctx, authkit.RedeemIntentInput{
	Code:      intent.Code,
	Messenger: authkit.NewMessenger("discord"),
})
```

## Reusable / Static Intent

```go
intent, _ := service.CreateIntent(ctx, authkit.CreateIntentInput{
	Messenger:      authkit.NewMessenger("slack"),
	SubjectID:      "user-1",
	RedemptionMode: authkit.IntentReusable,
	MaxRedemptions: 10, // 0 means unlimited for reusable intents
})
```

## Bot-First Login Link

```go
service, _ := authkit.NewAuthService(
	intentStore,
	linkStore,
	sessionIssuer,
	authkit.WithSignedQueryLoginLinks(
		"https://app.example/auth/complete",
		[]byte("replace-with-long-random-secret"),
		"auth_token",
	),
	authkit.WithMissingIdentityLinkMode(authkit.MissingIdentityLinkStrict),
)

login, _ := service.CreateLoginLink(ctx, authkit.CreateLoginLinkInput{
	Messenger: authkit.NewMessenger("telegram"),
	Identity: &authkit.Identity{
		MessengerUserID: "123456",
	},
})

// Send login.LoginURL to user in messenger chat.
session, _ := service.RedeemLoginLink(ctx, authkit.RedeemLoginLinkInput{
	LinkToken: login.LinkToken,
})
_ = session
```

## Extending for Production

Implement these interfaces:

- `IntentStore`: persist intents in SQL/Redis.
- `LinkStore`: resolve messenger identity to app user.
- `SessionIssuer`: issue/validate JWT or opaque sessions.

Optional:
- `ChannelAdapter`: delivery integration (send the intent code/link via messenger).

### Service wiring

```go
intentStore := NewPostgresIntentStore(db)
linkStore := NewPostgresLinkStore(db)
sessionIssuer := NewJWTIssuer(signingKey)

service, err := authkit.NewAuthService(
	intentStore,
	linkStore,
	sessionIssuer,
	authkit.WithConfig(authkit.Config{
		DefaultIntentTTL:              10 * time.Minute,
		DefaultRedemptionMode:         authkit.IntentOneTime,
		DefaultReusableMaxRedemptions: 0,
	}),
)
```

## Error Handling

Use `errors.Is` with sentinels from `errors.go`:
- `ErrInvalidInput`
- `ErrIntentNotFound`
- `ErrIntentExpired`
- `ErrIntentAlreadyRedeemed`
- `ErrIntentRedemptionLimitReached`
- `ErrSubjectUnresolved`
- `ErrIdentityLinkNotFound`
- `ErrSessionNotFound`
- `ErrSessionExpired`
- `ErrLoginLinkNotConfigured`
- `ErrLoginLinkInvalid`
- `ErrLoginLinkExpired`

## Notes

- `NewMessenger(" TeLeGrAm ")` normalizes to `"telegram"`.
- `Identity` is optional: web flows can work without profile attributes.
- Redeem path consumes intent before issuing session (security-first). If session issuance fails, create a new intent.
