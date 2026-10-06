# Architecture

`line-go` is a Go SDK, so Clean Architecture should protect the public client
contracts from protocol and transport details without turning every feature into
an application/use-case package. Keep the package graph small and let consumer
packages own the interfaces they need.

## Intended package map

```text
.
├── client.go                 # package line: high-level Client and domain models
├── base/                     # public BaseClient and direct service methods
├── types/                    # public LINE request/response DTOs and enums
├── storage/                  # public storage contract and memory/file stores
├── thrift/                   # public protocol API backed by internal codecs
├── agent/                    # standalone Agent I and native LINE AI clients
└── internal/
    ├── protocol/
    │   ├── thrift/            # Compact/Binary codec implementation
    │   └── legy/              # LEGY request wrapping
    ├── crypto/
    │   └── e2ee/              # X25519 and AES protocol primitives
    ├── transport/
    │   ├── http/              # HTTP request/response adapter
    │   └── push/              # streaming push connection and framing
    └── e2ee/                  # LINE key handling and message crypto
```

The high-level `line.Client` owns convenient workflows and maps public LINE DTOs
to distinct domain-facing `Chat`, `User`, and `Message` values. `base.BaseClient`
exposes direct service operations and returns the typed DTOs from `types`. Both
remain supported public entry points; the high-level package depends on `base`,
never the reverse.

## Dependency rules

1. `line` may depend on `base`, `types`, and internal adapters to compose the
   default client.
2. `base` may depend on `types`, internal protocol/crypto primitives, and narrow
   ports declared at the point of use. It must not import `line` or concrete
   HTTP, push, or storage adapters.
3. Internal adapters implement those ports. The public `thrift` package exposes
   LINEJS's Thrift capability through a facade backed by `internal/protocol`,
   while LEGY remains internal. The public `storage` package exposes the storage
   contract and memory/file implementations; `base` consumes a narrower
   interface declared at its own boundary.
4. `types` contains service DTOs and enums only. It does not depend on clients,
   transports, or domain-facing convenience models.
5. Keep cryptographic primitives in `internal/crypto`; expose workflows through
   `base.E2EEService` so clients do not depend on algorithm details. Convert
   DTOs to domain-facing values at the `line` facade boundary. Avoid aliases
   between these model sets so protocol changes do not silently change the
   convenience API.
6. Add interfaces only for actual seams: injected HTTP, persistent storage, and
   push streams are likely ports; avoid a generic repository or service-locator
   layer without a concrete need.

The root `line` package should be the composition root: it selects default
adapters and injects them into `base.BaseClient`. Direct `base` users should be
able to supply their own port implementations. This preserves customization
without making the protocol packages public.

## Current implementation

`internal/protocol/thrift` owns the wire value model and Compact/Binary Protocol
codecs, and `internal/protocol/legy` owns encrypted gateway framing; `thrift`
exposes message, struct, and request-framing APIs. The public
`storage` package provides concurrent-safe memory and atomic JSON-file stores.
`base.BaseClient` now composes those capabilities into direct HTTP/Thrift calls
with LINE device headers, access-token rotation, persisted request sequences,
and typed DTO request/response conversion. `types` contains generated DTO
declarations for the upstream Thrift schema. The `base` request pipeline selects
direct or LEGY-encrypted transport from configuration and token type. The initial
`TalkService` operations are available through `BaseClient.Talk()`. `BaseClient.Service`
exposes generated typed methods for 38 services and 407 RPC routes, including
method-specific paths and service exception conversion. `BaseClient.Auth()`
also supports refresh-token exchange, rotated-token persistence, stale-token
retry, and logout. `BaseClient.Polling()` exposes context-cancelable Talk and
Square long-poll event streams with sync cursor and continuation-token handling.
`BaseClient.Push()` exposes persistent Talk and Square event streams through the
HTTP/2 adapter, including sign-on, response decoding, acknowledgments, and
bounded reconnects. The high-level client exposes both transports as event
channels.
The root `line.Client` composes default HTTP and
memory-storage adapters and maps profiles, chats, contacts, and sent messages
to high-level values. It supports profile read/update, friend and joined-chat
lookup, chat membership and history actions, contact settings, message send,
auth-token and password login with profile readiness, and Talk/Square event
streams. Secure ForSecure and legacy QR flows, token persistence, E2EE key
restoration/registration, and E2EE text/location message encryption and
history decryption are also implemented. Push sign-on and dispatch currently
cover Talk services 5/8 and Square service 3. `base.ObjectStorage` owns LINE
OBS requests, Talk/Square media upload and download, E2EE media encryption, and
profile image upload; the root client maps those operations to domain messages.
`base.TimelineService` handles channel-token setup, JSON post actions, and
legacy Note media uploads. Its endpoint result remains raw JSON to match the
upstream loose response contract. The standalone `agent` package ports the
Yahoo Agent I and native LINE AI streaming clients. Calling, LIFF, most Square
media/signaling, LIFF, most Square workflows, and the remaining `Chat` and
`User` workflows also remain
outstanding; placeholder packages are intentionally
omitted.
