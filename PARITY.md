# Upstream parity checklist

Reference: [`evex-dev/linejs`](https://github.com/evex-dev/linejs) at
`ef6c3d9f70dd41fa51053615d47f071f58cf8db3`. Full parity covers the documented
LINEJS exports (`client`, `base`, `call`, `thrift`, `storage`, `types`) and the
repository's companion `agent` package. Go names and signatures may be idiomatic;
observable LINE behavior and supported capabilities are the parity target.

## Status

- [ ] `client`: login, event listening, users/chats/messages, profile, LIFF,
  VOOM, Square, and high-level call workflows.
- [ ] `base`: BaseClient transport/request pipeline, authentication and login,
  polling/push, timeline, E2EE, content upload/download, and all service APIs.
- [ ] `base` services: access-token refresh, account auth factor, auth,
  bot-external, buddy, call, channel, chat app, coin, device attestation, E2EE
  key backup, home safety check, LIFF, live talk, MOA, multi-profile, OA chat and
  membership, password update, premium font/status, primary account init/relogin/
  smart-switch and QR migration flows, primary seamless login, passwordless
  registration/login, relation, settings, shop/auth/collection, Square/SquareBot,
  and Talk.
- [ ] `call`: call control plane and media helpers, including signaling, audio,
  encryption, ICE, Planet transport/framing, RTP/RTCP, SDP, SIP, SRTP, and STUN.
  High-level route and group-call URL operations are implemented; media sessions
  and protocol helpers remain open.
- [ ] `thrift`: Compact and Binary Protocol APIs, generic read/write, struct/TMC
  helpers, message decoding, and LINE-specific request framing.
- [ ] `storage`: BaseStorage-compatible contract, MemoryStorage, FileStorage,
  typed key conventions, and migration semantics.
- [ ] `types`: complete request/response DTOs and enums from
  `@evex/linejs-types`, wire conversion, and explicit treatment of JavaScript
  int64/bigint values.
- [x] `agent` companion: Agent I URL/cookie/chat streaming client and native
  LINE AI REST plus query/cancel streaming API.

## Implemented

- [x] Compact Protocol struct codec and LINE v4 request header (`internal/protocol/thrift`).
- [x] Binary Protocol struct codec and strict Thrift CALL request header
  (`thrift`, backed by `internal/protocol/thrift`).
- [x] Compact/Binary message envelopes, decoding, and LINEJS's request terminator
  (`thrift`).
- [x] Concurrent-safe memory store, atomic JSON file store, CRUD snapshots,
  migration, and common storage key names (`storage`).
- [x] BaseClient device profiles, LINE headers, injectable HTTP transport,
  request deadlines, bounded response reads, gzip decoding, and next-access-token
  rotation (`base`).
- [x] LEGY auto/on/off selection, encrypted Talk request wrapping, response
  decryption and status/header recovery, access-token resolution, and bounded
  response handling (`internal/protocol/legy`, `base`).
- [x] Serialized, per-service request-sequence allocation persisted under the
  upstream `reqseq` key (`base`).
- [x] Generated DTO declarations for all 2,520 schema structs and 314 enums
  (`types`) and reflection-based tagged Thrift request/response conversion
  (`thrift`, `base.RequestTyped`).
- [x] Initial Talk service operations: long-poll `sync`, typed plain
  `sendMessage`, and `fetchOperations`, including request-sequence allocation
  and typed service exceptions (`base.TalkService`).
- [x] High-level client composition with default HTTP/storage adapters and a
  domain-facing message send/mapping path (root `line.Client`).
- [x] Initial high-level profile read/update, joined Talk chat listing and lookup,
  friend listing and lookup through Contacts V3, text sends from `Chat`/`User`,
  Contacts V2 and per-user fallbacks, chat rename/invite/kick/leave/history/BGM,
  and contact rename/favorite/notification/hide operations.
- [x] Auth-token login with raw, newline-paired JWT, and JSON credential inputs;
  refresh token/expiry persistence and profile readiness (`line.LoginWithAuthToken`).
- [x] Secure ForSecure QR login session, QR/PIN long polling, certificate
  fallback, token persistence, and profile readiness (`line.LoginWithSecureQR`).
- [x] Device-selected ForSecure or legacy QR login, legacy QR URL exchange,
  QR/PIN approval, certificate fallback, E2EE key initialization, token
  persistence, and profile readiness (`line.LoginWithQR`).
- [x] RSA-protected email/password login on legacy and token-v3 endpoints,
  PIN/verifier confirmation, E2EE key-chain restore, certificate reuse, token
  persistence, and profile readiness (`base.LoginService`, `line.LoginWithPassword`).
- [x] E2EE X25519 key generation/validation, QR-secret creation, encrypted
  key-chain restore, registered-key verification, and key persistence by key ID
  and account MID (`base.E2EEService`).
- [x] E2EE v2 text/location/JSON encryption for user and group chats, direct
  and group key negotiation/registration, and text/location decryption for chat
  history (`base.E2EEService`, `base.TalkService`, `line.Client`).
- [x] Zero-argument `getE2EEPublicKeys` compatibility call used by login-key
  verification (`base.TalkService`).
- [x] Generated route catalog for 38 upstream Thrift services and 407 typed
  RPC method routes, with typed per-service Args/Result methods, endpoint
  overrides, and result-envelope exception conversion (`cmd/genservices`).
- [x] Refresh-token exchange, access-token rotation, refresh-token/expiry
  persistence, stale-token refresh/retry, refreshed-token reporting, and
  logout (`base.AuthService`, root `line.Client`).
- [x] Context-cancelable Talk and Square long-poll event streams, including Talk
  revision tracking, Square sync/continuation tokens, and high-level message
  mapping for Talk message operations (`base.Polling`, root `line.Client`).
- [x] Persistent Talk/Square push sign-on, Compact and TMoreCompact response
  decoding, Talk revision and Square sync-token updates, ping/push acknowledgments,
  high-level event mapping, token-change renewal, and bounded reconnect backoff
  (`base.Push`, root `line.Client`). Push sign-on currently dispatches Talk
  services 5/8 and Square service 3; other subscribed service handlers remain
  unimplemented.
- [x] HTTP/2 push connection, LINE packet framing, ping/push acknowledgement
  frames, service subscription mask, bounded frame delivery, and the injected
  base transport port (`internal/transport/push`, `base.BaseClient`).
- [x] OBS service uploads and downloads for Talk, Square, E2EE media, and
  externally hosted content URLs; E2EE previews, metadata, and profile image
  uploads (`base.ObjectStorage`, root `line.Client`).
- [x] Timeline v57 channel-token setup, post create/read/list/update/delete,
  reactions, comments, sharing, and legacy Note attachment uploads
  (`base.TimelineService`, root `line.Client`). Responses preserve operation
  payloads as raw JSON because upstream returns a loose result shape.
- [x] Companion Agent I Yahoo SSE client and native LINE AI REST/SSE client,
  including cookie bootstrapping, multi-turn history, thread lifecycle,
  prompt presets, agreement, cancellation, and rate-limit metadata
  (`agent`).
- [x] High-level call route and group-call URL controls, group call state,
  invite/kick operations, default device environment info, and incoming/cancel
  operation parsing (`line.CallClient`). Call signaling/media remains open.

This checklist is intentionally feature-oriented; a package is complete only
after all upstream public methods, wire behavior, and supported data shapes have
Go implementations with evidence of behavioral parity.
