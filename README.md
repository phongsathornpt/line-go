# line-go

An idiomatic Go port of [LINEJS](https://github.com/evex-dev/linejs).

The current implementation includes Compact and Binary Thrift struct codecs,
LINEJS request framing, and the public memory/file storage package. The upstream
reference is pinned at
[`ef6c3d9`](https://github.com/evex-dev/linejs/commit/ef6c3d9f70dd41fa51053615d47f071f58cf8db3).

## Current status

- `thrift`: public Compact/Binary message and struct codecs, LINEJS request framing
- `internal/protocol/thrift`: codec implementation
- `storage`: memory and atomic JSON-file stores, migration, and well-known storage keys
- `base`: device profiles, direct and LEGY-encrypted HTTP/Thrift requests,
  persisted request sequences, initial Talk operations, token refresh/retry/logout,
  Talk and Square long-poll and persistent push event streams, secure and
  legacy QR login calls, password login, E2EE message/key management, plain and
  E2EE media upload/download through OBS, Timeline post and Note media
  workflows, and generated typed methods for 38 service endpoints
- root `line.Client`: default adapter composition, profile read/update, friend and
  joined-chat lookup, chat membership/history/BGM actions, message send, contact
  settings, auth-token/password/QR login, token refresh, call control, and
  Talk/Square event streams over polling or push
- `base.BaseClient.Service`: generated routes for 38 services and 407 typed RPC methods
- `types`: generated declarations for 2,520 Thrift structs and 314 enums, with tagged request/response wire conversion
- `agent`: Agent I Yahoo SSE client and native LINE AI REST/SSE client
- Media: Talk/Square OBS upload and download, E2EE file encryption, high-level
  message media retrieval, and profile image/background upload
- Push sign-on/event dispatch currently covers Talk services 5/8 and Square
  service 3. Other push services, call media/signaling, LIFF, and remaining
  high-level workflows are still being ported

```go
package main

import (
	"context"
	"log"

	line "github.com/phongsathornpt/line-go"
)

func main() {
	client, err := line.NewClient(line.ClientOptions{Device: line.DeviceAndroid})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	text := "hello"
	_, err = client.SendMessage(context.Background(), line.SendMessageOptions{
		To:   "u0123456789abcdef0123456789abcdef",
		Text: &text,
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for package boundaries and [PARITY.md](PARITY.md)
for the upstream feature checklist.
