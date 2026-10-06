# Upstream service catalog

`linejs_services.json` records the Thrift service endpoint and protocol map
from LINEJS commit `ef6c3d9f70dd41fa51053615d47f071f58cf8db3`. Its method lists
are the Thrift-backed methods exposed by the corresponding service modules at
that revision. The catalog generator cross-checks each method against
`types/schema.json` before emitting the Go route table.

Regenerate the route table and typed service methods from the repository root
with:

```sh
go run ./cmd/genservices
```

The manifest includes method-level endpoint overrides for RPCs that LINEJS
sends to a path other than the service's default endpoint.
