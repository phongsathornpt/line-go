# Generated LINE types

`models_gen.go` contains the Go declarations generated from all structs and
enums in `schema.json`. The schema was extracted from
`evex-dev/linejs` at commit `ef6c3d9f70dd41fa51053615d47f071f58cf8db3`.

To refresh the schema from a local upstream checkout and regenerate the Go
declarations:

```sh
node scripts/extract_thrift_schema.mjs ../linejs/packages/types/thrift.ts types/schema.json
go run ./cmd/gentypes
```

The generated DTOs are intentionally independent of clients and transports.
Their `thrift` tags are consumed by the public `thrift` package for wire
conversion.
