// Package storage provides persistent and in-memory storage for LINE client state.
package storage

import "context"

// Value is a JSON-compatible value stored by a LINE client.
//
// Supported values are nil, booleans, strings, numbers, slices, and string-keyed
// maps composed recursively from those values. FileStorage validates values by
// JSON encoding them; MemoryStorage applies the same constraint for parity.
type Value = any

// Store is the CRUD state store capability consumed by clients.
type Store interface {
	Set(ctx context.Context, key string, value Value) error
	Get(ctx context.Context, key string) (Value, bool, error)
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
}

// Storage is the complete public storage contract, including migration.
type Storage interface {
	Store
	GetAll(ctx context.Context) (map[string]Value, error)
	Migrate(ctx context.Context, destination Store) error
}
