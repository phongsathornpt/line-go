package storage

import (
	"context"
	"fmt"
	"sync"
)

// MemoryStorage keeps JSON-compatible values in memory and is safe for
// concurrent use.
type MemoryStorage struct {
	mu   sync.RWMutex
	data map[string][]byte
}

var _ Storage = (*MemoryStorage)(nil)

// NewMemoryStorage creates an empty in-memory store.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{data: make(map[string][]byte)}
}

// NewMemoryStorageWithData creates an in-memory store initialized with values.
func NewMemoryStorageWithData(initial map[string]Value) (*MemoryStorage, error) {
	data, err := encodeValues(initial)
	if err != nil {
		return nil, err
	}

	store := NewMemoryStorage()
	for key, value := range data {
		store.data[key] = value
	}
	return store, nil
}

// Set stores a JSON-compatible value under key.
func (s *MemoryStorage) Set(ctx context.Context, key string, value Value) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	data, err := encodeValue(value)
	if err != nil {
		return fmt.Errorf("storage set %q: %w", key, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.data[key] = data
	return nil
}

// Get returns the value for key. The boolean reports whether the key exists.
func (s *MemoryStorage) Get(ctx context.Context, key string) (Value, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	s.mu.RLock()
	data, ok := s.data[key]
	if ok {
		data = append([]byte(nil), data...)
	}
	s.mu.RUnlock()
	if !ok {
		return nil, false, nil
	}

	value, err := decodeValue(data)
	if err != nil {
		return nil, false, fmt.Errorf("storage get %q: %w", key, err)
	}
	return value, true, nil
}

// Delete removes key if it exists.
func (s *MemoryStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	delete(s.data, key)
	return nil
}

// Clear removes all stored values.
func (s *MemoryStorage) Clear(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.data = make(map[string][]byte)
	return nil
}

// GetAll returns a detached snapshot of the stored values.
func (s *MemoryStorage) GetAll(ctx context.Context) (map[string]Value, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	data := make(map[string][]byte, len(s.data))
	for key, value := range s.data {
		data[key] = append([]byte(nil), value...)
	}
	s.mu.RUnlock()

	values := make(map[string]Value, len(data))
	for key, value := range data {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		decoded, err := decodeValue(value)
		if err != nil {
			return nil, fmt.Errorf("storage get all %q: %w", key, err)
		}
		values[key] = decoded
	}
	return values, nil
}

// Migrate copies a snapshot of this store into destination. Existing keys in
// destination are overwritten; keys not present here are left untouched.
func (s *MemoryStorage) Migrate(ctx context.Context, destination Store) error {
	if destination == nil {
		return fmt.Errorf("storage migrate: destination is nil")
	}

	values, err := s.GetAll(ctx)
	if err != nil {
		return fmt.Errorf("storage migrate: read source: %w", err)
	}
	for key, value := range values {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := destination.Set(ctx, key, value); err != nil {
			return fmt.Errorf("storage migrate: write key %q: %w", key, err)
		}
	}
	return nil
}
