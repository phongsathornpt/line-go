package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// FileStorage persists the complete state map as a JSON object. Writes are
// serialized and committed with an atomic rename, so readers never observe a
// partially written file.
type FileStorage struct {
	path string
	mu   sync.Mutex
}

var _ Storage = (*FileStorage)(nil)

// NewFileStorage opens path, creating its parent directories and an initial
// JSON file if needed. Initial values are used only when the file does not yet
// exist.
func NewFileStorage(path string, initial map[string]Value) (*FileStorage, error) {
	if path == "" {
		return nil, fmt.Errorf("storage file: path is empty")
	}

	store := &FileStorage{path: path}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("storage file: create parent directory: %w", err)
	}

	_, err := os.Stat(path)
	if err == nil {
		if _, err := store.readAll(); err != nil {
			return nil, fmt.Errorf("storage file: load %q: %w", path, err)
		}
		return store, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("storage file: inspect %q: %w", path, err)
	}

	data, err := encodeValues(initial)
	if err != nil {
		return nil, fmt.Errorf("storage file: encode initial values: %w", err)
	}
	if err := store.writeAll(data); err != nil {
		return nil, fmt.Errorf("storage file: initialize %q: %w", path, err)
	}
	return store, nil
}

// Set stores a JSON-compatible value under key.
func (s *FileStorage) Set(ctx context.Context, key string, value Value) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	encoded, err := encodeValue(value)
	if err != nil {
		return fmt.Errorf("storage set %q: %w", key, err)
	}
	return s.update(ctx, func(data map[string]json.RawMessage) {
		data[key] = encoded
	})
}

// Get returns the value for key. The boolean reports whether the key exists.
func (s *FileStorage) Get(ctx context.Context, key string) (Value, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	data, err := s.readAll()
	if err != nil {
		return nil, false, fmt.Errorf("storage get %q: %w", key, err)
	}
	encoded, ok := data[key]
	if !ok {
		return nil, false, nil
	}
	value, err := decodeValue(encoded)
	if err != nil {
		return nil, false, fmt.Errorf("storage get %q: %w", key, err)
	}
	return value, true, nil
}

// Delete removes key if it exists.
func (s *FileStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.update(ctx, func(data map[string]json.RawMessage) {
		delete(data, key)
	})
}

// Clear removes all stored values.
func (s *FileStorage) Clear(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.update(ctx, func(data map[string]json.RawMessage) {
		clear(data)
	})
}

// GetAll returns a detached snapshot of the stored values.
func (s *FileStorage) GetAll(ctx context.Context) (map[string]Value, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	data, err := s.readAll()
	if err != nil {
		return nil, fmt.Errorf("storage get all: %w", err)
	}
	values, err := decodeValues(data)
	if err != nil {
		return nil, fmt.Errorf("storage get all: %w", err)
	}
	return values, nil
}

// Migrate copies a snapshot of this store into destination. Existing keys in
// destination are overwritten; keys not present here are left untouched.
func (s *FileStorage) Migrate(ctx context.Context, destination Store) error {
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

func (s *FileStorage) readAll() (map[string]json.RawMessage, error) {
	file, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	data := make(map[string]json.RawMessage)
	if err := decoder.Decode(&data); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("decode JSON object: file is empty")
		}
		return nil, fmt.Errorf("decode JSON object: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("decode JSON object: top-level value is not an object")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode JSON object: trailing JSON value")
		}
		return nil, fmt.Errorf("decode JSON object: %w", err)
	}
	return data, nil
}

func (s *FileStorage) update(ctx context.Context, mutate func(map[string]json.RawMessage)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	data, err := s.readAll()
	if err != nil {
		return fmt.Errorf("storage update: read file: %w", err)
	}
	mutate(data)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.writeAll(data); err != nil {
		return fmt.Errorf("storage update: write file: %w", err)
	}
	return nil
}

func (s *FileStorage) writeAll(data map[string]json.RawMessage) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode JSON object: %w", err)
	}

	directory := filepath.Dir(s.path)
	file, err := os.CreateTemp(directory, ".line-go-storage-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	committed := false
	defer func() {
		file.Close()
		if !committed {
			os.Remove(temporaryPath)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		return err
	}
	written, err := file.Write(encoded)
	if err != nil {
		return err
	}
	if written != len(encoded) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return err
	}
	committed = true
	return nil
}
