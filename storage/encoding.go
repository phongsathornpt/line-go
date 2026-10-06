package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func encodeValue(value Value) (json.RawMessage, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode storage value: %w", err)
	}
	return json.RawMessage(data), nil
}

func decodeValue(data json.RawMessage) (Value, error) {
	var value Value
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode storage value: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode storage value: trailing JSON value")
		}
		return nil, fmt.Errorf("decode storage value: %w", err)
	}
	return value, nil
}

func encodeValues(values map[string]Value) (map[string]json.RawMessage, error) {
	encoded := make(map[string]json.RawMessage, len(values))
	for key, value := range values {
		data, err := encodeValue(value)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", key, err)
		}
		encoded[key] = data
	}
	return encoded, nil
}

func decodeValues(values map[string]json.RawMessage) (map[string]Value, error) {
	decoded := make(map[string]Value, len(values))
	for key, data := range values {
		value, err := decodeValue(data)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", key, err)
		}
		decoded[key] = value
	}
	return decoded, nil
}
