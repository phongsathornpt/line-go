package base

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// GetReqseq returns and persists the next sequence number for name. An empty
// name selects LINEJS's default "talk" counter. Allocation is serialized per
// BaseClient so concurrent service calls cannot reuse a sequence number.
func (c *BaseClient) GetReqseq(ctx context.Context, name string) (int32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if name == "" {
		name = "talk"
	}

	c.reqseqMu.Lock()
	defer c.reqseqMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if c.reqseqs == nil {
		if err := c.loadReqseqs(ctx); err != nil {
			return 0, err
		}
	}

	sequence := c.reqseqs[name]
	if sequence > math.MaxInt32 {
		return 0, fmt.Errorf("line request sequence %q: value %d exceeds i32", name, sequence)
	}
	c.reqseqs[name] = sequence + 1
	encoded, err := json.Marshal(c.reqseqs)
	if err != nil {
		return 0, fmt.Errorf("line request sequence: encode counters: %w", err)
	}
	if err := c.storage.Set(ctx, "reqseq", string(encoded)); err != nil {
		return 0, fmt.Errorf("line request sequence: persist counters: %w", err)
	}
	return int32(sequence), nil
}

func (c *BaseClient) loadReqseqs(ctx context.Context) error {
	value, found, err := c.storage.Get(ctx, "reqseq")
	if err != nil {
		return fmt.Errorf("line request sequence: load counters: %w", err)
	}
	if !found || value == nil {
		c.reqseqs = make(map[string]int64)
		return nil
	}
	encoded, ok := value.(string)
	if !ok {
		return fmt.Errorf("line request sequence: stored counters have type %T, want string", value)
	}
	if strings.TrimSpace(encoded) == "" {
		c.reqseqs = make(map[string]int64)
		return nil
	}
	var counters map[string]int64
	if err := json.Unmarshal([]byte(encoded), &counters); err != nil {
		return fmt.Errorf("line request sequence: decode counters: %w", err)
	}
	if counters == nil {
		counters = make(map[string]int64)
	}
	c.reqseqs = counters
	return nil
}
