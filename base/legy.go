package base

import (
	"fmt"

	"github.com/phongsathornpt/line-go/internal/protocol/legy"
)

func (c *BaseClient) shouldUseLegy(path, accessToken string) bool {
	switch c.legy.Encryption {
	case LegyEncryptionDisabled:
		return false
	case LegyEncryptionEnabled:
		return accessToken != ""
	default:
		return legy.IsTalkPath(path) && legy.ShouldEncryptAccess(accessToken)
	}
}

func (c *BaseClient) getLegyTransport() (*legy.Transport, error) {
	c.legyMu.Lock()
	defer c.legyMu.Unlock()
	if c.legyWire != nil {
		return c.legyWire, nil
	}
	if c.legyErr != nil {
		return nil, c.legyErr
	}
	transport, err := legy.NewTransport(c.legy.Endpoint)
	if err != nil {
		c.legyErr = err
		return nil, fmt.Errorf("initialize LEGY transport: %w", err)
	}
	c.legyWire = transport
	return c.legyWire, nil
}
