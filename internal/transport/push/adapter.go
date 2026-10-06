package push

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/phongsathornpt/line-go/base"
)

// Connector adapts the internal HTTP/2 push transport to base's push port.
type Connector struct {
	client  HTTPDoer
	timeout time.Duration
}

// NewConnector creates a push adapter using the supplied HTTP transport.
func NewConnector(client HTTPDoer, connectTimeout time.Duration) *Connector {
	return &Connector{client: client, timeout: connectTimeout}
}

// Connect opens one HTTP/2 stream and returns its base-facing connection.
func (c *Connector) Connect(ctx context.Context, endpoint string, headers http.Header, services []uint8) (base.PushConnection, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("line push: connector has no HTTP transport")
	}
	conn, err := Connect(ctx, c.client, endpoint, headers, services, c.timeout)
	if err != nil {
		return nil, err
	}
	return &connectionAdapter{conn: conn}, nil
}

type connectionAdapter struct {
	conn *Conn
}

func (c *connectionAdapter) ReadFrame(ctx context.Context) (base.PushFrame, error) {
	if ctx == nil {
		return base.PushFrame{}, fmt.Errorf("line push: read context is nil")
	}
	select {
	case frame, ok := <-c.conn.Frames():
		if !ok {
			if err := c.conn.Err(); err != nil {
				return base.PushFrame{}, err
			}
			return base.PushFrame{}, io.EOF
		}
		return base.PushFrame{Type: uint8(frame.Type), Payload: frame.Payload}, nil
	case <-ctx.Done():
		return base.PushFrame{}, ctx.Err()
	}
}

func (c *connectionAdapter) WriteFrame(ctx context.Context, frame base.PushFrame) error {
	return c.conn.WriteFrame(ctx, Frame{Type: FrameType(frame.Type), Payload: frame.Payload})
}

func (c *connectionAdapter) Close() error {
	return c.conn.Close()
}
