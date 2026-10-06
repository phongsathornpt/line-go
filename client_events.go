package line

import (
	"context"
	"fmt"

	"github.com/phongsathornpt/line-go/base"
	"github.com/phongsathornpt/line-go/types"
)

// ClientEvent is a Talk operation, Square event, or error received while
// listening. Message is set for Talk message operations and contains decrypted
// E2EE content when the client has the required keys.
type ClientEvent struct {
	Operation     *types.Operation
	Message       *Message
	SquareEvent   *types.SquareEvent
	SquareMessage *types.SquareMessage
	Err           error
}

// ListenSquareEvents polls the user's Square event stream. The stream closes
// when ctx is canceled. Square message data remains available in the raw event
// and is also exposed as SquareMessage for notification-message events.
func (c *Client) ListenSquareEvents(ctx context.Context, options base.SquarePollingOptions) <-chan ClientEvent {
	events := make(chan ClientEvent)
	if c == nil || c.base == nil {
		go func() {
			defer close(events)
			publishClientEvent(ctx, events, ClientEvent{Err: fmt.Errorf("line client: cannot listen without a client")})
		}()
		return events
	}

	go func() {
		defer close(events)
		for polled := range c.base.Polling().ListenSquareEvents(ctx, options) {
			current := ClientEvent{SquareEvent: polled.Event, Err: polled.Err}
			if polled.Event != nil && polled.Event.Payload != nil && polled.Event.Payload.NotificationMessage != nil {
				current.SquareMessage = polled.Event.Payload.NotificationMessage.SquareMessage
			}
			if !publishClientEvent(ctx, events, current) {
				return
			}
		}
	}()
	return events
}

// ListenTalkEvents polls Talk sync and returns operations as they arrive. The
// stream closes when ctx is canceled. LINEJS-compatible sync errors are
// included in the stream and polling continues.
func (c *Client) ListenTalkEvents(ctx context.Context, options base.PollingOptions) <-chan ClientEvent {
	events := make(chan ClientEvent)
	if c == nil || c.base == nil {
		go func() {
			defer close(events)
			publishClientEvent(ctx, events, ClientEvent{Err: fmt.Errorf("line client: cannot listen without a client")})
		}()
		return events
	}

	go func() {
		defer close(events)
		for polled := range c.base.Polling().ListenTalkEvents(ctx, options) {
			current := ClientEvent{Operation: polled.Operation, Err: polled.Err}
			if polled.Operation != nil && isMessageOperation(polled.Operation.Type) && polled.Operation.Message != nil {
				message := cloneMessageDTO(polled.Operation.Message)
				if message.ContentMetadata["e2eeVersion"] != "" {
					if c.profile == nil {
						current.Err = fmt.Errorf("line client: decrypt event requires a signed-in profile")
					} else if err := c.base.E2EE().DecryptMessage(ctx, c.profile.MID, message); err != nil {
						current.Err = fmt.Errorf("line client: decrypt event message: %w", err)
					}
				}
				if current.Err == nil {
					current.Message = messageFromDTO(message)
				}
			}
			if !publishClientEvent(ctx, events, current) {
				return
			}
		}
	}()
	return events
}

// ListenPushEvents delivers Talk and Square events over LINE's persistent
// HTTP/2 push transport. The stream reconnects after transport failures and
// closes when ctx is canceled.
func (c *Client) ListenPushEvents(ctx context.Context, options base.PushOptions) <-chan ClientEvent {
	events := make(chan ClientEvent)
	if c == nil || c.base == nil {
		go func() {
			defer close(events)
			publishClientEvent(ctx, events, ClientEvent{Err: fmt.Errorf("line client: cannot listen without a client")})
		}()
		return events
	}

	go func() {
		defer close(events)
		for pushed := range c.base.Push().Listen(ctx, options) {
			current := ClientEvent{
				Operation:   pushed.Operation,
				SquareEvent: pushed.SquareEvent,
				Err:         pushed.Err,
			}
			if pushed.Operation != nil && isMessageOperation(pushed.Operation.Type) && pushed.Operation.Message != nil {
				message := cloneMessageDTO(pushed.Operation.Message)
				if message.ContentMetadata["e2eeVersion"] != "" {
					if c.profile == nil {
						current.Err = fmt.Errorf("line client: decrypt event requires a signed-in profile")
					} else if err := c.base.E2EE().DecryptMessage(ctx, c.profile.MID, message); err != nil {
						current.Err = fmt.Errorf("line client: decrypt event message: %w", err)
					}
				}
				if current.Err == nil {
					current.Message = messageFromDTO(message)
				}
			}
			if pushed.SquareEvent != nil && pushed.SquareEvent.Payload != nil && pushed.SquareEvent.Payload.NotificationMessage != nil {
				current.SquareMessage = pushed.SquareEvent.Payload.NotificationMessage.SquareMessage
			}
			if !publishClientEvent(ctx, events, current) {
				return
			}
		}
	}()
	return events
}

func isMessageOperation(operationType *types.OpType) bool {
	if operationType == nil {
		return false
	}
	return *operationType == types.OpTypeSENDMESSAGE || *operationType == types.OpTypeRECEIVEMESSAGE
}

func cloneMessageDTO(source *types.Message) *types.Message {
	clone := *source
	clone.ContentMetadata = cloneStringMap(source.ContentMetadata)
	clone.Chunks = cloneByteSlices(source.Chunks)
	return &clone
}

func publishClientEvent(ctx context.Context, events chan<- ClientEvent, event ClientEvent) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case events <- event:
		return true
	case <-ctx.Done():
		return false
	}
}
