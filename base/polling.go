package base

import (
	"context"
	"fmt"
	"time"

	"github.com/phongsathornpt/line-go/types"
)

// TalkSyncCursor tracks the three revisions used by LINE Talk synchronization.
type TalkSyncCursor struct {
	Revision           int64
	GlobalRevision     int64
	IndividualRevision int64
}

// PollingOptions configures long-poll Talk event delivery. Zero values use
// LINEJS defaults: 100 operations per sync request and a 100 ms poll interval.
type PollingOptions struct {
	Limit    int32
	Interval time.Duration
	Timeout  time.Duration
	Cursor   *TalkSyncCursor
}

// TalkPollEvent carries either one operation or a sync error. Sync errors are
// reported and polling continues until the context is canceled.
type TalkPollEvent struct {
	Operation *types.Operation
	Err       error
}

// SquarePollingOptions configures polling for the signed-in user's Square
// events. Zero values use LINEJS defaults: 100 events per request and a 1 s
// poll interval.
type SquarePollingOptions struct {
	Limit             int32
	Interval          time.Duration
	SyncToken         string
	ContinuationToken string
}

// SquarePollEvent carries either one Square event or a fetch error. Fetch
// errors are reported and polling continues until the context is canceled.
type SquarePollEvent struct {
	Event *types.SquareEvent
	Err   error
}

// Polling manages long-poll event streams for a BaseClient.
type Polling struct {
	client *BaseClient
}

// ListenTalkEvents continuously polls Talk sync and emits operations. Cancel
// ctx to stop polling and close the returned channel. When no initial cursor is
// provided, polling starts at revision zero, matching LINEJS.
func (p *Polling) ListenTalkEvents(ctx context.Context, options PollingOptions) <-chan TalkPollEvent {
	events := make(chan TalkPollEvent)
	go func() {
		defer close(events)
		if p == nil || p.client == nil {
			publishTalkPollEvent(ctx, events, TalkPollEvent{Err: ErrClientClosed})
			return
		}

		limit := options.Limit
		if limit == 0 {
			limit = 100
		}
		interval := options.Interval
		if interval <= 0 {
			interval = 100 * time.Millisecond
		}
		var cursor TalkSyncCursor
		if options.Cursor != nil {
			cursor = *options.Cursor
		}

		for ctx.Err() == nil {
			response, err := p.client.Talk().Sync(ctx, SyncOptions{
				Limit:              limit,
				Revision:           cursor.Revision,
				GlobalRevision:     cursor.GlobalRevision,
				IndividualRevision: cursor.IndividualRevision,
				Timeout:            options.Timeout,
			})
			if err != nil {
				if !publishTalkPollEvent(ctx, events, TalkPollEvent{Err: err}) {
					return
				}
			} else if response != nil {
				advanceTalkCursor(&cursor, response)
				if response.OperationResponse != nil {
					for _, operation := range response.OperationResponse.Operations {
						if operation == nil {
							continue
						}
						if operation.Revision != nil {
							cursor.Revision = *operation.Revision
						}
						if !publishTalkPollEvent(ctx, events, TalkPollEvent{Operation: operation}) {
							return
						}
					}
				}
			}

			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
		}
	}()
	return events
}

// ListenSquareEvents continuously polls Square events and emits each event.
// Cancel ctx to stop polling and close the returned channel.
func (p *Polling) ListenSquareEvents(ctx context.Context, options SquarePollingOptions) <-chan SquarePollEvent {
	events := make(chan SquarePollEvent)
	go func() {
		defer close(events)
		if p == nil || p.client == nil {
			publishSquarePollEvent(ctx, events, SquarePollEvent{Err: fmt.Errorf("line square polling: client is nil")})
			return
		}

		limit := options.Limit
		if limit == 0 {
			limit = 100
		}
		interval := options.Interval
		if interval <= 0 {
			interval = time.Second
		}
		syncToken := options.SyncToken
		continuationToken := options.ContinuationToken

		for ctx.Err() == nil {
			result, err := p.client.Square().FetchMyEvents(ctx, types.SquareServiceFetchMyEventsArgs{
				Request: &types.FetchMyEventsRequest{
					SyncToken:         optionalPollingString(syncToken),
					Limit:             int32Pointer(limit),
					ContinuationToken: optionalPollingString(continuationToken),
				},
			})
			if err == nil && result != nil && result.E != nil {
				err = squarePollingServiceError(result.E)
			}
			if err != nil {
				if !publishSquarePollEvent(ctx, events, SquarePollEvent{Err: err}) {
					return
				}
			} else if result != nil && result.Success != nil {
				syncToken = pollingString(result.Success.SyncToken)
				continuationToken = pollingString(result.Success.ContinuationToken)
				for _, event := range result.Success.Events {
					if event == nil {
						continue
					}
					if !publishSquarePollEvent(ctx, events, SquarePollEvent{Event: event}) {
						return
					}
				}
			}

			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return events
}

func advanceTalkCursor(cursor *TalkSyncCursor, response *types.SyncResponse) {
	if response.FullSyncResponse != nil && response.FullSyncResponse.NextRevision != nil {
		cursor.Revision = *response.FullSyncResponse.NextRevision
	}
	if response.OperationResponse == nil {
		return
	}
	if response.OperationResponse.GlobalEvents != nil && response.OperationResponse.GlobalEvents.LastRevision != nil {
		cursor.GlobalRevision = *response.OperationResponse.GlobalEvents.LastRevision
	}
	if response.OperationResponse.IndividualEvents != nil && response.OperationResponse.IndividualEvents.LastRevision != nil {
		cursor.IndividualRevision = *response.OperationResponse.IndividualEvents.LastRevision
	}
}

func publishTalkPollEvent(ctx context.Context, events chan<- TalkPollEvent, event TalkPollEvent) bool {
	select {
	case events <- event:
		return true
	case <-ctx.Done():
		return false
	}
}

func publishSquarePollEvent(ctx context.Context, events chan<- SquarePollEvent, event SquarePollEvent) bool {
	select {
	case events <- event:
		return true
	case <-ctx.Done():
		return false
	}
}

func optionalPollingString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func pollingString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func squarePollingServiceError(remote *types.SquareException) error {
	code := int32(0)
	if remote.ErrorCode != nil {
		code = int32(*remote.ErrorCode)
	}
	reason := ""
	if remote.Reason != nil {
		reason = *remote.Reason
	}
	if reason != "" {
		return fmt.Errorf("line square fetchMyEvents: %s (code %d)", reason, code)
	}
	return fmt.Errorf("line square fetchMyEvents: service exception %d", code)
}
