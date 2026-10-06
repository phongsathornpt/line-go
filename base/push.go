package base

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/phongsathornpt/line-go/thrift"
	"github.com/phongsathornpt/line-go/types"
)

// ErrPushUnavailable reports that no push transport adapter was configured.
var ErrPushUnavailable = errors.New("line push transport is unavailable")

// PushFrame is one decoded packet from LINE's persistent push connection.
type PushFrame struct {
	Type    uint8
	Payload []byte
}

// PushConnection is the narrow bidirectional stream used by LINE push.
type PushConnection interface {
	ReadFrame(context.Context) (PushFrame, error)
	WriteFrame(context.Context, PushFrame) error
	Close() error
}

// PushConnector opens a persistent push connection for the selected services.
type PushConnector interface {
	Connect(context.Context, string, http.Header, []uint8) (PushConnection, error)
}

// OpenPushConnection opens the framed LINE push transport. The returned stream
// belongs to the caller and must be closed when event delivery ends.
func (c *BaseClient) OpenPushConnection(ctx context.Context, services []uint8) (PushConnection, error) {
	if c == nil {
		return nil, fmt.Errorf("line push: client is nil")
	}
	if c.push == nil {
		return nil, ErrPushUnavailable
	}
	if ctx == nil {
		return nil, fmt.Errorf("line push: context is nil")
	}
	if c.isClosed() {
		return nil, ErrClientClosed
	}
	return c.push.Connect(ctx, c.endpoint.String(), c.Headers(http.MethodPost), services)
}

// PushOptions controls a persistent push event stream. Zero values select
// LINEJS's default services, event buffer, and initial cursors.
type PushOptions struct {
	Services        []uint8
	Buffer          int
	TalkCursor      *TalkSyncCursor
	SquareSyncToken string
}

// PushEvent carries a Talk operation, a Square event, or a recoverable error.
type PushEvent struct {
	Operation   *types.Operation
	SquareEvent *types.SquareEvent
	Err         error
}

// PushService manages persistent event delivery for a BaseClient.
type PushService struct {
	client *BaseClient
}

type pushSessionState struct {
	talkCursor      TalkSyncCursor
	squareSyncToken string
	squareSubID     int64
	squareContinue  string
}

type pushRequest struct {
	service uint8
}

type pushSessionOptions struct {
	services []uint8
	state    *pushSessionState
	events   chan<- PushEvent
}

type pushSession struct {
	service       *PushService
	ctx           context.Context
	conn          PushConnection
	state         *pushSessionState
	events        chan<- PushEvent
	requests      map[uint16]pushRequest
	fragments     map[uint16][]byte
	fragmentBytes int64
	nextRequestID uint16
}

// Listen opens a persistent LINE push stream, dispatches Talk and Square
// events, and reconnects with bounded backoff until ctx is canceled.
func (p *PushService) Listen(ctx context.Context, options PushOptions) <-chan PushEvent {
	buffer := options.Buffer
	if buffer == 0 {
		buffer = 200
	}
	invalidBuffer := buffer < 0 || buffer > 10000
	if invalidBuffer {
		buffer = 1
	}
	events := make(chan PushEvent, buffer)
	go func() {
		defer close(events)
		if p == nil || p.client == nil {
			publishPushEvent(ctx, events, PushEvent{Err: fmt.Errorf("line push: client is nil")})
			return
		}
		if ctx == nil {
			publishPushEvent(context.Background(), events, PushEvent{Err: fmt.Errorf("line push: context is nil")})
			return
		}
		if invalidBuffer {
			publishPushEvent(ctx, events, PushEvent{Err: fmt.Errorf("line push: event buffer must be between 0 and 10000")})
			return
		}

		state := pushSessionState{squareSyncToken: options.SquareSyncToken}
		if options.TalkCursor != nil {
			state.talkCursor = *options.TalkCursor
		}
		services := options.Services
		if len(services) == 0 {
			services = []uint8{3, 5}
		}
		services = uniquePushServices(services)
		for _, service := range services {
			if service == 0 || service > 32 {
				publishPushEvent(ctx, events, PushEvent{Err: fmt.Errorf("line push: service ID %d is outside the range 1..32", service)})
				return
			}
		}
		if p.client.push == nil {
			publishPushEvent(ctx, events, PushEvent{Err: ErrPushUnavailable})
			return
		}
		backoff := 500 * time.Millisecond
		for ctx.Err() == nil {
			startedAt := time.Now()
			conn, err := p.client.OpenPushConnection(ctx, services)
			if err == nil {
				err = p.runPushConnection(ctx, conn, pushSessionOptions{
					services: services,
					state:    &state,
					events:   events,
				})
				_ = conn.Close()
			}
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				err = io.EOF
			}
			if !publishPushEvent(ctx, events, PushEvent{Err: fmt.Errorf("line push: connection ended: %w", err)}) {
				return
			}
			if errors.Is(err, ErrClientClosed) || errors.Is(err, ErrPushUnavailable) {
				return
			}
			if time.Since(startedAt) > time.Minute {
				backoff = 500 * time.Millisecond
			}
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if backoff < 30*time.Second {
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
		}
	}()
	return events
}

func (p *PushService) runPushConnection(ctx context.Context, conn PushConnection, options pushSessionOptions) error {
	session := &pushSession{
		service:   p,
		ctx:       ctx,
		conn:      conn,
		state:     options.state,
		events:    options.events,
		requests:  make(map[uint16]pushRequest),
		fragments: make(map[uint16][]byte),
	}
	return session.run(options.services)
}

func (s *pushSession) run(services []uint8) error {
	if err := s.conn.WriteFrame(s.ctx, PushFrame{Type: 0, Payload: []byte{0, 0, 30}}); err != nil {
		return fmt.Errorf("send status frame: %w", err)
	}
	for _, service := range services {
		switch service {
		case 3:
			if err := s.sendSquareSignOn(); err != nil {
				return err
			}
		case 5, 8:
			if err := s.sendTalkSignOn(service); err != nil {
				return err
			}
		}
	}
	return s.readFrames()
}

func (s *pushSession) readFrames() error {
	for {
		frame, err := s.conn.ReadFrame(s.ctx)
		if err != nil {
			return err
		}
		switch frame.Type {
		case 0:
			continue
		case 1:
			pingType, pingID, err := decodePushPing(frame.Payload)
			if err != nil {
				return err
			}
			if pingType != 2 {
				continue
			}
			if err := s.conn.WriteFrame(s.ctx, PushFrame{Type: 1, Payload: pushPingAck(pingID)}); err != nil {
				return fmt.Errorf("ack ping: %w", err)
			}
			if pingID%3 == 0 {
				s.service.noopAndRenewOnTokenChange(s.ctx, s.conn)
			}
		case 3:
			requestID, fin, payload, err := decodePushSignOnResponse(frame.Payload)
			if err != nil {
				return err
			}
			request, ok := s.requests[requestID]
			if !ok {
				continue
			}
			previous := s.fragments[requestID]
			combined := make([]byte, len(previous)+len(payload))
			copy(combined, previous)
			copy(combined[len(previous):], payload)
			combinedBytes := s.fragmentBytes - int64(len(previous)) + int64(len(combined))
			if combinedBytes > s.service.client.config.MaxResponseBytes {
				return &ResponseTooLargeError{Limit: s.service.client.config.MaxResponseBytes}
			}
			if !fin {
				s.fragments[requestID] = combined
				s.fragmentBytes = combinedBytes
				continue
			}
			s.fragmentBytes -= int64(len(previous))
			delete(s.fragments, requestID)
			delete(s.requests, requestID)
			if err := s.handleSignOn(request, combined); err != nil {
				return err
			}
		case 4:
			pushType, service, pushID, payload, err := decodePushNotification(frame.Payload)
			if err != nil {
				return err
			}
			if pushType == 2 {
				if err := s.conn.WriteFrame(s.ctx, PushFrame{Type: 4, Payload: pushAckPayload(service, pushID)}); err != nil {
					return fmt.Errorf("ack push event: %w", err)
				}
			} else if pushType != 0 {
				return fmt.Errorf("line push: unsupported push type %d", pushType)
			}
			if service == 3 {
				if err := s.handleSquarePush(payload); err != nil && !publishPushEvent(s.ctx, s.events, PushEvent{Err: err}) {
					return s.ctx.Err()
				}
			}
		case 5:
			return io.EOF
		default:
			return fmt.Errorf("line push: unsupported frame type %d", frame.Type)
		}
	}
}

func (s *pushSession) handleSignOn(request pushRequest, data []byte) error {
	switch request.service {
	case 3:
		message, err := thrift.UnmarshalMessage(thrift.ProtocolCompact, data)
		if err != nil {
			return fmt.Errorf("decode Square sign-on response: %w", err)
		}
		result := new(types.SquareServiceFetchMyEventsResult)
		if err := thrift.UnmarshalStructValue(message.Args, result); err != nil {
			return fmt.Errorf("decode Square result: %w", err)
		}
		if result.E != nil {
			return squarePollingServiceError(result.E)
		}
		if result.Success == nil {
			return fmt.Errorf("line push: Square sign-on response has no success payload")
		}
		s.state.squareSyncToken = pollingString(result.Success.SyncToken)
		s.state.squareContinue = pollingString(result.Success.ContinuationToken)
		if result.Success.Subscription != nil && result.Success.Subscription.SubscriptionId != nil {
			s.state.squareSubID = *result.Success.Subscription.SubscriptionId
		}
		for _, event := range result.Success.Events {
			if event != nil && !publishPushEvent(s.ctx, s.events, PushEvent{SquareEvent: event}) {
				return s.ctx.Err()
			}
		}
		return nil
	case 5, 8:
		fields, err := thrift.UnmarshalTMoreCompactStruct(data)
		if err != nil {
			message, compactErr := thrift.UnmarshalMessage(thrift.ProtocolCompact, data)
			if compactErr != nil {
				return fmt.Errorf("decode Talk TMoreCompact response: %w (compact fallback: %v)", err, compactErr)
			}
			fields = message.Args
		}
		result := new(types.SyncResult)
		if err := thrift.UnmarshalStructValue(fields, result); err != nil {
			return fmt.Errorf("decode Talk sync result: %w", err)
		}
		if result.E != nil {
			if !publishPushEvent(s.ctx, s.events, PushEvent{Err: talkServiceError("sync", result.E)}) {
				return s.ctx.Err()
			}
		} else if result.Success == nil {
			if !publishPushEvent(s.ctx, s.events, PushEvent{Err: ErrMissingServiceSuccess}) {
				return s.ctx.Err()
			}
		} else {
			advanceTalkCursor(&s.state.talkCursor, result.Success)
			if result.Success.OperationResponse != nil {
				for _, operation := range result.Success.OperationResponse.Operations {
					if operation == nil {
						continue
					}
					if operation.Revision != nil {
						s.state.talkCursor.Revision = *operation.Revision
					}
					if !publishPushEvent(s.ctx, s.events, PushEvent{Operation: operation}) {
						return s.ctx.Err()
					}
				}
			}
		}
		return s.sendTalkSignOn(request.service)
	default:
		return fmt.Errorf("line push: unsupported sign-on service %d", request.service)
	}
}

func (s *pushSession) handleSquarePush(payload []byte) error {
	fields, err := thrift.UnmarshalCompactStruct(payload)
	if err != nil {
		return fmt.Errorf("line push: decode Square notification: %w", err)
	}
	var notification struct {
		SubscriptionID *int64 `thrift:"1,10"`
	}
	if err := thrift.UnmarshalStructValue(fields, &notification); err != nil {
		return fmt.Errorf("line push: decode Square subscription ID: %w", err)
	}
	if notification.SubscriptionID != nil {
		s.state.squareSubID = *notification.SubscriptionID
	}
	result, err := s.service.client.Square().FetchMyEvents(s.ctx, types.SquareServiceFetchMyEventsArgs{
		Request: &types.FetchMyEventsRequest{
			SubscriptionId:    optionalPushInt64(s.state.squareSubID),
			SyncToken:         optionalPollingString(s.state.squareSyncToken),
			Limit:             int32Pointer(100),
			ContinuationToken: optionalPollingString(s.state.squareContinue),
		},
	})
	if err != nil {
		return fmt.Errorf("line push: fetch Square events: %w", err)
	}
	if result.E != nil {
		return squarePollingServiceError(result.E)
	}
	if result.Success == nil {
		return fmt.Errorf("line push: Square fetch response has no success payload")
	}
	s.state.squareSyncToken = pollingString(result.Success.SyncToken)
	s.state.squareContinue = pollingString(result.Success.ContinuationToken)
	if result.Success.Subscription != nil && result.Success.Subscription.SubscriptionId != nil {
		s.state.squareSubID = *result.Success.Subscription.SubscriptionId
	}
	for _, event := range result.Success.Events {
		if event != nil && !publishPushEvent(s.ctx, s.events, PushEvent{SquareEvent: event}) {
			return s.ctx.Err()
		}
	}
	return nil
}

func (s *pushSession) sendSquareSignOn() error {
	s.state.squareSubID = time.Now().UnixMilli()
	args := types.SquareServiceFetchMyEventsArgs{Request: &types.FetchMyEventsRequest{
		SubscriptionId:    optionalPushInt64(s.state.squareSubID),
		SyncToken:         optionalPollingString(s.state.squareSyncToken),
		Limit:             int32Pointer(100),
		ContinuationToken: optionalPollingString(s.state.squareContinue),
	}}
	return s.sendSignOn(3, "fetchMyEvents", args)
}

func (s *pushSession) sendTalkSignOn(service uint8) error {
	args := types.SyncArgs{Request: &types.SyncRequest{
		LastRevision:           int64Pointer(s.state.talkCursor.Revision),
		Count:                  int32Pointer(100),
		LastGlobalRevision:     int64Pointer(s.state.talkCursor.GlobalRevision),
		LastIndividualRevision: int64Pointer(s.state.talkCursor.IndividualRevision),
	}}
	return s.sendSignOn(service, "sync", args)
}

func (s *pushSession) sendSignOn(service uint8, method string, args any) error {
	fields, err := thrift.MarshalArgs(args)
	if err != nil {
		return fmt.Errorf("line push: encode %s args: %w", method, err)
	}
	request, err := thrift.MarshalRequest(thrift.ProtocolCompact, method, fields)
	if err != nil {
		return fmt.Errorf("line push: encode %s request: %w", method, err)
	}
	if len(request) > 65535-6 {
		return fmt.Errorf("line push: %s request is too large", method)
	}
	requestID := nextPushRequestID(&s.nextRequestID, s.requests)
	if requestID == 0 {
		return fmt.Errorf("line push: no free sign-on request ID")
	}
	payload := make([]byte, 6+len(request))
	binary.BigEndian.PutUint16(payload[:2], requestID)
	payload[2] = service
	payload[3] = 0
	binary.BigEndian.PutUint16(payload[4:6], uint16(len(request)))
	copy(payload[6:], request)
	s.requests[requestID] = pushRequest{service: service}
	if err := s.conn.WriteFrame(s.ctx, PushFrame{Type: 2, Payload: payload}); err != nil {
		delete(s.requests, requestID)
		return fmt.Errorf("line push: send %s sign-on: %w", method, err)
	}
	return nil
}

func nextPushRequestID(next *uint16, requests map[uint16]pushRequest) uint16 {
	for range 32767 {
		*next = *next%32767 + 1
		if _, exists := requests[*next]; !exists {
			return *next
		}
	}
	return 0
}

func decodePushPing(payload []byte) (uint8, uint16, error) {
	if len(payload) != 3 {
		return 0, 0, fmt.Errorf("line push: malformed ping frame")
	}
	return payload[0], binary.BigEndian.Uint16(payload[1:]), nil
}

func decodePushSignOnResponse(payload []byte) (uint16, bool, []byte, error) {
	if len(payload) < 2 {
		return 0, false, nil, fmt.Errorf("line push: malformed sign-on response")
	}
	encodedID := binary.BigEndian.Uint16(payload[:2])
	return encodedID & 0x7fff, encodedID&0x8000 != 0, payload[2:], nil
}

func decodePushNotification(payload []byte) (uint8, uint8, uint32, []byte, error) {
	if len(payload) < 6 {
		return 0, 0, 0, nil, fmt.Errorf("line push: malformed push notification")
	}
	return payload[0], payload[1], binary.BigEndian.Uint32(payload[2:6]), payload[6:], nil
}

func pushPingAck(id uint16) []byte {
	ack := make([]byte, 3)
	ack[0] = 1
	binary.BigEndian.PutUint16(ack[1:], id)
	return ack
}

func pushAckPayload(service uint8, id uint32) []byte {
	ack := make([]byte, 6)
	ack[0] = 1
	ack[1] = service
	binary.BigEndian.PutUint32(ack[2:], id)
	return ack
}

func uniquePushServices(services []uint8) []uint8 {
	unique := make([]uint8, 0, len(services))
	seen := make(map[uint8]struct{}, len(services))
	for _, service := range services {
		if _, exists := seen[service]; exists {
			continue
		}
		seen[service] = struct{}{}
		unique = append(unique, service)
	}
	return unique
}

func optionalPushInt64(value int64) *int64 {
	if value == 0 {
		return nil
	}
	return &value
}

func publishPushEvent(ctx context.Context, events chan<- PushEvent, event PushEvent) bool {
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

func (p *PushService) noopAndRenewOnTokenChange(ctx context.Context, conn PushConnection) {
	oldToken := p.client.AuthToken()
	go func() {
		if _, err := p.client.Talk().Noop(ctx, types.NoopArgs{}); err == nil && oldToken != p.client.AuthToken() {
			_ = conn.Close()
		}
	}()
}
