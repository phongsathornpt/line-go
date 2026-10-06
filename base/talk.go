package base

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/phongsathornpt/line-go/types"
)

var ErrMissingServiceSuccess = errors.New("line service response has neither success nor exception")

// ServiceError is an exception returned in a LINE service result envelope.
type ServiceError struct {
	Method     string
	Code       int32
	Reason     string
	Parameters map[string]string
}

func (e *ServiceError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("line %s: %s (code %d)", e.Method, e.Reason, e.Code)
	}
	return fmt.Sprintf("line %s: service exception %d", e.Method, e.Code)
}

// TalkService exposes direct LINE Talk service operations.
type TalkService struct {
	client *BaseClient
	rpc    *RPCService
}

// SyncOptions controls operation synchronization. Zero revisions select the
// initial sync position; a zero limit selects LINEJS's default of 100.
type SyncOptions struct {
	Limit              int32
	Revision           int64
	GlobalRevision     int64
	IndividualRevision int64
	Timeout            time.Duration
}

// Sync retrieves LINE operations from the requested revision.
func (s *TalkService) Sync(ctx context.Context, options SyncOptions) (*types.SyncResponse, error) {
	limit := options.Limit
	if limit == 0 {
		limit = 100
	}
	request := types.SyncRequest{
		LastRevision:           int64Pointer(options.Revision),
		Count:                  int32Pointer(limit),
		LastGlobalRevision:     int64Pointer(options.GlobalRevision),
		LastIndividualRevision: int64Pointer(options.IndividualRevision),
	}
	result := new(types.SyncResult)
	if err := s.request(ctx, "sync", options.Timeout, true,
		types.SyncArgs{Request: &request}, result); err != nil {
		return nil, err
	}
	if result.E != nil {
		return nil, talkServiceError("sync", result.E)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line sync: %w", ErrMissingServiceSuccess)
	}
	return result.Success, nil
}

// SendMessageOptions describes a plain Talk message. Chunks can carry caller-
// prepared message payloads; encryption and E2EE negotiation are separate
// capabilities and are not performed by this method.
type SendMessageOptions struct {
	From             string
	To               string
	E2EE             bool
	Text             *string
	ContentType      types.ContentType
	ContentMetadata  map[string]string
	RelatedMessageID *string
	Location         *types.Location
	Chunks           [][]byte
}

// SendMessage sends a Talk message using the persisted Talk request sequence.
func (s *TalkService) SendMessage(ctx context.Context, options SendMessageOptions) (*types.Message, error) {
	if options.To == "" {
		return nil, fmt.Errorf("line sendMessage: recipient is empty")
	}
	text := options.Text
	location := options.Location
	chunks := options.Chunks
	metadata := cloneTalkMetadata(options.ContentMetadata)
	if metadata == nil {
		metadata = make(map[string]string)
	}
	if options.E2EE && chunks == nil && (text != nil || location != nil) {
		var data any
		if text != nil {
			data = *text
		} else {
			data = location
		}
		encrypted, err := s.client.E2EE().EncryptMessage(
			ctx,
			options.From,
			options.To,
			data,
			options.ContentType,
			metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("line sendMessage: encrypt E2EE payload: %w", err)
		}
		chunks = encrypted.Chunks
		metadata = encrypted.ContentMetadata
		text = nil
		location = nil
	}
	sequence, err := s.client.GetReqseq(ctx, "talk")
	if err != nil {
		return nil, fmt.Errorf("line sendMessage: allocate request sequence: %w", err)
	}
	message := &types.Message{
		To:               stringPointer(options.To),
		CreatedTime:      int64Pointer(0),
		DeliveredTime:    int64Pointer(0),
		HasContent:       boolPointer(false),
		ContentType:      contentTypePointer(options.ContentType),
		ContentMetadata:  metadata,
		SessionId:        int8Pointer(0),
		Text:             text,
		Location:         location,
		Chunks:           chunks,
		RelatedMessageId: options.RelatedMessageID,
	}
	if options.RelatedMessageID != nil {
		message.MessageRelationType = messageRelationReplyPointer()
		message.RelatedMessageServiceCode = messageServiceTalkPointer()
	}

	result := new(types.SendMessageResult)
	args := types.SendMessageArgs{Seq: int32Pointer(sequence), Message: message}
	if err := s.request(ctx, "sendMessage", 0, false, args, result); err != nil {
		return nil, err
	}
	if result.E != nil {
		return nil, talkServiceError("sendMessage", result.E)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line sendMessage: %w", ErrMissingServiceSuccess)
	}
	return result.Success, nil
}

// FetchOperations retrieves device operations after offsetFrom.
func (s *TalkService) FetchOperations(ctx context.Context, request types.FetchOperationsRequest) (*types.FetchOperationsResponse, error) {
	result := new(types.FetchOperationsResult)
	args := types.FetchOperationsArgs{Request: &request}
	if err := s.request(ctx, "fetchOperations", 0, false, args, result); err != nil {
		return nil, err
	}
	if result.E != nil {
		reason := ""
		if result.E.Reason != nil {
			reason = *result.E.Reason
		}
		code := int32(0)
		if result.E.Code != nil {
			code = int32(*result.E.Code)
		}
		return nil, &ServiceError{Method: "fetchOperations", Code: code, Reason: reason}
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line fetchOperations: %w", ErrMissingServiceSuccess)
	}
	return result.Success, nil
}

// GetContactsV2 retrieves contacts through the older Talk V2 endpoint. LINEJS
// uses it as a compatibility fallback when Relation.getContactsV3 is not
// available for the current account or device profile.
func (s *TalkService) GetContactsV2(ctx context.Context, mids []string) (*types.GetContactsV2Response, error) {
	if s == nil || s.client == nil || s.rpc == nil {
		return nil, fmt.Errorf("line getContactsV2: client is nil")
	}
	result := new(getContactsV2Result)
	args := getContactsV2Args{Request: &getContactsV2Request{Mids: mids}}
	_, err := s.client.RequestTyped(ctx, RequestOptions{
		Path:     s.rpc.definition.Endpoint,
		Method:   "getContactsV2",
		Protocol: s.rpc.definition.Protocol,
	}, args, result)
	if err != nil {
		return nil, fmt.Errorf("line getContactsV2: %w", err)
	}
	if result.E != nil {
		return nil, talkServiceError("getContactsV2", result.E)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line getContactsV2: %w", ErrMissingServiceSuccess)
	}
	return result.Success, nil
}

// GetE2EEPublicKeys retrieves all registered E2EE public keys for the
// authenticated account. LINEJS exposes this RPC even though the pinned
// service catalog omits its zero-argument method declaration.
func (s *TalkService) GetE2EEPublicKeys(ctx context.Context) ([]*types.Pb1C13097n4, error) {
	if s == nil || s.client == nil || s.rpc == nil {
		return nil, fmt.Errorf("line getE2EEPublicKeys: client is nil")
	}
	result := new(types.GetE2EEPublicKeysResult)
	_, err := s.client.RequestTyped(ctx, RequestOptions{
		Path:     s.rpc.definition.Endpoint,
		Method:   "getE2EEPublicKeys",
		Protocol: s.rpc.definition.Protocol,
	}, nil, result)
	if err != nil {
		return nil, fmt.Errorf("line getE2EEPublicKeys: %w", err)
	}
	if result.E != nil {
		return nil, talkServiceError("getE2EEPublicKeys", result.E)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line getE2EEPublicKeys: %w", ErrMissingServiceSuccess)
	}
	return result.Success, nil
}

func (s *TalkService) request(ctx context.Context, method string, timeout time.Duration, long bool, args, result any) error {
	_, err := s.rpc.CallTypedWithOptions(ctx, ServiceCallOptions{
		Timeout: timeout,
		Long:    long,
	}, method, args, result)
	return err
}

func talkServiceError(method string, remote *types.TalkException) error {
	code := int32(0)
	if remote.Code != nil {
		code = int32(*remote.Code)
	}
	reason := ""
	if remote.Reason != nil {
		reason = *remote.Reason
	}
	return &ServiceError{Method: method, Code: code, Reason: reason, Parameters: remote.ParameterMap}
}

func stringPointer(value string) *string                            { return &value }
func int8Pointer(value int8) *int8                                  { return &value }
func int32Pointer(value int32) *int32                               { return &value }
func int64Pointer(value int64) *int64                               { return &value }
func boolPointer(value bool) *bool                                  { return &value }
func contentTypePointer(value types.ContentType) *types.ContentType { return &value }

func cloneTalkMetadata(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func messageRelationReplyPointer() *types.MessageRelationType {
	value := types.MessageRelationReply
	return &value
}

func messageServiceTalkPointer() *types.MessageServiceCode {
	value := types.MessageServiceTalk
	return &value
}

type getContactsV2Args struct {
	Request *getContactsV2Request `thrift:"1,12"`
}

type getContactsV2Request struct {
	Mids []string `thrift:"1,15,11"`
}

type getContactsV2Result struct {
	Success *types.GetContactsV2Response `thrift:"0,12"`
	E       *types.TalkException         `thrift:"1,12"`
}
