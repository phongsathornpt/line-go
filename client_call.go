package line

import (
	"context"
	"fmt"

	"github.com/phongsathornpt/line-go/base"
	"github.com/phongsathornpt/line-go/types"
)

// CallType selects the media for a one-to-one call.
type CallType string

const (
	CallTypeAudio    CallType = "AUDIO"
	CallTypeVideo    CallType = "VIDEO"
	CallTypeFaceplay CallType = "FACEPLAY"
)

// CallRouteOptions selects a one-to-one call route and its caller environment.
type CallRouteOptions struct {
	To          string
	CallType    CallType
	FromEnvInfo map[string]string
}

// CallClient exposes call control operations through the LINE CallService.
type CallClient struct {
	client *Client
}

// Call returns call control operations for this client.
func (c *Client) Call() *CallClient {
	if c == nil {
		return nil
	}
	return &CallClient{client: c}
}

// Service returns the generated lower-level CallService.
func (c *CallClient) Service() *base.CallService {
	if c == nil || c.client == nil || c.client.base == nil {
		return nil
	}
	return c.client.base.Call()
}

// AcquireRoute obtains the signaling route for a one-to-one call.
func (c *CallClient) AcquireRoute(ctx context.Context, options CallRouteOptions) (*types.CallRoute, error) {
	if c == nil || c.client == nil || c.client.base == nil {
		return nil, fmt.Errorf("line call: client is nil")
	}
	if options.To == "" {
		return nil, fmt.Errorf("line call: recipient MID is empty")
	}
	if options.CallType == "" {
		options.CallType = CallTypeAudio
	}
	wireCallType, err := callTypeEnum(options.CallType)
	if err != nil {
		return nil, err
	}
	if options.FromEnvInfo == nil {
		options.FromEnvInfo = DefaultCallFromEnvInfo(c.client.base.DeviceDetails())
	}
	result, err := c.client.base.Call().AcquireCallRoute(ctx, types.AcquireCallRouteArgs{
		To: stringPointer(options.To), CallType: &wireCallType, FromEnvInfo: options.FromEnvInfo,
	})
	if err != nil {
		return nil, fmt.Errorf("line call: acquire route: %w", err)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line call: %w", missingSuccess("acquireCallRoute"))
	}
	return result.Success, nil
}

// AcquireGroupRoute obtains a group-call signaling route.
func (c *CallClient) AcquireGroupRoute(ctx context.Context, args types.AcquireGroupCallRouteArgs) (*types.GroupCallRoute, error) {
	if service, err := c.service(); err != nil {
		return nil, err
	} else {
		result, callErr := service.AcquireGroupCallRoute(ctx, args)
		if callErr != nil {
			return nil, fmt.Errorf("line call: acquire group route: %w", callErr)
		}
		if result.Success == nil {
			return nil, fmt.Errorf("line call: %w", missingSuccess("acquireGroupCallRoute"))
		}
		return result.Success, nil
	}
}

// AcquireOARoute obtains a route for an official account call.
func (c *CallClient) AcquireOARoute(ctx context.Context, request types.AcquireOACallRouteRequest) (*types.AcquireOACallRouteResponse, error) {
	service, err := c.service()
	if err != nil {
		return nil, err
	}
	result, err := service.AcquireOACallRoute(ctx, types.AcquireOACallRouteArgs{Request: &request})
	if err != nil {
		return nil, fmt.Errorf("line call: acquire OA route: %w", err)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line call: %w", missingSuccess("acquireOACallRoute"))
	}
	return result.Success, nil
}

// GetGroupCall returns the current call state for a Talk group.
func (c *CallClient) GetGroupCall(ctx context.Context, chatMID string) (*types.GroupCall, error) {
	service, err := c.service()
	if err != nil {
		return nil, err
	}
	if chatMID == "" {
		return nil, fmt.Errorf("line call: chat MID is empty")
	}
	result, err := service.GetGroupCall(ctx, types.GetGroupCallArgs{ChatMid: stringPointer(chatMID)})
	if err != nil {
		return nil, fmt.Errorf("line call: get group call: %w", err)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line call: %w", missingSuccess("getGroupCall"))
	}
	return result.Success, nil
}

// CreateGroupCallURL creates a persistent call URL for the user's group chats.
func (c *CallClient) CreateGroupCallURL(ctx context.Context, title string) (*types.GroupCallUrl, error) {
	service, err := c.service()
	if err != nil {
		return nil, err
	}
	result, err := service.CreateGroupCallUrl(ctx, types.CreateGroupCallUrlArgs{
		Request: &types.CreateGroupCallUrlRequest{Title: stringPointer(title)},
	})
	if err != nil {
		return nil, fmt.Errorf("line call: create group call URL: %w", err)
	}
	if result.Success == nil || result.Success.Url == nil {
		return nil, fmt.Errorf("line call: %w", missingSuccess("createGroupCallUrl"))
	}
	return result.Success.Url, nil
}

// GetGroupCallURL looks up a persistent group-call URL by its ticket.
func (c *CallClient) GetGroupCallURL(ctx context.Context, ticket string) (*types.GetGroupCallUrlInfoResponse, error) {
	service, err := c.service()
	if err != nil {
		return nil, err
	}
	if ticket == "" {
		return nil, fmt.Errorf("line call: group call URL ticket is empty")
	}
	result, err := service.GetGroupCallUrlInfo(ctx, types.GetGroupCallUrlInfoArgs{
		Request: &types.GetGroupCallUrlInfoRequest{UrlId: stringPointer(ticket)},
	})
	if err != nil {
		return nil, fmt.Errorf("line call: get group call URL: %w", err)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line call: %w", missingSuccess("getGroupCallUrlInfo"))
	}
	return result.Success, nil
}

// ListGroupCallURLs returns persistent call URLs for the signed-in account.
func (c *CallClient) ListGroupCallURLs(ctx context.Context) ([]*types.GroupCallUrl, error) {
	service, err := c.service()
	if err != nil {
		return nil, err
	}
	result, err := service.GetGroupCallUrls(ctx, types.GetGroupCallUrlsArgs{Request: &types.Pb1C13042j5{}})
	if err != nil {
		return nil, fmt.Errorf("line call: list group call URLs: %w", err)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line call: %w", missingSuccess("getGroupCallUrls"))
	}
	return result.Success.Urls, nil
}

// UpdateGroupCallURL applies a generated request to a persistent call URL.
func (c *CallClient) UpdateGroupCallURL(ctx context.Context, request types.UpdateGroupCallUrlRequest) error {
	service, err := c.service()
	if err != nil {
		return err
	}
	if _, err := service.UpdateGroupCallUrl(ctx, types.UpdateGroupCallUrlArgs{Request: &request}); err != nil {
		return fmt.Errorf("line call: update group call URL: %w", err)
	}
	return nil
}

// DeleteGroupCallURL removes a persistent call URL.
func (c *CallClient) DeleteGroupCallURL(ctx context.Context, urlID string) error {
	service, err := c.service()
	if err != nil {
		return err
	}
	if urlID == "" {
		return fmt.Errorf("line call: group call URL ID is empty")
	}
	if _, err := service.DeleteGroupCallUrl(ctx, types.DeleteGroupCallUrlArgs{
		Request: &types.DeleteGroupCallUrlRequest{UrlId: stringPointer(urlID)},
	}); err != nil {
		return fmt.Errorf("line call: delete group call URL: %w", err)
	}
	return nil
}

// JoinChatByCallURL joins the chat associated with a call URL ticket.
func (c *CallClient) JoinChatByCallURL(ctx context.Context, ticket string) (*types.JoinChatByCallUrlResponse, error) {
	service, err := c.service()
	if err != nil {
		return nil, err
	}
	if ticket == "" {
		return nil, fmt.Errorf("line call: group call URL ticket is empty")
	}
	result, err := service.JoinChatByCallUrl(ctx, types.JoinChatByCallUrlArgs{
		Request: &types.JoinChatByCallUrlRequest{UrlId: stringPointer(ticket)},
	})
	if err != nil {
		return nil, fmt.Errorf("line call: join chat by call URL: %w", err)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line call: %w", missingSuccess("joinChatByCallUrl"))
	}
	return result.Success, nil
}

// InviteIntoGroupCall invites members to a group call.
func (c *CallClient) InviteIntoGroupCall(ctx context.Context, args types.InviteIntoGroupCallArgs) error {
	service, err := c.service()
	if err != nil {
		return err
	}
	if _, err := service.InviteIntoGroupCall(ctx, args); err != nil {
		return fmt.Errorf("line call: invite into group call: %w", err)
	}
	return nil
}

// KickoutFromGroupCall removes members from a group call.
func (c *CallClient) KickoutFromGroupCall(ctx context.Context, request types.KickoutFromGroupCallRequest) error {
	service, err := c.service()
	if err != nil {
		return err
	}
	if _, err := service.KickoutFromGroupCall(ctx, types.KickoutFromGroupCallArgs{KickoutFromGroupCallRequest: &request}); err != nil {
		return fmt.Errorf("line call: kick member from group call: %w", err)
	}
	return nil
}

// IncomingCallEvent is a parsed incoming-call Talk operation.
type IncomingCallEvent struct {
	CallMID string
	From    string
	Kind    string
	Raw     *types.Operation
}

// CancelCallEvent is a parsed call-cancellation Talk operation.
type CancelCallEvent struct {
	CallMID string
	From    string
	Reason  string
	Raw     *types.Operation
}

// ParseIncomingCall reads call identifiers from a Talk operation.
func ParseIncomingCall(operation *types.Operation) IncomingCallEvent {
	return IncomingCallEvent{
		CallMID: operationParam(operation, func(op *types.Operation) *string { return op.Param1 }),
		From:    operationParam(operation, func(op *types.Operation) *string { return op.Param2 }),
		Kind:    operationParam(operation, func(op *types.Operation) *string { return op.Param3 }),
		Raw:     operation,
	}
}

// ParseCancelCall reads cancellation details from a Talk operation.
func ParseCancelCall(operation *types.Operation) CancelCallEvent {
	return CancelCallEvent{
		CallMID: operationParam(operation, func(op *types.Operation) *string { return op.Param1 }),
		From:    operationParam(operation, func(op *types.Operation) *string { return op.Param2 }),
		Reason:  operationParam(operation, func(op *types.Operation) *string { return op.Param3 }),
		Raw:     operation,
	}
}

func (c *CallClient) service() (*base.CallService, error) {
	if c == nil || c.client == nil || c.client.base == nil {
		return nil, fmt.Errorf("line call: client is nil")
	}
	return c.client.base.Call(), nil
}

func callTypeEnum(callType CallType) (types.Pb1D4, error) {
	switch callType {
	case CallTypeAudio:
		return types.Pb1D4AUDIO, nil
	case CallTypeVideo:
		return types.Pb1D4VIDEO, nil
	case CallTypeFaceplay:
		return types.Pb1D4FACEPLAY, nil
	default:
		return 0, fmt.Errorf("line call: unsupported call type %q", callType)
	}
}

// DefaultCallFromEnvInfo builds the LINE caller environment map for a device.
func DefaultCallFromEnvInfo(details base.DeviceDetails) map[string]string {
	deviceName := details.SystemName
	switch details.Device {
	case base.DeviceAndroid, base.DeviceAndroidSecondary:
		deviceName = "Android"
	case base.DeviceIOS:
		deviceName = "iPhone"
	case base.DeviceIOSIPad:
		deviceName = "iPad"
	case base.DeviceDesktopWindows:
		deviceName = "Windows"
	case base.DeviceDesktopMac:
		deviceName = "Mac"
	case base.DeviceWatchOS:
		deviceName = "Watch"
	case base.DeviceWearOS:
		deviceName = "Wear OS"
	default:
		if deviceName == "" {
			deviceName = string(details.Device)
		}
	}
	return map[string]string{"devname": deviceName}
}

func operationParam(operation *types.Operation, field func(*types.Operation) *string) string {
	if operation == nil {
		return ""
	}
	value := field(operation)
	if value == nil {
		return ""
	}
	return *value
}
