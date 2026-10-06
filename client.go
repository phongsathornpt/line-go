// Package line provides the high-level LINE client.
package line

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/phongsathornpt/line-go/base"
	pushtransport "github.com/phongsathornpt/line-go/internal/transport/push"
	"github.com/phongsathornpt/line-go/storage"
	"github.com/phongsathornpt/line-go/types"
)

// Device identifies the LINE application profile to emulate.
type Device = base.Device

const (
	DeviceDesktopWindows   = base.DeviceDesktopWindows
	DeviceDesktopMac       = base.DeviceDesktopMac
	DeviceAndroid          = base.DeviceAndroid
	DeviceAndroidSecondary = base.DeviceAndroidSecondary
	DeviceIOS              = base.DeviceIOS
	DeviceIOSIPad          = base.DeviceIOSIPad
	DeviceWatchOS          = base.DeviceWatchOS
	DeviceWearOS           = base.DeviceWearOS
)

// ClientOptions configures the high-level client. A nil HTTPClient or Storage
// selects the standard HTTP transport and an in-memory store, respectively.
type ClientOptions struct {
	Device       Device
	Version      string
	Endpoint     string
	HTTPClient   base.HTTPDoer
	Storage      base.StateStore
	Config       base.Config
	Legy         base.LegyOptions
	AuthToken    string
	RefreshToken string
}

// Client is the high-level LINE SDK entry point. Direct protocol and service
// access remains available through Base.
type Client struct {
	base    *base.BaseClient
	profile *Profile
}

// NewClient creates a client with default HTTP and memory-storage adapters
// unless callers provide their own implementations.
func NewClient(options ClientOptions) (*Client, error) {
	if options.HTTPClient == nil {
		options.HTTPClient = &http.Client{}
	}
	if options.Storage == nil {
		options.Storage = storage.NewMemoryStorage()
	}
	baseClient, err := base.NewBaseClient(base.Options{
		Device:     options.Device,
		Version:    options.Version,
		Endpoint:   options.Endpoint,
		HTTPClient: options.HTTPClient,
		Storage:    options.Storage,
		Config:     options.Config,
		Legy:       options.Legy,
		Push:       pushtransport.NewConnector(options.HTTPClient, options.Config.Timeout),
	})
	if err != nil {
		return nil, fmt.Errorf("line client: %w", err)
	}
	baseClient.SetAuthToken(options.AuthToken)
	if options.RefreshToken != "" {
		if err := baseClient.Storage().Set(context.Background(), "refreshToken", options.RefreshToken); err != nil {
			return nil, fmt.Errorf("line client: persist refresh token: %w", err)
		}
	}
	return &Client{base: baseClient}, nil
}

// Base returns the lower-level client for direct service and Thrift access.
func (c *Client) Base() *base.BaseClient {
	return c.base
}

// E2EE returns the lower-level E2EE key and login helpers.
func (c *Client) E2EE() *base.E2EEService {
	return c.base.E2EE()
}

// SetAuthToken changes the access token used by subsequent requests.
func (c *Client) SetAuthToken(token string) {
	c.base.SetAuthToken(token)
}

// AuthToken returns the token currently used by the client.
func (c *Client) AuthToken() string {
	return c.base.AuthToken()
}

// Profile returns the profile loaded by a successful login flow, if any.
func (c *Client) Profile() *Profile {
	return c.profile
}

// TryRefreshToken rotates the access token using the refresh token in storage.
func (c *Client) TryRefreshToken(ctx context.Context) error {
	_, err := c.base.Auth().TryRefreshToken(ctx)
	return err
}

// Logout asks LINE to end the session, clears the in-memory access token, and
// closes this client after the remote request succeeds.
func (c *Client) Logout(ctx context.Context) (bool, error) {
	return c.base.Auth().Logout(ctx)
}

// Close disables future requests.
func (c *Client) Close() error {
	return c.base.Close()
}

// ContentType is the domain-facing category of a LINE message.
type ContentType int32

const (
	ContentNone             ContentType = 0
	ContentImage            ContentType = 1
	ContentVideo            ContentType = 2
	ContentAudio            ContentType = 3
	ContentHTML             ContentType = 4
	ContentPDF              ContentType = 5
	ContentCall             ContentType = 6
	ContentSticker          ContentType = 7
	ContentPresence         ContentType = 8
	ContentGift             ContentType = 9
	ContentGroupBoard       ContentType = 10
	ContentAppLink          ContentType = 11
	ContentLink             ContentType = 12
	ContentContact          ContentType = 13
	ContentFile             ContentType = 14
	ContentLocation         ContentType = 15
	ContentPostNotification ContentType = 16
	ContentRich             ContentType = 17
	ContentChatEvent        ContentType = 18
	ContentMusic            ContentType = 19
	ContentPayment          ContentType = 20
	ContentExtendedImage    ContentType = 21
	ContentFlex             ContentType = 22
)

// Location is a domain-facing geographic location attached to a message.
type Location struct {
	Title      string
	Address    string
	Latitude   float64
	Longitude  float64
	Phone      string
	CategoryID string
}

// Message is the domain-facing representation returned by common client APIs.
type Message struct {
	ID               string
	From             string
	To               string
	Text             string
	CreatedAt        time.Time
	ContentType      ContentType
	ContentMetadata  map[string]string
	RelatedMessageID string
	Location         *Location
	Chunks           [][]byte
}

// SendMessageOptions describes a Talk message to send.
type SendMessageOptions struct {
	To               string
	E2EE             bool
	Text             *string
	ContentType      ContentType
	ContentMetadata  map[string]string
	RelatedMessageID string
	Location         *Location
	Chunks           [][]byte
}

// SendMessage sends a Talk message and maps its wire DTO to a domain Message.
func (c *Client) SendMessage(ctx context.Context, options SendMessageOptions) (*Message, error) {
	var relatedMessageID *string
	if options.RelatedMessageID != "" {
		relatedMessageID = &options.RelatedMessageID
	}
	var location *types.Location
	if options.Location != nil {
		location = &types.Location{
			Title:      optionalString(options.Location.Title),
			Address:    optionalString(options.Location.Address),
			Latitude:   float64Pointer(options.Location.Latitude),
			Longitude:  float64Pointer(options.Location.Longitude),
			Phone:      optionalString(options.Location.Phone),
			CategoryId: optionalString(options.Location.CategoryID),
		}
	}
	from := ""
	if c.profile != nil {
		from = c.profile.MID
	}
	result, err := c.base.Talk().SendMessage(ctx, base.SendMessageOptions{
		From:             from,
		To:               options.To,
		E2EE:             options.E2EE,
		Text:             options.Text,
		ContentType:      types.ContentType(options.ContentType),
		ContentMetadata:  options.ContentMetadata,
		RelatedMessageID: relatedMessageID,
		Location:         location,
		Chunks:           options.Chunks,
	})
	if err != nil {
		return nil, err
	}
	if options.E2EE {
		if options.Text != nil && result.Text == nil {
			result.Text = options.Text
		}
		if location != nil && result.Location == nil {
			result.Location = location
		}
	}
	return messageFromDTO(result), nil
}

func messageFromDTO(message *types.Message) *Message {
	if message == nil {
		return nil
	}
	result := &Message{
		ContentType:     ContentNone,
		ContentMetadata: cloneStringMap(message.ContentMetadata),
		Chunks:          cloneByteSlices(message.Chunks),
	}
	if message.From != nil {
		result.From = *message.From
	}
	if message.To != nil {
		result.To = *message.To
	}
	if message.Id != nil {
		result.ID = *message.Id
	}
	if message.Text != nil {
		result.Text = *message.Text
	}
	if message.CreatedTime != nil {
		result.CreatedAt = time.UnixMilli(*message.CreatedTime)
	}
	if message.ContentType != nil {
		result.ContentType = ContentType(*message.ContentType)
	}
	if message.RelatedMessageId != nil {
		result.RelatedMessageID = *message.RelatedMessageId
	}
	if message.Location != nil {
		result.Location = locationFromDTO(message.Location)
	}
	return result
}

func locationFromDTO(location *types.Location) *Location {
	result := new(Location)
	if location.Title != nil {
		result.Title = *location.Title
	}
	if location.Address != nil {
		result.Address = *location.Address
	}
	if location.Latitude != nil {
		result.Latitude = *location.Latitude
	}
	if location.Longitude != nil {
		result.Longitude = *location.Longitude
	}
	if location.Phone != nil {
		result.Phone = *location.Phone
	}
	if location.CategoryId != nil {
		result.CategoryID = *location.CategoryId
	}
	return result
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func float64Pointer(value float64) *float64 { return &value }

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func cloneByteSlices(source [][]byte) [][]byte {
	if source == nil {
		return nil
	}
	clone := make([][]byte, len(source))
	for index, value := range source {
		clone[index] = append([]byte(nil), value...)
	}
	return clone
}
