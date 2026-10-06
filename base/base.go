// Package base exposes the lower-level LINE client and direct Thrift request
// capability.
package base

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/phongsathornpt/line-go/internal/protocol/legy"
	"github.com/phongsathornpt/line-go/thrift"
)

const defaultEndpoint = "legy.line-apps.com"

// ErrClientClosed reports requests attempted after the client is closed.
var ErrClientClosed = errors.New("line base client is closed")

// HTTPDoer is implemented by *http.Client and custom transports.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// StateStore is the narrow state capability consumed by BaseClient.
type StateStore interface {
	Set(ctx context.Context, key string, value any) error
	Get(ctx context.Context, key string) (any, bool, error)
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
}

// Config controls network deadlines and response resource limits.
type Config struct {
	Timeout          time.Duration
	LongTimeout      time.Duration
	MaxResponseBytes int64
}

// LegyEncryptionMode controls request wrapping through LINE's LEGY gateway.
type LegyEncryptionMode string

const (
	LegyEncryptionAuto     LegyEncryptionMode = "auto"
	LegyEncryptionDisabled LegyEncryptionMode = "disabled"
	LegyEncryptionEnabled  LegyEncryptionMode = "enabled"
)

// LegyOptions configures encrypted transport for modern LINE access tokens.
// The zero mode selects automatic encryption for supported Talk paths.
type LegyOptions struct {
	Encryption LegyEncryptionMode
	Endpoint   string
}

// Options configures a BaseClient. Device, HTTPClient, and Storage are required;
// endpoint and timeout values receive LINEJS-compatible defaults.
type Options struct {
	Device     Device
	Version    string
	Endpoint   string
	HTTPClient HTTPDoer
	Storage    StateStore
	Config     Config
	Legy       LegyOptions
	Push       PushConnector
}

// BaseClient performs direct LINE Thrift requests. It owns no network
// resources when a caller supplies HTTPClient.
type BaseClient struct {
	endpoint   *url.URL
	legy       LegyOptions
	details    DeviceDetails
	httpClient HTTPDoer
	storage    StateStore
	config     Config
	reqseqMu   sync.Mutex
	reqseqs    map[string]int64
	tokenMu    sync.RWMutex
	authToken  string
	profileMID string
	closed     bool
	closedMu   sync.RWMutex
	talk       *TalkService
	polling    *Polling
	auth       *AuthService
	login      *LoginService
	services   map[ServiceName]*RPCService
	e2ee       *E2EEService
	obs        *ObjectStorage
	timeline   *TimelineService
	push       PushConnector
	pushEvents *PushService
	legyMu     sync.Mutex
	legyWire   *legy.Transport
	legyErr    error
}

// NewBaseClient validates options and creates a lower-level client.
func NewBaseClient(options Options) (*BaseClient, error) {
	details, ok := getDeviceDetails(options.Device, options.Version)
	if !ok {
		return nil, fmt.Errorf("line base client: unsupported device %q", options.Device)
	}

	endpoint, err := parseEndpoint(options.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("line base client: %w", err)
	}
	if options.HTTPClient == nil {
		return nil, fmt.Errorf("line base client: HTTP transport is required")
	}
	if options.Storage == nil {
		return nil, fmt.Errorf("line base client: storage is required")
	}
	if options.Config.Timeout == 0 {
		options.Config.Timeout = 30 * time.Second
	}
	if options.Config.LongTimeout == 0 {
		options.Config.LongTimeout = 180 * time.Second
	}
	if options.Config.MaxResponseBytes == 0 {
		options.Config.MaxResponseBytes = 64 << 20
	}
	if options.Config.Timeout < 0 || options.Config.LongTimeout < 0 {
		return nil, fmt.Errorf("line base client: request timeouts cannot be negative")
	}
	if options.Config.MaxResponseBytes < 1 {
		return nil, fmt.Errorf("line base client: maximum response size must be positive")
	}
	if options.Config.MaxResponseBytes >= 1<<63-1 {
		return nil, fmt.Errorf("line base client: maximum response size is too large")
	}
	if options.Legy.Encryption == "" {
		options.Legy.Encryption = LegyEncryptionAuto
	}
	switch options.Legy.Encryption {
	case LegyEncryptionAuto, LegyEncryptionDisabled, LegyEncryptionEnabled:
	default:
		return nil, fmt.Errorf("line base client: unsupported LEGY encryption mode %q", options.Legy.Encryption)
	}
	if options.Legy.Endpoint != "" {
		if err := legy.ValidateEndpoint(options.Legy.Endpoint); err != nil {
			return nil, fmt.Errorf("line base client: %w", err)
		}
	}

	client := &BaseClient{
		endpoint:   endpoint,
		legy:       options.Legy,
		details:    details,
		httpClient: options.HTTPClient,
		storage:    options.Storage,
		config:     options.Config,
		push:       options.Push,
		services:   make(map[ServiceName]*RPCService, len(linejsServiceCatalog)),
	}
	for _, definition := range linejsServiceCatalog {
		client.services[definition.Name] = &RPCService{client: client, definition: definition}
	}
	client.talk = &TalkService{client: client, rpc: client.services[ServiceNameTalk]}
	client.polling = &Polling{client: client}
	client.auth = &AuthService{client: client, rpc: client.services[ServiceNameAuth]}
	client.login = &LoginService{client: client}
	client.e2ee = &E2EEService{client: client}
	client.obs = &ObjectStorage{client: client}
	client.timeline = &TimelineService{client: client}
	client.pushEvents = &PushService{client: client}
	return client, nil
}

// Endpoint returns the configured API endpoint.
func (c *BaseClient) Endpoint() string {
	return c.endpoint.String()
}

// DeviceDetails returns the immutable emulated device profile.
func (c *BaseClient) DeviceDetails() DeviceDetails {
	return c.details
}

// Storage returns the storage capability used by this client.
func (c *BaseClient) Storage() StateStore {
	return c.storage
}

// Talk returns the Talk service bound to this client.
func (c *BaseClient) Talk() *TalkService {
	return c.talk
}

// Polling returns the long-poll event client bound to this BaseClient.
func (c *BaseClient) Polling() *Polling {
	return c.polling
}

// Push returns the persistent push event client bound to this BaseClient.
func (c *BaseClient) Push() *PushService {
	return c.pushEvents
}

// Auth returns the authentication service bound to this client.
func (c *BaseClient) Auth() *AuthService {
	return c.auth
}

// Login returns the low-level account-login service.
func (c *BaseClient) Login() *LoginService {
	return c.login
}

// E2EE returns E2EE key management and login cryptography bound to this client.
func (c *BaseClient) E2EE() *E2EEService {
	return c.e2ee
}

// SetAuthToken changes the access token sent on subsequent requests.
func (c *BaseClient) SetAuthToken(token string) {
	c.tokenMu.Lock()
	c.authToken = token
	c.tokenMu.Unlock()
}

// SetProfileMID records the authenticated account MID for base workflows that
// need an account identity, such as Timeline channel-token initialization.
func (c *BaseClient) SetProfileMID(mid string) {
	c.tokenMu.Lock()
	c.profileMID = mid
	c.tokenMu.Unlock()
}

// ProfileMID returns the MID recorded for the authenticated account.
func (c *BaseClient) ProfileMID() string {
	c.tokenMu.RLock()
	mid := c.profileMID
	c.tokenMu.RUnlock()
	return mid
}

// AuthToken returns the current access token.
func (c *BaseClient) AuthToken() string {
	c.tokenMu.RLock()
	token := c.authToken
	c.tokenMu.RUnlock()
	return token
}

// Timeline returns the Timeline service bound to this BaseClient.
func (c *BaseClient) Timeline() *TimelineService {
	if c == nil {
		return nil
	}
	return c.timeline
}

// Close disables future requests. Injected and shared HTTP clients are not
// closed because their lifecycle remains with the caller.
func (c *BaseClient) Close() error {
	c.closedMu.Lock()
	c.closed = true
	c.closedMu.Unlock()
	return nil
}

// Headers builds the standard LINE application headers for an HTTP method.
func (c *BaseClient) Headers(httpMethod string) http.Header {
	if httpMethod == "" {
		httpMethod = http.MethodPost
	}
	application := strings.Join([]string{
		string(c.details.Device),
		c.details.AppVersion,
		c.details.SystemName,
		c.details.SystemVersion,
	}, "\t")
	headers := make(http.Header, 12)
	headers.Set("Accept", "application/x-thrift")
	headers.Set("User-Agent", "Line/"+c.details.AppVersion)
	headers.Set("X-Line-Application", application)
	headers.Set("Content-Type", "application/x-thrift")
	headers.Set("X-Lal", "ja_JP")
	headers.Set("X-Lpv", "1")
	headers.Set("X-Lhm", httpMethod)
	headers.Set("Accept-Encoding", "gzip")
	if token := c.AuthToken(); token != "" {
		headers.Set("X-Line-Access", token)
	}
	return headers
}

func (c *BaseClient) isClosed() bool {
	c.closedMu.RLock()
	closed := c.closed
	c.closedMu.RUnlock()
	return closed
}

func parseEndpoint(endpoint string) (*url.URL, error) {
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("endpoint scheme must be http or https")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("endpoint must contain only a host and optional base path")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf("endpoint base paths are not supported")
	}
	parsed.Path = ""
	return parsed, nil
}

// RequestOptions selects a LINE API method and its HTTP route.
type RequestOptions struct {
	Path       string
	Method     string
	Protocol   thrift.Protocol
	HTTPMethod string
	Timeout    time.Duration
	Long       bool
	Headers    http.Header
}

// Response contains the decoded Thrift message and its HTTP metadata.
type Response struct {
	Message    thrift.Message
	StatusCode int
	Headers    http.Header
}

// ResponseTooLargeError indicates that an HTTP response exceeded the configured
// maximum before the Thrift decoder could process it.
type ResponseTooLargeError struct {
	Limit int64
}

func (e *ResponseTooLargeError) Error() string {
	return fmt.Sprintf("line request: response exceeds %d bytes", e.Limit)
}
