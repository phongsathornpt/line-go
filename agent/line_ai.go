package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	LineAIHostRelease                 = "https://line-x-openai.line-apps.com"
	LineAIHostAlpha                   = "https://line-x-openai.line-apps-alpha.com"
	LineAIDefaultLineVersion          = "26.7.2"
	LineAIDefaultLineOS               = "IOS"
	LineAIDefaultAcceptLanguage       = "ja"
	LineAIChannelID                   = "2006890580"
	lineAIResponseLimit         int64 = 64 << 20
)

// LineAIPromptContext selects a suggested-prompt collection.
type LineAIPromptContext string

const (
	LineAIPromptTrending      LineAIPromptContext = "trending"
	LineAIPromptImageAttached LineAIPromptContext = "image-attached"
)

// LineAIOptions configures requests to LINE's native Agent I API.
// AccessToken is a channel-scoped token for LineAIChannelID.
type LineAIOptions struct {
	AccessToken    string
	LineVersion    string
	LineOS         string
	AcceptLanguage string
	Host           string
	HTTPClient     HTTPDoer
	UserAgent      string
}

// LineAIQueryRequest is the JSON body accepted by POST /v2/query-ai.
type LineAIQueryRequest struct {
	ThreadID *string `json:"threadId"`
	Message  string  `json:"message"`
	ImageURL *string `json:"imageUrl"`
}

// LineAICancelQueryRequest identifies a running query to cancel.
type LineAICancelQueryRequest struct {
	ThreadID string `json:"threadId"`
	RunID    string `json:"runId"`
}

// LineAIRateLimit contains the response rate-limit headers.
type LineAIRateLimit struct {
	Limit     string
	Remaining string
	Usage     string
}

// LineAIResponse wraps an HTTP response and its parsed JSON or text body.
type LineAIResponse struct {
	Status    int
	RateLimit LineAIRateLimit
	Body      any
}

// LineAIQueryChunk is one Server-Sent Event from /v2/query-ai.
type LineAIQueryChunk struct {
	Event string
	Data  any
}

// LineAIClient calls LINE's native LINE AI service.
type LineAIClient struct {
	host           string
	accessToken    string
	lineVersion    string
	lineOS         string
	acceptLanguage string
	userAgent      string
	httpClient     HTTPDoer
}

// NewLineAIClient creates a client for LINE's native Agent I REST API.
func NewLineAIClient(options LineAIOptions) *LineAIClient {
	host := strings.TrimRight(options.Host, "/")
	if host == "" {
		host = LineAIHostRelease
	}
	version := options.LineVersion
	if version == "" {
		version = LineAIDefaultLineVersion
	}
	lineOS := options.LineOS
	if lineOS == "" {
		lineOS = LineAIDefaultLineOS
	}
	language := options.AcceptLanguage
	if language == "" {
		language = LineAIDefaultAcceptLanguage
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	userAgent := options.UserAgent
	if userAgent == "" {
		userAgent = fmt.Sprintf("LINE/%s CFNetwork/3860.200.71 Darwin/25.1.0", version)
	}
	return &LineAIClient{
		host: host, accessToken: options.AccessToken, lineVersion: version,
		lineOS: lineOS, acceptLanguage: language, userAgent: userAgent, httpClient: httpClient,
	}
}

// GetServiceInfo returns the service catalog and help links.
func (c *LineAIClient) GetServiceInfo(ctx context.Context) (*LineAIResponse, error) {
	return c.get(ctx, "/v2/service-info", nil)
}

// GetPromptPresets returns suggested prompts for a context.
func (c *LineAIClient) GetPromptPresets(ctx context.Context, contextType string, acceptLanguage string) (*LineAIResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("line agent: client is nil")
	}
	if contextType == "" {
		return nil, fmt.Errorf("line agent: prompt context is empty")
	}
	if acceptLanguage == "" {
		acceptLanguage = c.acceptLanguage
	}
	return c.get(ctx, "/v2/"+url.PathEscape(contextType)+"/prompt-preset", http.Header{"Accept-Language": {acceptLanguage}})
}

// CreateThread creates a conversation thread.
func (c *LineAIClient) CreateThread(ctx context.Context) (*LineAIResponse, error) {
	return c.request(ctx, http.MethodPost, "/v2/thread", []byte{}, http.Header{"Content-Type": {"application/json; charset=utf-8"}})
}

// GetThread retrieves a conversation thread.
func (c *LineAIClient) GetThread(ctx context.Context, threadID string) (*LineAIResponse, error) {
	return c.get(ctx, "/v2/thread/"+url.PathEscape(threadID), nil)
}

// DeleteThread deletes a conversation thread.
func (c *LineAIClient) DeleteThread(ctx context.Context, threadID string) (*LineAIResponse, error) {
	return c.request(ctx, http.MethodDelete, "/v2/thread/"+url.PathEscape(threadID), nil, nil)
}

// SubmitAgreement submits the one-time consent for LINE AI.
func (c *LineAIClient) SubmitAgreement(ctx context.Context) (*LineAIResponse, error) {
	return c.request(ctx, http.MethodPost, "/v2/user/agreement", []byte{}, http.Header{"Content-Type": {"application/json; charset=utf-8"}})
}

// CancelQuery requests cancellation of an active AI run.
func (c *LineAIClient) CancelQuery(ctx context.Context, query LineAICancelQueryRequest) (*LineAIResponse, error) {
	body, err := json.Marshal(map[string]string{"threadId": query.ThreadID, "runId": query.RunID})
	if err != nil {
		return nil, fmt.Errorf("line agent: encode query cancellation: %w", err)
	}
	return c.request(ctx, http.MethodPost, "/v2/query-ai/cancel", body, http.Header{"Content-Type": {"application/json; charset=utf-8"}})
}

// Query starts a streaming LINE AI response.
func (c *LineAIClient) Query(ctx context.Context, query LineAIQueryRequest) (*LineAIStream, error) {
	if c == nil {
		return nil, fmt.Errorf("line agent: client is nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("line agent: context is nil")
	}
	body, err := json.Marshal(map[string]any{"threadId": query.ThreadID, "message": query.Message, "imageUrl": query.ImageURL})
	if err != nil {
		return nil, fmt.Errorf("line agent: encode query: %w", err)
	}
	headers := c.headers()
	headers.Set("Content-Type", "application/json; charset=utf-8")
	headers.Set("Accept", "text/event-stream")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.host+"/v2/query-ai", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("line agent: create query request: %w", err)
	}
	request.Header = headers
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("line agent: query request: %w", err)
	}
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("line agent: query endpoint returned an empty response")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("line agent query failed: HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	return &LineAIStream{body: response.Body, stream: newSSEReader(response.Body)}, nil
}

func (c *LineAIClient) get(ctx context.Context, path string, extra http.Header) (*LineAIResponse, error) {
	return c.request(ctx, http.MethodGet, path, nil, extra)
}

func (c *LineAIClient) request(ctx context.Context, method, path string, body []byte, extra http.Header) (*LineAIResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("line agent: client is nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("line agent: context is nil")
	}
	request, err := http.NewRequestWithContext(ctx, method, c.host+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("line agent: create request: %w", err)
	}
	request.Header = c.headers()
	for name, values := range extra {
		request.Header[name] = append([]string(nil), values...)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("line agent: request: %w", err)
	}
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("line agent: endpoint returned an empty response")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, lineAIResponseLimit+1))
	if err != nil {
		return nil, fmt.Errorf("line agent: read response: %w", err)
	}
	if int64(len(data)) > lineAIResponseLimit {
		return nil, fmt.Errorf("line agent: response exceeds %d bytes", lineAIResponseLimit)
	}
	return wrapLineAIResponse(response.StatusCode, response.Header, data), nil
}

func (c *LineAIClient) headers() http.Header {
	headers := make(http.Header, 7)
	headers.Set("Accept", "application/json")
	headers.Set("User-Agent", c.userAgent)
	headers.Set("X-Access-Token", c.accessToken)
	headers.Set("X-Line-Version", c.lineVersion)
	headers.Set("X-Line-Os", c.lineOS)
	headers.Set("Accept-Language", c.acceptLanguage)
	return headers
}

// LineAIStream incrementally reads a streaming query response.
type LineAIStream struct {
	body   io.ReadCloser
	stream *sseReader
	chunk  LineAIQueryChunk
	err    error
	done   bool
}

// Next advances to the next event.
func (s *LineAIStream) Next() bool {
	if s == nil || s.done || s.err != nil {
		return false
	}
	if !s.stream.Next() {
		s.err = s.stream.Err()
		s.done = true
		if s.body != nil {
			_ = s.body.Close()
		}
		return false
	}
	event := s.stream.Event()
	s.chunk = LineAIQueryChunk{Event: event.name, Data: decodeAnyJSON(event.data)}
	return true
}

// Chunk returns the event produced by the latest successful Next call.
func (s *LineAIStream) Chunk() LineAIQueryChunk {
	if s == nil {
		return LineAIQueryChunk{}
	}
	return s.chunk
}

// Err returns the stream error, if any.
func (s *LineAIStream) Err() error {
	if s == nil {
		return nil
	}
	return s.err
}

// Close closes the response body.
func (s *LineAIStream) Close() error {
	if s == nil || s.body == nil {
		return nil
	}
	s.done = true
	return s.body.Close()
}

func wrapLineAIResponse(status int, headers http.Header, body []byte) *LineAIResponse {
	return &LineAIResponse{
		Status: status,
		RateLimit: LineAIRateLimit{
			Limit:     headers.Get("X-Ratelimit-Limit"),
			Remaining: headers.Get("X-Ratelimit-Remaining"),
			Usage:     headers.Get("X-Ratelimit-Usage"),
		},
		Body: decodeResponseBody(body),
	}
}

func decodeAnyJSON(value string) any {
	if value == "" {
		return ""
	}
	var decoded any
	if json.Unmarshal([]byte(value), &decoded) == nil {
		return decoded
	}
	return value
}

func decodeResponseBody(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return decodeAnyJSON(string(value))
}
