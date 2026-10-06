// Package agent ports LINEJS's standalone Agent I and native LINE AI clients.
package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const (
	defaultAgentIEndpoint = "https://search-agent.yahoo.co.jp/v2/chat"
	defaultAgentIPage     = "https://search.yahoo.co.jp/chat"
	defaultAgentIVersion  = "26.7.2"
)

// HTTPDoer is implemented by net/http clients and test transports.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// AgentISource identifies the LINE tab that opened Agent I.
type AgentISource string

const (
	AgentIChatTabSource AgentISource = "chattab_searchbar"
	AgentIHomeTabSource AgentISource = "hometab_searchbar"
	AgentINewsTabSource AgentISource = "newstab_searchbar"
)

// AgentRole is the role stored in the Agent I conversation history.
type AgentRole string

const (
	AgentRoleUser      AgentRole = "user"
	AgentRoleAssistant AgentRole = "assistant"
)

// AgentIOptions configures the Yahoo Search Agent client used by LINE Android.
type AgentIOptions struct {
	Cookie      string
	LineVersion string
	Source      AgentISource
	Endpoint    string
	HTTPClient  HTTPDoer
	UserAgent   string
}

// AgentIMessage is one turn in the multi-turn Agent I conversation.
type AgentIMessage struct {
	ID       string          `json:"id"`
	Role     AgentRole       `json:"role"`
	Contents []AgentIContent `json:"contents"`
}

// AgentIContent is a text segment in an Agent I message.
type AgentIContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// AgentIChunk is one Server-Sent Event from Yahoo's Agent I endpoint.
type AgentIChunk struct {
	Event string
	Data  any
	Text  *string
}

// AgentIChatOptions overrides per-request correlation identifiers.
type AgentIChatOptions struct {
	LogID string
	QID   string
}

// AgentIClient sends multi-turn chat requests to Yahoo's Agent I endpoint.
type AgentIClient struct {
	mu         sync.Mutex
	cookie     string
	version    string
	source     AgentISource
	endpoint   string
	userAgent  string
	httpClient HTTPDoer
	history    []AgentIMessage
}

// NewAgentIClient creates an Agent I client using LINE Android's default
// source, version, endpoint, and iOS-shaped user agent.
func NewAgentIClient(options AgentIOptions) *AgentIClient {
	version := options.LineVersion
	if version == "" {
		version = defaultAgentIVersion
	}
	source := options.Source
	if source == "" {
		source = AgentIChatTabSource
	}
	endpoint := options.Endpoint
	if endpoint == "" {
		endpoint = defaultAgentIEndpoint
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	userAgent := options.UserAgent
	if userAgent == "" {
		userAgent = fmt.Sprintf("Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Line/%s/Agenti", version)
	}
	return &AgentIClient{
		cookie: options.Cookie, version: version, source: source,
		endpoint: endpoint, userAgent: userAgent, httpClient: httpClient,
	}
}

// BuildAgentIWebViewURL creates the URL LINE Android loads in its WebView.
func BuildAgentIWebViewURL(source AgentISource, query, baseURL string) (string, error) {
	if !validAgentISource(source) {
		return "", fmt.Errorf("line agent: unsupported Agent I source %q", source)
	}
	if baseURL == "" {
		baseURL = defaultAgentIPage
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("line agent: invalid Agent I page URL")
	}
	values := parsed.Query()
	values.Set("fr", AgentIFrCode(source))
	values.Set("frtype", AgentIFrType(source))
	if query != "" {
		values.Set("q", query)
	}
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

// AgentIFrCode returns the request-origin code sent by LINE Android.
func AgentIFrCode(source AgentISource) string {
	return "line_agenti_" + string(source)
}

// AgentIFrType returns the request type sent by LINE Android.
func AgentIFrType(source AgentISource) string {
	return "line_" + string(source)
}

// Chat begins a streamed Agent I turn. Call Next until it returns false, then
// inspect Err. The user turn is added to history before sending, matching the
// upstream client's retry behavior.
func (c *AgentIClient) Chat(ctx context.Context, text string, options ...AgentIChatOptions) (*AgentIStream, error) {
	if c == nil {
		return nil, fmt.Errorf("line agent: client is nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("line agent: context is nil")
	}
	turnID, err := randomID32()
	if err != nil {
		return nil, err
	}
	turn := AgentIMessage{ID: turnID, Role: AgentRoleUser, Contents: []AgentIContent{{Type: "text", Text: text}}}
	c.mu.Lock()
	c.history = append(c.history, turn)
	history := cloneAgentHistory(c.history)
	cookie := c.cookie
	c.mu.Unlock()
	if cookie == "" {
		cookie, err = c.mintAnonymousCookies(ctx)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		if c.cookie == "" {
			c.cookie = cookie
		} else {
			cookie = c.cookie
		}
		c.mu.Unlock()
	}
	requestOptions := AgentIChatOptions{}
	if len(options) > 0 {
		requestOptions = options[0]
	}
	logID := requestOptions.LogID
	if logID == "" {
		logID, err = randomID32()
		if err != nil {
			return nil, err
		}
	}
	qID := requestOptions.QID
	if qID == "" {
		qID, err = randomID32()
		if err != nil {
			return nil, err
		}
	}
	body, err := json.Marshal(map[string]any{
		"chats": history,
		"context": map[string]any{
			"agentMode": "multi", "logid": logID, "qId": qID, "snc": true,
			"frtype": AgentIFrType(c.source), "frcode": AgentIFrCode(c.source),
			"requestType": "free_text", "index": 0, "yz": false, "pdis": false,
		},
		"debug": map[string]any{},
	})
	if err != nil {
		return nil, fmt.Errorf("line agent: encode chat: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("line agent: create chat request: %w", err)
	}
	request.Header = http.Header{
		"User-Agent":      {c.userAgent},
		"Accept":          {"text/event-stream"},
		"Content-Type":    {"application/json"},
		"Pragma":          {"no-cache"},
		"Cache-Control":   {"no-cache"},
		"Sec-Fetch-Site":  {"same-site"},
		"Sec-Fetch-Mode":  {"cors"},
		"Sec-Fetch-Dest":  {"empty"},
		"Accept-Language": {"ja"},
		"Origin":          {"https://search.yahoo.co.jp"},
		"Referer":         {"https://search.yahoo.co.jp/"},
		"Priority":        {"u=3, i"},
		"Cookie":          {cookie},
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("line agent: send chat: %w", err)
	}
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("line agent: endpoint returned an empty response")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("line agent: HTTP %d %s: %s", response.StatusCode, response.Status, strings.TrimSpace(string(message)))
	}
	return &AgentIStream{client: c, body: response.Body, stream: newSSEReader(response.Body)}, nil
}

// Reset clears the in-memory multi-turn conversation.
func (c *AgentIClient) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.history = nil
	c.mu.Unlock()
}

// History returns a detached snapshot of the conversation, oldest first.
func (c *AgentIClient) History() []AgentIMessage {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	history := cloneAgentHistory(c.history)
	c.mu.Unlock()
	return history
}

// MintAnonymousCookies fetches the Agent I page and extracts Yahoo cookies.
func (c *AgentIClient) MintAnonymousCookies(ctx context.Context) (string, error) {
	if c == nil {
		return "", fmt.Errorf("line agent: client is nil")
	}
	return c.mintAnonymousCookies(ctx)
}

func (c *AgentIClient) mintAnonymousCookies(ctx context.Context) (string, error) {
	pageURL, err := BuildAgentIWebViewURL(c.source, "", "")
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return "", fmt.Errorf("line agent: create cookie request: %w", err)
	}
	response, err := doWithoutRedirect(c.httpClient, request)
	if err != nil {
		return "", fmt.Errorf("line agent: mint Yahoo cookies: %w", err)
	}
	if response == nil || response.Body == nil {
		return "", fmt.Errorf("line agent: cookie endpoint returned an empty response")
	}
	defer response.Body.Close()
	var cookies []string
	for _, cookie := range response.Cookies() {
		cookies = append(cookies, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(cookies, "; "), nil
}

// AgentIStream incrementally reads Agent I Server-Sent Events.
type AgentIStream struct {
	client *AgentIClient
	body   io.ReadCloser
	stream *sseReader
	chunk  AgentIChunk
	text   strings.Builder
	err    error
	done   bool
}

// Next advances to the next non-empty data event.
func (s *AgentIStream) Next() bool {
	if s == nil || s.done || s.err != nil {
		return false
	}
	for s.stream.Next() {
		event := s.stream.Event()
		if event.data == "" {
			continue
		}
		data := decodeSSEData(event.data)
		text := extractAgentText(data)
		if text != nil {
			s.text.WriteString(*text)
		}
		s.chunk = AgentIChunk{Event: event.name, Data: data, Text: text}
		return true
	}
	s.err = s.stream.Err()
	s.finish()
	return false
}

// Chunk returns the event produced by the most recent successful Next call.
func (s *AgentIStream) Chunk() AgentIChunk {
	if s == nil {
		return AgentIChunk{}
	}
	return s.chunk
}

// Err returns the stream or network error, if any.
func (s *AgentIStream) Err() error {
	if s == nil {
		return nil
	}
	return s.err
}

// Close closes the underlying HTTP response body.
func (s *AgentIStream) Close() error {
	if s == nil || s.body == nil {
		return nil
	}
	s.done = true
	return s.body.Close()
}

func (s *AgentIStream) finish() {
	if s.done {
		return
	}
	s.done = true
	if s.body != nil {
		_ = s.body.Close()
	}
	if s.err != nil || s.text.Len() == 0 || s.client == nil {
		return
	}
	id, err := randomID32()
	if err != nil {
		s.err = err
		return
	}
	s.client.mu.Lock()
	s.client.history = append(s.client.history, AgentIMessage{
		ID: id, Role: AgentRoleAssistant,
		Contents: []AgentIContent{{Type: "text", Text: s.text.String()}},
	})
	s.client.mu.Unlock()
}

func decodeSSEData(value string) any {
	var decoded any
	if strings.HasPrefix(value, "{") || strings.HasPrefix(value, "[") {
		if json.Unmarshal([]byte(value), &decoded) == nil {
			return decoded
		}
	}
	return value
}

func extractAgentText(data any) *string {
	if value, ok := data.(string); ok {
		return &value
	}
	object, ok := data.(map[string]any)
	if !ok {
		return nil
	}
	if object["type"] == "compositeMessage-delta" || object["type"] == "compositeMessage-end" {
		if value, ok := object["value"].(map[string]any); ok {
			if message, ok := value["message"].(string); ok {
				return &message
			}
			if message, ok := value["message"].(map[string]any); ok {
				if text, ok := message["text"].(string); ok {
					return &text
				}
			}
		}
	}
	for _, key := range []string{"text", "delta", "content"} {
		if text, ok := object[key].(string); ok {
			return &text
		}
	}
	contents, ok := object["contents"].([]any)
	if !ok {
		return nil
	}
	var parts []string
	for _, content := range contents {
		if item, ok := content.(map[string]any); ok {
			if text, ok := item["text"].(string); ok {
				parts = append(parts, text)
			}
		}
	}
	if len(parts) == 0 {
		return nil
	}
	joined := strings.Join(parts, "")
	return &joined
}

func randomID32() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("line agent: generate request ID: %w", err)
	}
	return hex.EncodeToString(bytes[:]), nil
}

func cloneAgentHistory(history []AgentIMessage) []AgentIMessage {
	copyHistory := make([]AgentIMessage, len(history))
	for index, message := range history {
		copyHistory[index] = message
		copyHistory[index].Contents = append([]AgentIContent(nil), message.Contents...)
	}
	return copyHistory
}

func validAgentISource(source AgentISource) bool {
	return source == AgentIChatTabSource || source == AgentIHomeTabSource || source == AgentINewsTabSource
}

func doWithoutRedirect(client HTTPDoer, request *http.Request) (*http.Response, error) {
	if standardClient, ok := client.(*http.Client); ok {
		copyClient := *standardClient
		copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return copyClient.Do(request)
	}
	return client.Do(request)
}
