package push

import (
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HTTPDoer is implemented by net/http.Client and compatible custom transports.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Conn owns one persistent push request and its bounded incoming frame stream.
type Conn struct {
	writeMu sync.Mutex
	close   sync.Once
	cancel  context.CancelFunc
	body    *io.PipeWriter
	frames  chan Frame
	closed  chan struct{}
	errMu   sync.Mutex
	err     error
}

// Connect opens LINE's long-lived push endpoint. The returned connection is
// closed when ctx is canceled or Close is called. connectTimeout bounds only
// establishment; it does not limit the lifetime of the stream.
func Connect(
	ctx context.Context,
	client HTTPDoer,
	endpoint string,
	headers http.Header,
	services []uint8,
	connectTimeout time.Duration,
) (*Conn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("line push: context is nil")
	}
	if client == nil {
		return nil, fmt.Errorf("line push: HTTP transport is nil")
	}
	if headers == nil || headers.Get("X-Line-Access") == "" {
		return nil, fmt.Errorf("line push: access token is empty")
	}
	mask, err := ServiceMask(services)
	if err != nil {
		return nil, err
	}
	requestURL, err := pushURL(endpoint, mask)
	if err != nil {
		return nil, err
	}

	streamCtx, cancel := context.WithCancel(ctx)
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(streamCtx, http.MethodPost, requestURL, reader)
	if err != nil {
		cancel()
		reader.Close()
		writer.Close()
		return nil, fmt.Errorf("line push: create request: %w", err)
	}
	request.Header = headers.Clone()
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Lhm", "POST")

	type connectResult struct {
		response *http.Response
		err      error
	}
	connected := make(chan connectResult, 1)
	go func() {
		response, err := client.Do(request)
		connected <- connectResult{response: response, err: err}
	}()

	if connectTimeout <= 0 {
		connectTimeout = 15 * time.Second
	}
	timer := time.NewTimer(connectTimeout)
	defer timer.Stop()
	var response *http.Response
	select {
	case result := <-connected:
		if result.err != nil {
			cancel()
			reader.Close()
			writer.Close()
			return nil, fmt.Errorf("line push: connect: %w", result.err)
		}
		response = result.response
	case <-timer.C:
		cancel()
		reader.Close()
		writer.Close()
		return nil, fmt.Errorf("line push: connect timed out after %s", connectTimeout)
	case <-ctx.Done():
		cancel()
		reader.Close()
		writer.Close()
		return nil, ctx.Err()
	}
	if response == nil || response.Body == nil {
		cancel()
		reader.Close()
		writer.Close()
		return nil, fmt.Errorf("line push: server returned no response body")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		response.Body.Close()
		cancel()
		reader.Close()
		writer.Close()
		return nil, fmt.Errorf("line push: server returned HTTP %d", response.StatusCode)
	}
	if response.ProtoMajor != 2 {
		response.Body.Close()
		cancel()
		reader.Close()
		writer.Close()
		return nil, fmt.Errorf("line push: server negotiated HTTP/%d, want HTTP/2", response.ProtoMajor)
	}
	streamBody, err := decompressPushBody(response)
	if err != nil {
		response.Body.Close()
		cancel()
		reader.Close()
		writer.Close()
		return nil, err
	}
	conn := &Conn{
		cancel: cancel,
		body:   writer,
		frames: make(chan Frame, 32),
		closed: make(chan struct{}),
	}
	go conn.readFrames(streamBody)
	return conn, nil
}

// Frames returns the bounded stream of decoded packets. The channel closes
// when the connection ends; inspect Err for its terminal read error.
func (c *Conn) Frames() <-chan Frame {
	return c.frames
}

// Err returns the terminal stream error, if any.
func (c *Conn) Err() error {
	c.errMu.Lock()
	err := c.err
	c.errMu.Unlock()
	return err
}

// WriteFrame encodes and writes one packet to the persistent request body.
func (c *Conn) WriteFrame(ctx context.Context, frame Frame) error {
	if c == nil || c.body == nil {
		return fmt.Errorf("line push: connection is nil")
	}
	if ctx == nil {
		return fmt.Errorf("line push: write context is nil")
	}
	encoded, err := frame.Encode()
	if err != nil {
		return err
	}
	writeDone := make(chan error, 1)
	go func() {
		c.writeMu.Lock()
		_, err := c.body.Write(encoded)
		c.writeMu.Unlock()
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			return fmt.Errorf("line push: write frame: %w", err)
		}
		return nil
	case <-ctx.Done():
		_ = c.Close()
		return ctx.Err()
	case <-c.closed:
		if err := c.Err(); err != nil {
			return err
		}
		return io.ErrClosedPipe
	}
}

// Close cancels the HTTP/2 stream and closes both directions.
func (c *Conn) Close() error {
	if c == nil {
		return nil
	}
	var closeErr error
	c.close.Do(func() {
		close(c.closed)
		c.cancel()
		if c.body != nil {
			closeErr = c.body.Close()
		}
	})
	return closeErr
}

func (c *Conn) readFrames(body io.ReadCloser) {
	defer close(c.frames)
	defer body.Close()
	for {
		var header [3]byte
		if _, err := io.ReadFull(body, header[:]); err != nil {
			if err != io.EOF && !c.isClosed() {
				c.setErr(fmt.Errorf("line push: read frame header: %w", err))
			}
			return
		}
		length := int(binary.BigEndian.Uint16(header[:2]))
		payload := make([]byte, length)
		if _, err := io.ReadFull(body, payload); err != nil {
			if !c.isClosed() {
				c.setErr(fmt.Errorf("line push: read frame payload: %w", err))
			}
			return
		}
		frame := Frame{Type: FrameType(header[2]), Payload: payload}
		select {
		case c.frames <- frame:
		case <-c.closed:
			return
		}
	}
}

func (c *Conn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *Conn) setErr(err error) {
	c.errMu.Lock()
	c.err = err
	c.errMu.Unlock()
}

func pushURL(endpoint string, mask uint32) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("line push: parse endpoint: %w", err)
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("line push: endpoint must be an HTTPS host")
	}
	parsed.Path = "/PUSH/1/subs"
	parsed.RawPath = ""
	parsed.RawQuery = "m=" + strconv.FormatUint(uint64(mask), 10)
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

type pushBody struct {
	reader io.Reader
	close  func() error
}

func (b pushBody) Read(data []byte) (int, error) {
	return b.reader.Read(data)
}

func (b pushBody) Close() error {
	return b.close()
}

func decompressPushBody(response *http.Response) (io.ReadCloser, error) {
	encoding := strings.TrimSpace(strings.ToLower(response.Header.Get("Content-Encoding")))
	switch encoding {
	case "", "identity":
		return response.Body, nil
	case "gzip":
		reader, err := gzip.NewReader(response.Body)
		if err != nil {
			return nil, fmt.Errorf("line push: open gzip stream: %w", err)
		}
		return pushBody{reader: reader, close: func() error {
			readerErr := reader.Close()
			bodyErr := response.Body.Close()
			if readerErr != nil {
				return readerErr
			}
			return bodyErr
		}}, nil
	default:
		return nil, fmt.Errorf("line push: unsupported content encoding %q", encoding)
	}
}
