package base

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/phongsathornpt/line-go/internal/protocol/legy"
	"github.com/phongsathornpt/line-go/thrift"
)

// Request writes one LINEJS Thrift request and decodes its response envelope.
func (c *BaseClient) Request(ctx context.Context, options RequestOptions, args thrift.StructValue) (Response, error) {
	if c.isClosed() {
		return Response{}, ErrClientClosed
	}
	if options.Method == "" {
		return Response{}, fmt.Errorf("line request: method is empty")
	}
	if options.Path == "" {
		options.Path = "/S3"
	}
	requestURL, err := c.requestURL(options.Path)
	if err != nil {
		return Response{}, err
	}

	protocolType := options.Protocol
	if protocolType == 0 {
		protocolType = thrift.ProtocolBinary
	}
	payload, err := thrift.MarshalRequest(protocolType, options.Method, args)
	if err != nil {
		return Response{}, fmt.Errorf("line request %s: encode Thrift request: %w", options.Method, err)
	}

	httpMethod := options.HTTPMethod
	if httpMethod == "" {
		httpMethod = http.MethodPost
	}
	requestContext := ctx
	timeout := options.Timeout
	if timeout == 0 {
		timeout = c.config.Timeout
		if options.Long {
			timeout = c.config.LongTimeout
		}
	}
	if timeout < 0 {
		return Response{}, fmt.Errorf("line request %s: timeout cannot be negative", options.Method)
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		requestContext, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	request, err := http.NewRequestWithContext(requestContext, httpMethod, requestURL, bytes.NewReader(payload))
	if err != nil {
		return Response{}, fmt.Errorf("line request %s: create HTTP request: %w", options.Method, err)
	}
	request.Host = c.endpoint.Host
	request.Header = c.Headers(httpMethod)
	for key, values := range options.Headers {
		if strings.EqualFold(key, "Host") {
			if len(values) > 0 {
				request.Host = values[len(values)-1]
			}
			continue
		}
		request.Header[key] = append([]string(nil), values...)
	}

	var response *http.Response
	if c.shouldUseLegy(request.URL.Path, request.Header.Get("X-Line-Access")) {
		transport, transportErr := c.getLegyTransport()
		if transportErr != nil {
			return Response{}, fmt.Errorf("line request %s: initialize LEGY transport: %w", options.Method, transportErr)
		}
		response, err = transport.Do(c.httpClient, request, payload, c.config.MaxResponseBytes)
		var legyTooLarge *legy.ResponseTooLargeError
		if errors.As(err, &legyTooLarge) {
			return Response{}, &ResponseTooLargeError{Limit: legyTooLarge.Limit}
		}
	} else {
		response, err = c.httpClient.Do(request)
	}
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return Response{}, fmt.Errorf("line request %s %s: send HTTP request: %w", options.Method, options.Path, err)
	}
	if response == nil || response.Body == nil {
		return Response{}, fmt.Errorf(
			"line request %s %s: transport returned an empty response body",
			options.Method,
			options.Path,
		)
	}
	defer response.Body.Close()
	if nextToken := response.Header.Get("X-Line-Next-Access"); nextToken != "" {
		c.SetAuthToken(nextToken)
	}

	reader, closeReader, err := responseReader(response)
	if err != nil {
		return Response{}, fmt.Errorf("line request %s %s: read HTTP response: %w", options.Method, options.Path, err)
	}
	if closeReader != nil {
		defer closeReader()
	}
	body, err := io.ReadAll(io.LimitReader(reader, c.config.MaxResponseBytes+1))
	if err != nil {
		return Response{}, fmt.Errorf("line request %s %s: read HTTP response: %w", options.Method, options.Path, err)
	}
	if int64(len(body)) > c.config.MaxResponseBytes {
		return Response{}, &ResponseTooLargeError{Limit: c.config.MaxResponseBytes}
	}

	message, err := thrift.UnmarshalMessage(protocolType, body)
	if err != nil {
		return Response{}, fmt.Errorf(
			"line request %s %s: decode thrift response (HTTP %d): %w",
			options.Method,
			options.Path,
			response.StatusCode,
			err,
		)
	}
	return Response{
		Message:    message,
		StatusCode: response.StatusCode,
		Headers:    response.Header.Clone(),
	}, nil
}

// RequestTyped encodes a tagged args DTO, sends the request, and optionally
// decodes the Thrift result envelope into result, which must be a pointer to a
// generated DTO. Passing a nil result returns the raw response only.
func (c *BaseClient) RequestTyped(ctx context.Context, options RequestOptions, args any, result any) (Response, error) {
	encodedArgs, err := thrift.MarshalArgs(args)
	if err != nil {
		return Response{}, fmt.Errorf("line request %s: encode args DTO: %w", options.Method, err)
	}
	response, err := c.Request(ctx, options, encodedArgs)
	if err != nil {
		return Response{}, err
	}
	if result != nil {
		if err := thrift.UnmarshalStructValue(response.Message.Args, result); err != nil {
			return Response{}, fmt.Errorf("line request %s: decode result DTO: %w", options.Method, err)
		}
	}
	return response, nil
}

func (c *BaseClient) requestURL(path string) (string, error) {
	parsedPath, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("line request: invalid path %q: %w", path, err)
	}
	isExternal := parsedPath.IsAbs() || parsedPath.Host != ""
	isInvalidPath := !strings.HasPrefix(parsedPath.Path, "/") || parsedPath.Fragment != ""
	if isExternal || isInvalidPath {
		return "", fmt.Errorf("line request: path must be an absolute path on the configured endpoint")
	}
	endpoint := *c.endpoint
	endpoint.Path = parsedPath.Path
	endpoint.RawPath = parsedPath.RawPath
	endpoint.RawQuery = parsedPath.RawQuery
	return endpoint.String(), nil
}

func responseReader(response *http.Response) (io.Reader, func() error, error) {
	contentEncoding := strings.TrimSpace(strings.ToLower(response.Header.Get("Content-Encoding")))
	switch contentEncoding {
	case "", "identity":
		return response.Body, nil, nil
	case "gzip":
		reader, err := gzip.NewReader(response.Body)
		if err != nil {
			return nil, nil, err
		}
		return reader, reader.Close, nil
	case "deflate":
		buffered := bufio.NewReader(response.Body)
		prefix, err := buffered.Peek(2)
		if err != nil {
			return nil, nil, err
		}
		if prefix[0]&0x0f == 8 && (int(prefix[0])<<8|int(prefix[1]))%31 == 0 {
			reader, err := zlib.NewReader(buffered)
			if err != nil {
				return nil, nil, err
			}
			return reader, reader.Close, nil
		}
		reader := flate.NewReader(buffered)
		return reader, reader.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported content encoding %q", contentEncoding)
	}
}
