// Package legy implements LINE's encrypted gateway wire protocol.
package legy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultEndpoint = "https://gf.line.naver.jp/enc"
	legyVersion     = "7"
	legyApplication = "5"
)

// HTTPDoer is the transport boundary used to send the encrypted request.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// ResponseTooLargeError reports an encrypted response that exceeds its limit.
type ResponseTooLargeError struct {
	Limit int64
}

func (e *ResponseTooLargeError) Error() string {
	return fmt.Sprintf("LEGY response exceeds %d bytes", e.Limit)
}

var legyIV = [aes.BlockSize]byte{
	78, 9, 72, 62, 56, 245, 255, 114,
	128, 18, 123, 158, 251, 92, 45, 51,
}

const lineLegyPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMC6HAYeMq4R59e2yRw6
W1OWT2t9aepiAp4fbSCXzRj7A29BOAFAvKlzAub4oxN13Nt8dbcB+ICAufyDnN5N
d3+vXgDxEXZ/sx2/wuFbC3B3evSNKR4hKcs80suRs8aL6EeWi+bAU2oYIc78Bbqh
Nzx0WCzZSJbMBFw1VlsU/HQ/XdiUufopl5QSa0S246XXmwJmmXRO0v7bNvrxaNV0
cbviGkOvTlBt1+RerIFHMTw3SwLDnCOolTz3CuE5V2OrPZCmC0nlmPRzwUfxoxxs
/6qFdpZNoORH/s5mQenSyqPkmH8TBOlHJWPH3eN1k6aZIlK5S54mcUb/oNRRq9wD
1wIDAQAB
-----END PUBLIC KEY-----`

// Transport encrypts LINE requests and unwraps LEGY responses.
type Transport struct {
	endpoint string
	aesKey   [16]byte
	public   *rsa.PublicKey
	mu       sync.Mutex
	xLcs     string
}

// ValidateEndpoint checks an optional LEGY gateway URL.
func ValidateEndpoint(value string) error {
	_, err := parseEndpoint(value)
	return err
}

func parseEndpoint(value string) (*url.URL, error) {
	if value == "" {
		value = defaultEndpoint
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("invalid LEGY endpoint: %w", err)
	}
	isHTTP := parsed.Scheme == "http"
	isHTTPS := parsed.Scheme == "https"
	hasInvalidEndpointParts := parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != ""
	if (!isHTTP && !isHTTPS) || hasInvalidEndpointParts {
		return nil, fmt.Errorf("LEGY endpoint must be an HTTP(S) URL without credentials, query, or fragment")
	}
	return parsed, nil
}

// NewTransport creates a LEGY session with an independent AES key.
func NewTransport(endpoint string) (*Transport, error) {
	parsed, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(lineLegyPublicKey))
	if block == nil {
		return nil, fmt.Errorf("decode embedded LEGY public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse embedded LEGY public key: %w", err)
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("embedded LEGY public key has type %T, want RSA", publicKey)
	}
	transport := &Transport{endpoint: parsed.String(), public: rsaPublicKey}
	if _, err := io.ReadFull(rand.Reader, transport.aesKey[:]); err != nil {
		return nil, fmt.Errorf("generate LEGY session key: %w", err)
	}
	return transport, nil
}

func (transport *Transport) Do(
	client HTTPDoer,
	inner *http.Request,
	payload []byte,
	maxResponseBytes int64,
) (*http.Response, error) {
	innerHeaders := make([]legyHeader, 0, 2)
	path := inner.URL.EscapedPath()
	if inner.URL.RawQuery != "" {
		path += "?" + inner.URL.RawQuery
	}
	innerHeaders = append(innerHeaders, legyHeader{key: "x-lpqs", value: path})
	if accessToken := inner.Header.Get("X-Line-Access"); accessToken != "" {
		innerHeaders = append(innerHeaders, legyHeader{
			key:   "x-lt",
			value: ResolveAccessToken(accessToken),
		})
	}
	plaintext, err := encodeLegyHeaders(innerHeaders, payload)
	if err != nil {
		return nil, fmt.Errorf("encode LEGY inner headers: %w", err)
	}
	plaintext = append([]byte{7}, plaintext...)
	encrypted, err := transport.encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	mac := legyHMAC(transport.aesKey[:], encrypted)
	encrypted = append(encrypted, mac...)

	xLcs, err := transport.encryptedSessionKey()
	if err != nil {
		return nil, err
	}
	outerRequest, err := http.NewRequestWithContext(
		inner.Context(),
		http.MethodPost,
		transport.endpoint,
		bytes.NewReader(encrypted),
	)
	if err != nil {
		return nil, fmt.Errorf("create LEGY request: %w", err)
	}
	outerRequest.Header = transport.outerHeaders(inner, xLcs)
	response, err := client.Do(outerRequest)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, fmt.Errorf("send LEGY request: %w", err)
	}
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("LEGY transport returned an empty response body")
	}
	defer response.Body.Close()
	reader, closeReader, err := responseReader(response)
	if err != nil {
		return nil, fmt.Errorf("read LEGY response: %w", err)
	}
	if closeReader != nil {
		defer closeReader()
	}
	const maxInt64 = int64(1<<63 - 1)
	outerLimit := maxResponseBytes
	if outerLimit <= maxInt64-4097 {
		outerLimit += 4096
	}
	readLimit := outerLimit
	if readLimit < maxInt64 {
		readLimit++
	}
	responseBody, err := io.ReadAll(io.LimitReader(reader, readLimit))
	if err != nil {
		return nil, fmt.Errorf("read LEGY response: %w", err)
	}
	if int64(len(responseBody)) > outerLimit {
		return nil, &ResponseTooLargeError{Limit: maxResponseBytes}
	}
	decrypted, err := transport.decrypt(responseBody)
	if err != nil {
		return nil, fmt.Errorf("decrypt LEGY response: %w", err)
	}
	if len(decrypted) == 0 || decrypted[0] != 7 {
		return nil, fmt.Errorf("LEGY response has an invalid version prefix")
	}
	decodedHeaders, body, err := decodeLegyHeaders(decrypted[1:])
	if err != nil {
		return nil, fmt.Errorf("decode LEGY response headers: %w", err)
	}
	if int64(len(body)) > maxResponseBytes {
		return nil, &ResponseTooLargeError{Limit: maxResponseBytes}
	}
	statusCode := response.StatusCode
	if lineCode := decodedHeaders["x-lc"]; lineCode != "" && lineCode != "200" {
		if parsed, parseErr := strconv.Atoi(lineCode); parseErr == nil {
			statusCode = parsed
		}
	}
	resultHeaders := response.Header.Clone()
	resultHeaders.Del("Content-Encoding")
	resultHeaders.Del("Content-Length")
	for key, value := range decodedHeaders {
		resultHeaders.Set(key, value)
	}
	resultHeaders.Set("Content-Type", "application/x-thrift")
	return &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Header:     resultHeaders,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    inner,
	}, nil
}

func (transport *Transport) outerHeaders(inner *http.Request, xLcs string) http.Header {
	headers := make(http.Header, 14)
	headers.Set("X-Line-Application", inner.Header.Get("X-Line-Application"))
	headers.Set("X-Le", legyVersion)
	headers.Set("X-Lap", legyApplication)
	lineVersion := inner.Header.Get("X-Lpv")
	if lineVersion == "" {
		lineVersion = "1"
	}
	headers.Set("X-Lpv", lineVersion)
	headers.Set("X-Lcs", xLcs)
	headers.Set("User-Agent", inner.Header.Get("User-Agent"))
	contentType := inner.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/x-thrift"
	}
	headers.Set("Content-Type", contentType)
	language := inner.Header.Get("X-Lal")
	if language == "" {
		language = "ja_JP"
	}
	headers.Set("X-Lal", language)
	httpMethod := inner.Header.Get("X-Lhm")
	if httpMethod == "" {
		httpMethod = inner.Method
	}
	headers.Set("X-Lhm", httpMethod)
	accept := inner.Header.Get("Accept")
	if accept == "" {
		accept = "*/*"
	}
	headers.Set("Accept", accept)
	headers.Set("Accept-Encoding", "gzip, deflate")
	headers.Set("Connection", "keep-alive")
	return headers
}

func (transport *Transport) encryptedSessionKey() (string, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.xLcs != "" {
		return transport.xLcs, nil
	}
	encrypted, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, transport.public, transport.aesKey[:], nil)
	if err != nil {
		return "", fmt.Errorf("encrypt LEGY session key: %w", err)
	}
	transport.xLcs = "0008" + base64.StdEncoding.EncodeToString(encrypted)
	return transport.xLcs, nil
}

func (transport *Transport) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(transport.aesKey[:])
	if err != nil {
		return nil, err
	}
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	plaintext = append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, legyIV[:]).CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func (transport *Transport) decrypt(ciphertext []byte) ([]byte, error) {
	blockLength := len(ciphertext) / aes.BlockSize * aes.BlockSize
	if blockLength == 0 {
		return nil, fmt.Errorf("ciphertext length %d is shorter than one AES block", len(ciphertext))
	}
	block, err := aes.NewCipher(transport.aesKey[:])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, blockLength)
	cipher.NewCBCDecrypter(block, legyIV[:]).CryptBlocks(plaintext, ciphertext[:blockLength])
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(plaintext) {
		return nil, fmt.Errorf("invalid PKCS7 padding length %d", padding)
	}
	for _, value := range plaintext[len(plaintext)-padding:] {
		if int(value) != padding {
			return nil, fmt.Errorf("invalid PKCS7 padding bytes")
		}
	}
	return plaintext[:len(plaintext)-padding], nil
}

type legyHeader struct {
	key   string
	value string
}

func encodeLegyHeaders(headers []legyHeader, body []byte) ([]byte, error) {
	if len(headers) > 65535 {
		return nil, fmt.Errorf("too many LEGY headers: %d", len(headers))
	}
	encoded := make([]byte, 2)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(headers)))
	for _, header := range headers {
		key := []byte(header.key)
		value := []byte(header.value)
		if len(key) > 65535 || len(value) > 65535 {
			return nil, fmt.Errorf("LEGY header %q exceeds the 16-bit length limit", header.key)
		}
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(key)))
		encoded = append(encoded, key...)
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(value)))
		encoded = append(encoded, value...)
	}
	headerLength := len(encoded) - 2
	if headerLength > 65535 {
		return nil, fmt.Errorf("encoded LEGY headers exceed the 16-bit length limit")
	}
	binary.BigEndian.PutUint16(encoded[:2], uint16(headerLength))
	return append(encoded, body...), nil
}

func decodeLegyHeaders(data []byte) (map[string]string, []byte, error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("header block is truncated")
	}
	blockLength := int(binary.BigEndian.Uint16(data[:2])) + 2
	if blockLength > len(data) {
		return nil, nil, fmt.Errorf("header block length %d exceeds payload size %d", blockLength, len(data))
	}
	count := int(binary.BigEndian.Uint16(data[2:4]))
	offset := 4
	headers := make(map[string]string, count)
	for index := 0; index < count; index++ {
		key, next, err := readLegyString(data[:blockLength], offset)
		if err != nil {
			return nil, nil, fmt.Errorf("read header %d key: %w", index, err)
		}
		offset = next
		value, next, err := readLegyString(data[:blockLength], offset)
		if err != nil {
			return nil, nil, fmt.Errorf("read header %d value: %w", index, err)
		}
		offset = next
		headers[key] = value
	}
	if offset != blockLength {
		return nil, nil, fmt.Errorf("header block has %d trailing bytes", blockLength-offset)
	}
	return headers, data[blockLength:], nil
}

func readLegyString(data []byte, offset int) (string, int, error) {
	if offset+2 > len(data) {
		return "", offset, fmt.Errorf("length prefix is truncated")
	}
	length := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	start := offset + 2
	end := start + length
	if end > len(data) {
		return "", offset, fmt.Errorf("value length %d exceeds remaining header bytes", length)
	}
	return string(data[start:end]), end, nil
}

func legyHMAC(key, data []byte) []byte {
	ipad := make([]byte, len(key))
	opad := make([]byte, len(key))
	for index, value := range key {
		ipad[index] = 0x36 ^ value
		opad[index] = 0x5c ^ value
	}
	innerInput := append(ipad, data...)
	innerDigest := xxhash32(innerInput)
	innerBytes := []byte{
		byte(innerDigest >> 24),
		byte(innerDigest >> 16),
		byte(innerDigest >> 8),
		byte(innerDigest),
	}
	outerDigest := xxhash32(append(opad, innerBytes...))
	mac := make([]byte, 4)
	binary.BigEndian.PutUint32(mac, outerDigest)
	return mac
}

func xxhash32(data []byte) uint32 {
	const (
		prime1 uint32 = 0x9e3779b1
		prime2 uint32 = 0x85ebca77
		prime3 uint32 = 0xc2b2ae3d
		prime4 uint32 = 0x27d4eb2f
		prime5 uint32 = 0x165667b1
	)
	length := len(data)
	offset := 0
	var hash uint32
	if length >= 16 {
		v1 := prime1
		v1 += prime2
		v2 := prime2
		v3 := uint32(0)
		v4 := uint32(0)
		v4 -= prime1
		limit := length - 16
		for offset <= limit {
			v1 = xxhashRound(v1, binary.LittleEndian.Uint32(data[offset:offset+4]))
			offset += 4
			v2 = xxhashRound(v2, binary.LittleEndian.Uint32(data[offset:offset+4]))
			offset += 4
			v3 = xxhashRound(v3, binary.LittleEndian.Uint32(data[offset:offset+4]))
			offset += 4
			v4 = xxhashRound(v4, binary.LittleEndian.Uint32(data[offset:offset+4]))
			offset += 4
		}
		hash = bits.RotateLeft32(v1, 1) + bits.RotateLeft32(v2, 7) + bits.RotateLeft32(v3, 12) + bits.RotateLeft32(v4, 18)
	} else {
		hash = prime5
	}
	hash += uint32(length)
	for offset <= length-4 {
		hash = bits.RotateLeft32(hash+binary.LittleEndian.Uint32(data[offset:offset+4])*prime3, 17) * prime4
		offset += 4
	}
	for offset < length {
		hash = bits.RotateLeft32(hash+uint32(data[offset])*prime5, 11) * prime1
		offset++
	}
	hash ^= hash >> 15
	hash *= prime2
	hash ^= hash >> 13
	hash *= prime3
	hash ^= hash >> 16
	return hash
}

func xxhashRound(accumulator, input uint32) uint32 {
	return bits.RotateLeft32(accumulator+input*0x85ebca77, 13) * 0x9e3779b1
}

// IsTalkPath reports whether path is one of LINEJS's LEGY-wrapped Talk routes.
func IsTalkPath(path string) bool {
	parsed, err := url.Parse(path)
	if err != nil {
		return false
	}
	switch parsed.Path {
	case "/S3", "/S4", "/V4", "/SYNC3", "/SYNC4", "/P4", "/P5", "/NP4", "/NP5", "/C5", "/CA5", "/ECA5":
		return true
	default:
		return false
	}
}

// ShouldEncryptAccess reports whether token requires automatic LEGY wrapping.
func ShouldEncryptAccess(token string) bool {
	value := strings.TrimSpace(token)
	if isLineJWT(value) {
		return true
	}
	colon := strings.IndexByte(value, ':')
	if colon < 0 {
		return false
	}
	payload := value[colon+1:]
	return isLineJWT(payload) || isPrimaryAccessToken(value) || isLineAuthKey(value)
}

// ResolveAccessToken converts LINE auth-key input into its request access token.
func ResolveAccessToken(token string) string {
	value := strings.TrimSpace(token)
	colon := strings.IndexByte(value, ':')
	if colon < 0 {
		return value
	}
	mid := value[:colon]
	payload := value[colon+1:]
	if isLineJWT(payload) {
		return payload
	}
	if isPrimaryAccessToken(value) || !isLineAuthKey(value) {
		return value
	}
	key, err := decodeBase64(payload)
	if err != nil || len(key) == 0 {
		return value
	}
	issuedAt := time.Now().Unix() / 60 * 60
	issued := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("iat: %d\n", issuedAt))) + "."
	signature := hmac.New(sha1.New, key)
	_, _ = signature.Write([]byte(issued))
	return mid + ":" + issued + base64.StdEncoding.EncodeToString(signature.Sum(nil))
}

func isPrimaryAccessToken(token string) bool {
	colon := strings.IndexByte(token, ':')
	if colon < 0 {
		return false
	}
	parts := strings.SplitN(token[colon+1:], ".", 2)
	if len(parts) == 0 {
		return false
	}
	decoded, err := decodeBase64(parts[0])
	return err == nil && bytes.HasPrefix(decoded, []byte("iat:"))
}

func isLineAuthKey(token string) bool {
	colon := strings.IndexByte(token, ':')
	if colon < 0 {
		return false
	}
	mid := token[:colon]
	if len(mid) != 33 || (mid[0] < 'a' || mid[0] > 'z') && (mid[0] < 'A' || mid[0] > 'Z') {
		return false
	}
	for _, char := range mid[1:] {
		isDigit := char >= '0' && char <= '9'
		isLowerHex := char >= 'a' && char <= 'f'
		isUpperHex := char >= 'A' && char <= 'F'
		if !isDigit && !isLowerHex && !isUpperHex {
			return false
		}
	}
	decoded, err := decodeBase64(token[colon+1:])
	return err == nil && len(decoded) > 0
}

func isLineJWT(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		return false
	}
	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		return false
	}
	var header map[string]any
	var payload map[string]any
	if jsonUnmarshal(headerBytes, &header) != nil || jsonUnmarshal(payloadBytes, &payload) != nil {
		return false
	}
	if _, ok := header["alg"].(string); !ok {
		return false
	}
	for _, key := range []string{"ver", "scp", "exp", "iat", "sub", "iss", "aud"} {
		if _, found := payload[key]; found {
			return true
		}
	}
	return false
}

func decodeBase64URL(value string) ([]byte, error) {
	value = strings.NewReplacer("-", "+", "_", "/").Replace(value)
	if remainder := len(value) % 4; remainder != 0 {
		value += strings.Repeat("=", 4-remainder)
	}
	return base64.StdEncoding.DecodeString(value)
}

func decodeBase64(value string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
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

func jsonUnmarshal(data []byte, target any) error {
	return json.Unmarshal(data, target)
}
