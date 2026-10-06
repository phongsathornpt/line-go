package base

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	cryptoe2ee "github.com/phongsathornpt/line-go/internal/crypto/e2ee"
	"github.com/phongsathornpt/line-go/thrift"
	"github.com/phongsathornpt/line-go/types"
)

const obsEndpoint = "https://obs.line-apps.com"

// ObjectType identifies the media class used by LINE's Object Storage Service.
type ObjectType string

const (
	ObjectImage ObjectType = "image"
	ObjectGIF   ObjectType = "gif"
	ObjectVideo ObjectType = "video"
	ObjectAudio ObjectType = "audio"
	ObjectFile  ObjectType = "file"
)

// ObjectUploadOptions describes an upload to an OBS service path.
type ObjectUploadOptions struct {
	Data     []byte
	Type     ObjectType
	Path     string
	Params   map[string]string
	Filename string
	Headers  http.Header
}

// ObjectUploadResult identifies an uploaded object and includes server headers.
type ObjectUploadResult struct {
	ObjectID string
	Hash     string
	Headers  http.Header
}

// ObjectDownloadOptions describes a download from an OBS service path.
type ObjectDownloadOptions struct {
	Path     string
	ObjectID string
	Headers  http.Header
}

// ObjectSize accepts the number or decimal string used by OBS metadata.
type ObjectSize int64

// UnmarshalJSON accepts either an integer or a decimal string.
func (s *ObjectSize) UnmarshalJSON(data []byte) error {
	var number json.Number
	if len(data) > 0 && data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		number = json.Number(value)
	} else {
		number = json.Number(string(data))
	}
	value, err := number.Int64()
	if err != nil {
		return fmt.Errorf("line OBS: invalid size %q: %w", number, err)
	}
	*s = ObjectSize(value)
	return nil
}

// ObjectMetadata is the metadata returned by OBS for a Talk or Square message.
type ObjectMetadata struct {
	Status        string           `json:"status"`
	Name          string           `json:"name"`
	MIME          string           `json:"mime"`
	Type          string           `json:"type"`
	Hash          string           `json:"hash"`
	Checksum      string           `json:"cksum"`
	Size          ObjectSize       `json:"size"`
	CreatedTimeMS int64            `json:"ctimeMillis"`
	ImageDetails  *ImageDetails    `json:"imageDetails,omitempty"`
	VideoDetails  *VideoMP4Details `json:"videoMp4Details,omitempty"`
	AudioDetails  *AudioM4ADetails `json:"audioM4aDetails,omitempty"`
	Service       string           `json:"svc"`
	Offset        int64            `json:"offset"`
	CreatedTime   string           `json:"ctime"`
	ObjectID      string           `json:"oid"`
	UserID        string           `json:"userid"`
	ServiceID     string           `json:"sid"`
}

// ImageDetails describes image dimensions and encoding reported by OBS.
type ImageDetails struct {
	Format    string `json:"format"`
	Height    int32  `json:"height"`
	Width     int32  `json:"width"`
	Signature string `json:"signature"`
}

// VideoMP4Details describes an MP4 video reported by OBS.
type VideoMP4Details struct {
	Size           int64  `json:"size"`
	DurationMillis int64  `json:"durationMillis"`
	Height         int32  `json:"height"`
	Width          int32  `json:"width"`
	Format         string `json:"format"`
	Status         string `json:"status"`
}

// AudioM4ADetails describes an M4A audio object reported by OBS.
type AudioM4ADetails struct {
	Size           int64  `json:"size"`
	DurationMillis int64  `json:"durationMillis"`
	Format         string `json:"format"`
	Status         string `json:"status"`
}

// DownloadedObject contains object bytes and their filename and MIME type.
type DownloadedObject struct {
	Data        []byte
	Filename    string
	ContentType string
}

// TalkMediaUploadOptions describes a non-E2EE Talk or Square media upload.
type TalkMediaUploadOptions struct {
	To          string
	Type        ObjectType
	Data        []byte
	ContentType string
	ObjectID    string
	Filename    string
	DurationMS  *int64
}

// E2EEMediaUploadOptions describes an encrypted Talk media upload.
type E2EEMediaUploadOptions struct {
	From        string
	To          string
	Type        ObjectType
	Data        []byte
	Preview     []byte
	ContentType string
	Filename    string
	DurationMS  *int64
}

// ObjectStorage implements LINE's OBS media upload and download protocol.
type ObjectStorage struct {
	client *BaseClient
}

type objectRequest struct {
	method  string
	path    string
	headers http.Header
	body    []byte
}

// OBS returns the Object Storage Service bound to this BaseClient.
func (c *BaseClient) OBS() *ObjectStorage {
	if c == nil {
		return nil
	}
	return c.obs
}

func (s *ObjectStorage) do(ctx context.Context, input objectRequest) (*http.Response, context.CancelFunc, error) {
	if s == nil || s.client == nil {
		return nil, nil, fmt.Errorf("line OBS: client is nil")
	}
	if ctx == nil {
		return nil, nil, fmt.Errorf("line OBS: context is nil")
	}
	if s.client.isClosed() {
		return nil, nil, ErrClientClosed
	}
	if s.client.AuthToken() == "" {
		return nil, nil, fmt.Errorf("line OBS: access token is empty")
	}
	requestURL, err := obsURL(input.path)
	if err != nil {
		return nil, nil, err
	}
	requestContext, cancel := context.WithTimeout(ctx, s.client.config.LongTimeout)
	request, err := http.NewRequestWithContext(requestContext, input.method, requestURL, bytes.NewReader(input.body))
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("line OBS: create request: %w", err)
	}
	request.Header = s.client.Headers(input.method)
	if input.headers != nil {
		for key, values := range input.headers {
			request.Header[key] = append([]string(nil), values...)
		}
	}
	response, err := s.client.httpClient.Do(request)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("line OBS: %s request: %w", strings.ToLower(input.method), err)
	}
	if response == nil || response.Body == nil {
		cancel()
		return nil, nil, fmt.Errorf("line OBS: transport returned an empty response")
	}
	if token := response.Header.Get("X-Line-Next-Access"); token != "" {
		s.client.SetAuthToken(token)
	}
	return response, cancel, nil
}

// UploadObjectForService uploads data to a service-specific OBS path.
func (s *ObjectStorage) UploadObjectForService(ctx context.Context, options ObjectUploadOptions) (*ObjectUploadResult, error) {
	if len(options.Data) == 0 {
		return nil, fmt.Errorf("line OBS upload: no data to send")
	}
	if options.Type == "" {
		options.Type = ObjectImage
	}
	if options.Path == "" {
		options.Path = "myhome/h"
	}
	if options.Filename == "" {
		id, err := randomObjectID()
		if err != nil {
			return nil, err
		}
		options.Filename = id
	}
	params := map[string]string{
		"type": strings.ToLower(string(options.Type)),
		"ver":  "2.0",
		"name": options.Filename,
	}
	for key, value := range options.Params {
		params[key] = value
	}
	encodedParams, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("line OBS upload: encode parameters: %w", err)
	}
	headers := cloneHTTPHeader(options.Headers)
	headers.Set("Content-Type", "application/octet-stream")
	headers.Set("X-Obs-Params", base64.StdEncoding.EncodeToString(encodedParams))
	response, cancel, err := s.do(ctx, objectRequest{
		method:  http.MethodPost,
		path:    "/r/" + options.Path,
		headers: headers,
		body:    options.Data,
	})
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer response.Body.Close()
	if err := obsResponseStatus(response, "object upload"); err != nil {
		return nil, err
	}
	return &ObjectUploadResult{
		ObjectID: response.Header.Get("X-Obs-Oid"),
		Hash:     response.Header.Get("X-Obs-Hash"),
		Headers:  response.Header.Clone(),
	}, nil
}

// DownloadObjectForService retrieves one object from a service-specific path.
func (s *ObjectStorage) DownloadObjectForService(ctx context.Context, options ObjectDownloadOptions) ([]byte, error) {
	if strings.TrimSpace(options.Path) == "" {
		return nil, fmt.Errorf("line OBS download: service path is empty")
	}
	if options.ObjectID == "" || strings.ContainsAny(options.ObjectID, "/\\?#") {
		return nil, fmt.Errorf("line OBS download: object ID is empty or invalid")
	}
	path := options.Path
	if strings.Contains(path, "{oid}") {
		path = strings.ReplaceAll(path, "{oid}", options.ObjectID)
	} else {
		path = strings.TrimRight(path, "/") + "/" + options.ObjectID
	}
	response, cancel, err := s.do(ctx, objectRequest{
		method:  http.MethodGet,
		path:    "/r/" + path,
		headers: options.Headers,
	})
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer response.Body.Close()
	if err := obsResponseStatus(response, "object download"); err != nil {
		return nil, err
	}
	return readOBSBody(response.Body, s.client.config.MaxResponseBytes)
}

// GetMessageDataURL returns the OBS URL for a Talk or Square message object.
func (s *ObjectStorage) GetMessageDataURL(messageID string, preview, square bool) string {
	service := "talk"
	if square {
		service = "g2"
	}
	path := obsEndpoint + "/r/" + service + "/m/" + messageID
	if preview {
		path += "/preview"
	}
	return path
}

// GetMessageMetadataURL returns the OBS metadata URL for a message object.
func (s *ObjectStorage) GetMessageMetadataURL(messageID string, square bool) string {
	service := "talk"
	if square {
		service = "g2"
	}
	return obsEndpoint + "/r/" + service + "/m/" + messageID + "/object_info.obs"
}

// GetMessageMetadata fetches metadata for a Talk or Square message object.
func (s *ObjectStorage) GetMessageMetadata(ctx context.Context, messageID string, square bool) (*ObjectMetadata, error) {
	if messageID == "" || strings.ContainsAny(messageID, "/\\?#") {
		return nil, fmt.Errorf("line OBS metadata: message ID is empty or invalid")
	}
	service := "talk"
	if square {
		service = "g2"
	}
	headers := make(http.Header)
	headers.Set("Accept", "application/json, text/plain, */*")
	response, cancel, err := s.do(ctx, objectRequest{
		method:  http.MethodGet,
		path:    "/r/" + service + "/m/" + messageID + "/object_info.obs",
		headers: headers,
	})
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer response.Body.Close()
	if err := obsResponseStatus(response, "message metadata request"); err != nil {
		return nil, err
	}
	body, err := readOBSBody(response.Body, s.client.config.MaxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("line OBS metadata: read response: %w", err)
	}
	var metadata ObjectMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("line OBS metadata: decode response: %w", err)
	}
	return &metadata, nil
}

// DownloadURL fetches externally hosted message content without LINE auth
// headers, matching LINEJS's direct fetch path for DOWNLOAD_URL metadata.
func (s *ObjectStorage) DownloadURL(ctx context.Context, target string) (*DownloadedObject, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("line media download: client is nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("line media download: context is nil")
	}
	if s.client.isClosed() {
		return nil, ErrClientClosed
	}
	parsed, err := url.ParseRequestURI(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("line media download: invalid content URL")
	}
	requestContext, cancel := context.WithTimeout(ctx, s.client.config.LongTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("line media download: create request: %w", err)
	}
	response, err := s.client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("line media download: request: %w", err)
	}
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("line media download: transport returned an empty response")
	}
	defer response.Body.Close()
	if err := obsResponseStatus(response, "content download"); err != nil {
		return nil, err
	}
	data, err := readOBSBody(response.Body, s.client.config.MaxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("line media download: read response: %w", err)
	}
	filename := filepath.Base(parsed.Path)
	if disposition := response.Header.Get("Content-Disposition"); disposition != "" {
		if _, params, parseErr := mime.ParseMediaType(disposition); parseErr == nil && params["filename"] != "" {
			filename = params["filename"]
		}
	}
	return &DownloadedObject{Data: data, Filename: filename, ContentType: response.Header.Get("Content-Type")}, nil
}

// DownloadMessageData downloads a non-E2EE message object and resolves its
// filename from the OBS metadata endpoint.
func (s *ObjectStorage) DownloadMessageData(ctx context.Context, messageID string, preview, square bool) (*DownloadedObject, error) {
	if messageID == "" || strings.ContainsAny(messageID, "/\\?#") {
		return nil, fmt.Errorf("line OBS download: message ID is empty or invalid")
	}
	service := "talk"
	if square {
		service = "g2"
	}
	path := "/r/" + service + "/m/" + messageID
	if preview {
		path += "/preview"
	}
	headers := make(http.Header)
	headers.Set("Accept", "application/json, text/plain, */*")
	response, cancel, err := s.do(ctx, objectRequest{
		method:  http.MethodGet,
		path:    path,
		headers: headers,
	})
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer response.Body.Close()
	if err := obsResponseStatus(response, "message data download"); err != nil {
		return nil, err
	}
	data, err := readOBSBody(response.Body, s.client.config.MaxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("line OBS message data: read response: %w", err)
	}
	metadata, err := s.GetMessageMetadata(ctx, messageID, square)
	if err != nil {
		return nil, err
	}
	contentType := metadata.MIME
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}
	return &DownloadedObject{Data: data, Filename: metadata.Name, ContentType: contentType}, nil
}

// UploadTalkObject uploads plain media for Talk or Square. An empty ObjectID
// uses LINE's reqseq mode, where the OBS service creates the message itself.
func (s *ObjectStorage) UploadTalkObject(ctx context.Context, options TalkMediaUploadOptions) (*ObjectUploadResult, error) {
	if options.To == "" {
		return nil, fmt.Errorf("line OBS upload: recipient is empty")
	}
	if options.Type != ObjectImage && options.Type != ObjectGIF && options.Type != ObjectVideo && options.Type != ObjectAudio && options.Type != ObjectFile {
		return nil, fmt.Errorf("line OBS upload: unsupported media type %q", options.Type)
	}
	extension := mediaExtension(options.Filename, options.ContentType)
	if options.Filename == "" {
		options.Filename = "line." + extension
	}
	sequence, err := s.client.GetReqseq(ctx, "talk")
	if err != nil {
		return nil, fmt.Errorf("line OBS upload: allocate request sequence: %w", err)
	}
	params := map[string]string{
		"ver":  "2.0",
		"name": options.Filename,
		"type": string(options.Type),
	}
	if options.Type == ObjectGIF {
		params["type"] = string(ObjectImage)
	}
	pathObjectID := options.ObjectID
	if pathObjectID == "" {
		pathObjectID = "reqseq"
		params["oid"] = "reqseq"
		params["tomid"] = options.To
		params["reqseq"] = strconv.FormatInt(int64(sequence), 10)
	} else {
		params["oid"] = options.ObjectID
	}
	if options.Type == ObjectImage || options.Type == ObjectGIF {
		params["cat"] = "original"
	}
	if options.Type == ObjectGIF {
		params["type"] = string(ObjectImage)
	}
	if options.Type == ObjectAudio || options.Type == ObjectVideo {
		duration := int64(1919)
		if options.DurationMS != nil {
			duration = *options.DurationMS
		}
		params["duration"] = strconv.FormatInt(duration, 10)
	}
	service := "talk"
	if options.To[0] == 'm' || options.To[0] == 't' {
		service = "g2"
	}
	return s.UploadObjectForService(ctx, ObjectUploadOptions{
		Data:     options.Data,
		Type:     options.Type,
		Path:     service + "/m/" + pathObjectID,
		Params:   params,
		Filename: options.Filename,
	})
}

// UploadMediaByE2EE encrypts, uploads, and sends a Talk media message.
func (s *ObjectStorage) UploadMediaByE2EE(ctx context.Context, options E2EEMediaUploadOptions) (*types.Message, error) {
	namespace, contentType, err := e2eeMediaType(options.Type)
	if err != nil {
		return nil, err
	}
	if options.From == "" || options.To == "" {
		return nil, fmt.Errorf("line OBS E2EE upload: sender and recipient MIDs are required")
	}
	if !isUserMID(options.To) && options.To[0] != 'c' {
		return nil, fmt.Errorf("line OBS E2EE upload: invalid recipient MID %q", options.To)
	}
	if len(options.Data) == 0 {
		return nil, fmt.Errorf("line OBS E2EE upload: no data to send")
	}
	extension := mediaExtension(options.Filename, options.ContentType)
	filename := options.Filename
	if filename == "" {
		filename = "line." + extension
	}
	keyMaterial := []byte(nil)
	encryptedData, keyMaterial, err := cryptoe2ee.EncryptMedia(options.Data, keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("line OBS E2EE upload: encrypt media: %w", err)
	}
	objectParams := map[string]string{"type": string(ObjectFile)}
	if options.Type == ObjectGIF {
		objectParams["cat"] = "original"
	}
	requestID, err := randomObjectID()
	if err != nil {
		return nil, err
	}
	mediaPath := "talk/" + namespace + "/reqid-" + requestID
	uploaded, err := s.UploadObjectForService(ctx, ObjectUploadOptions{
		Data:   encryptedData,
		Type:   ObjectFile,
		Path:   mediaPath,
		Params: objectParams,
	})
	if err != nil {
		return nil, fmt.Errorf("line OBS E2EE upload: upload media: %w", err)
	}
	if uploaded.ObjectID == "" {
		return nil, fmt.Errorf("line OBS E2EE upload: response has no object ID")
	}
	if options.Type == ObjectImage || options.Type == ObjectGIF || options.Type == ObjectVideo {
		previewData := encryptedData
		if len(options.Preview) > 0 {
			previewData, _, err = cryptoe2ee.EncryptMedia(options.Preview, keyMaterial)
			if err != nil {
				return nil, fmt.Errorf("line OBS E2EE upload: encrypt preview: %w", err)
			}
		}
		previewUpload, err := s.UploadObjectForService(ctx, ObjectUploadOptions{
			Data:   previewData,
			Type:   ObjectFile,
			Path:   "talk/" + namespace + "/" + uploaded.ObjectID + "__ud-preview",
			Params: objectParams,
		})
		if err != nil {
			return nil, fmt.Errorf("line OBS E2EE upload: upload preview: %w", err)
		}
		if previewUpload.ObjectID != uploaded.ObjectID {
			return nil, fmt.Errorf("line OBS E2EE upload: preview object ID %q differs from media object ID %q", previewUpload.ObjectID, uploaded.ObjectID)
		}
	}
	metadata := map[string]string{
		"SID":         namespace,
		"OID":         uploaded.ObjectID,
		"FILE_SIZE":   strconv.Itoa(len(encryptedData)),
		"e2eeVersion": "2",
	}
	if options.Type == ObjectImage || options.Type == ObjectGIF || options.Type == ObjectVideo {
		mediaInfo, err := json.Marshal(map[string]any{
			"category":  "original",
			"fileSize":  len(encryptedData),
			"extension": extension,
			"animated":  options.Type == ObjectGIF,
		})
		if err != nil {
			return nil, fmt.Errorf("line OBS E2EE upload: encode media metadata: %w", err)
		}
		metadata["MEDIA_CONTENT_INFO"] = string(mediaInfo)
	}
	if options.Type == ObjectVideo && options.DurationMS != nil && *options.DurationMS > 0 {
		metadata["DURATION"] = strconv.FormatInt(*options.DurationMS, 10)
	}
	descriptor := map[string]string{
		"keyMaterial": base64.StdEncoding.EncodeToString(keyMaterial),
		"fileName":    filename,
	}
	encryptedMessage, err := s.client.E2EE().EncryptMessage(ctx, options.From, options.To, descriptor, contentType, metadata)
	if err != nil {
		return nil, fmt.Errorf("line OBS E2EE upload: encrypt message descriptor: %w", err)
	}
	message, err := s.client.Talk().SendMessage(ctx, SendMessageOptions{
		From:            options.From,
		To:              options.To,
		ContentType:     contentType,
		ContentMetadata: encryptedMessage.ContentMetadata,
		Chunks:          encryptedMessage.Chunks,
	})
	if err != nil {
		return nil, fmt.Errorf("line OBS E2EE upload: send message: %w", err)
	}
	return message, nil
}

// DownloadMediaByE2EE retrieves and decrypts an encrypted Talk media message.
func (s *ObjectStorage) DownloadMediaByE2EE(ctx context.Context, selfMID string, message *types.Message) (*DownloadedObject, error) {
	if message == nil || message.Id == nil || message.ContentMetadata == nil {
		return nil, fmt.Errorf("line OBS E2EE download: message is missing ID or content metadata")
	}
	if message.To == nil || (!isUserMID(*message.To) && !strings.HasPrefix(*message.To, "c")) {
		return nil, fmt.Errorf("line OBS E2EE download: message has an unsupported recipient MID")
	}
	media, err := s.client.E2EE().DecryptMediaMessageData(ctx, selfMID, message)
	if err != nil {
		return nil, err
	}
	keyMaterial, err := base64.StdEncoding.DecodeString(media.KeyMaterial)
	if err != nil {
		return nil, fmt.Errorf("line OBS E2EE download: decode key material: %w", err)
	}
	objectID := message.ContentMetadata["OID"]
	serviceID := message.ContentMetadata["SID"]
	if objectID == "" || serviceID == "" {
		return nil, fmt.Errorf("line OBS E2EE download: message is missing OID or SID metadata")
	}
	talkMeta, err := encodeTalkMetadata(*message.Id)
	if err != nil {
		return nil, err
	}
	headers := make(http.Header)
	headers.Set("X-Talk-Meta", talkMeta)
	encrypted, err := s.DownloadObjectForService(ctx, ObjectDownloadOptions{
		Path:     "talk/" + serviceID,
		ObjectID: objectID,
		Headers:  headers,
	})
	if err != nil {
		return nil, fmt.Errorf("line OBS E2EE download: fetch media: %w", err)
	}
	data, err := cryptoe2ee.DecryptMedia(encrypted, keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("line OBS E2EE download: decrypt media: %w", err)
	}
	contentType := mime.TypeByExtension(filepath.Ext(media.FileName))
	return &DownloadedObject{Data: data, Filename: media.FileName, ContentType: contentType}, nil
}

func obsURL(path string) (string, error) {
	trimmed := strings.TrimLeft(path, "/")
	if trimmed == "" {
		return "", fmt.Errorf("line OBS: path is empty")
	}
	for _, segment := range strings.Split(trimmed, "/") {
		if segment == ".." || segment == "." || segment == "" {
			return "", fmt.Errorf("line OBS: invalid path %q", path)
		}
	}
	parsed := url.URL{Scheme: "https", Host: "obs.line-apps.com", Path: "/" + trimmed}
	return parsed.String(), nil
}

func obsResponseStatus(response *http.Response, operation string) error {
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("line OBS %s failed: HTTP %d", operation, response.StatusCode)
	}
	return nil
}

func readOBSBody(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &ResponseTooLargeError{Limit: limit}
	}
	return data, nil
}

func cloneHTTPHeader(headers http.Header) http.Header {
	if headers == nil {
		return make(http.Header)
	}
	return headers.Clone()
}

func mediaExtension(filename, contentType string) string {
	if extension := strings.TrimPrefix(filepath.Ext(filename), "."); extension != "" {
		return extension
	}
	if contentType == "" {
		return "bin"
	}
	if extension := map[string]string{
		"image/jpeg": "jpg",
		"image/png":  "png",
		"image/gif":  "gif",
		"video/mp4":  "mp4",
		"audio/mp4":  "m4a",
		"audio/mpeg": "mp3",
	}[strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))]; extension != "" {
		return extension
	}
	extensions, err := mime.ExtensionsByType(contentType)
	if err != nil || len(extensions) == 0 {
		return "bin"
	}
	return strings.TrimPrefix(extensions[0], ".")
}

func e2eeMediaType(mediaType ObjectType) (string, types.ContentType, error) {
	switch mediaType {
	case ObjectImage, ObjectGIF:
		return "emi", types.ContentTypeIMAGE, nil
	case ObjectVideo:
		return "emv", types.ContentTypeVIDEO, nil
	case ObjectAudio:
		return "ema", types.ContentTypeAUDIO, nil
	case ObjectFile:
		return "emf", types.ContentTypeFILE, nil
	default:
		return "", 0, fmt.Errorf("line OBS E2EE upload: unsupported media type %q", mediaType)
	}
}

func randomObjectID() (string, error) {
	var identifier [16]byte
	if _, err := rand.Read(identifier[:]); err != nil {
		return "", fmt.Errorf("line OBS: generate object ID: %w", err)
	}
	identifier[6] = identifier[6]&0x0f | 0x40
	identifier[8] = identifier[8]&0x3f | 0x80
	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], identifier[0:4])
	hex.Encode(encoded[9:13], identifier[4:6])
	hex.Encode(encoded[14:18], identifier[6:8])
	hex.Encode(encoded[19:23], identifier[8:10])
	hex.Encode(encoded[24:36], identifier[10:16])
	encoded[8], encoded[13], encoded[18], encoded[23] = '-', '-', '-', '-'
	return string(encoded), nil
}

func encodeTalkMetadata(messageID string) (string, error) {
	encoded, err := thrift.MarshalBinaryStruct(thrift.StructValue{
		{ID: 4, Value: thrift.StringValue(messageID)},
		{ID: 27, Value: thrift.ListValue{ElementType: thrift.TypeStruct, Values: []thrift.Value{}}},
	})
	if err != nil {
		return "", fmt.Errorf("line OBS E2EE download: encode talk metadata: %w", err)
	}
	outer, err := json.Marshal(map[string]string{"message": base64.StdEncoding.EncodeToString(encoded)})
	if err != nil {
		return "", fmt.Errorf("line OBS E2EE download: encode talk metadata envelope: %w", err)
	}
	return base64.StdEncoding.EncodeToString(outer), nil
}
