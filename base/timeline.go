package base

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phongsathornpt/line-go/types"
)

const timelineChannelID = "1341209850"

// TimelineResponse is the JSON envelope returned by LINE's Timeline API.
// Result stays as raw JSON because the endpoint's payload varies by operation.
type TimelineResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Result  json.RawMessage `json:"result"`
}

// TimelineService calls LINE's JSON-based Timeline and VOOM endpoints.
type TimelineService struct {
	client *BaseClient
	mu     sync.Mutex
	token  string
}

// TimelinePostOptions describes the content and audience of a new post.
type TimelinePostOptions struct {
	HomeID             string
	Text               *string
	SharedPostID       *string
	TextSizeMode       string
	BackgroundColor    string
	TextAnimation      string
	ReadPermissionType string
	ReadPermissionGIDs []string
	HoldingTime        *int64
	StickerIDs         []string
	StickerPackageIDs  []string
	LocationLatitudes  []float64
	LocationLongitudes []float64
	LocationNames      []string
	MediaObjectIDs     []string
	MediaObjectTypes   []string
	SourceType         string
}

// TimelineUpdatePostOptions describes changes to an existing post.
type TimelineUpdatePostOptions struct {
	HomeID             string
	PostID             string
	Text               *string
	SharedPostID       *string
	TextSizeMode       string
	BackgroundColor    string
	TextAnimation      string
	HoldingTime        *int64
	StickerIDs         []string
	StickerPackageIDs  []string
	LocationLatitudes  []float64
	LocationLongitudes []float64
	LocationNames      []string
	MediaObjectIDs     []string
	MediaObjectTypes   []string
}

// TimelineListPostOptions controls pagination and source selection.
type TimelineListPostOptions struct {
	HomeID      string
	PostID      string
	UpdatedTime *int64
	SourceType  string
}

// TimelineLikePostOptions describes a reaction to a post.
type TimelineLikePostOptions struct {
	HomeID     string
	ContentID  string
	LikeType   string
	SourceType string
}

// TimelineCommentOptions describes a comment. ContentsList accepts pre-encoded
// JSON entries for rich comment attachments.
type TimelineCommentOptions struct {
	HomeID       string
	ContentID    string
	CommentText  string
	SourceType   string
	ContentsList []json.RawMessage
}

// TimelineSharePostOptions shares a post into a Talk chat.
type TimelineSharePostOptions struct {
	HomeID  string
	PostID  string
	ChatMID string
}

// TimelineMediaType selects the legacy Note media upload format.
type TimelineMediaType string

const (
	TimelineMediaImage TimelineMediaType = "image"
	TimelineMediaVideo TimelineMediaType = "video"
)

// TimelineMediaUploadResult identifies an uploaded Note attachment.
type TimelineMediaUploadResult struct {
	ObjectID string
	Hash     string
}

// InitTimeline issues the channel token required by Timeline endpoints.
func (s *TimelineService) InitTimeline(ctx context.Context) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("line timeline: client is nil")
	}
	if ctx == nil {
		return fmt.Errorf("line timeline: context is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" {
		return nil
	}
	if s.client.ProfileMID() == "" {
		return fmt.Errorf("line timeline: profile MID is required; call SetProfileMID after login")
	}
	result, err := s.client.Channel().ApproveChannelAndIssueChannelToken(ctx, types.ApproveChannelAndIssueChannelTokenArgs{
		ChannelId: stringPointer(timelineChannelID),
	})
	if err != nil {
		return fmt.Errorf("line timeline: issue channel token: %w", err)
	}
	if result.Success == nil || result.Success.ChannelAccessToken == nil || *result.Success.ChannelAccessToken == "" {
		return fmt.Errorf("line timeline: channel token response is empty")
	}
	s.token = *result.Success.ChannelAccessToken
	return nil
}

// CreatePost creates a Timeline post and its optional text, media, stickers,
// locations, and visibility settings.
func (s *TimelineService) CreatePost(ctx context.Context, options TimelinePostOptions) (*TimelineResponse, error) {
	if err := validateTimelinePostArrays(options.StickerIDs, options.StickerPackageIDs, options.LocationLatitudes, options.LocationLongitudes, options.LocationNames, options.MediaObjectIDs, options.MediaObjectTypes); err != nil {
		return nil, err
	}
	if options.HomeID == "" {
		return nil, fmt.Errorf("line timeline: home ID is empty")
	}
	if strings.HasPrefix(options.HomeID, "u") {
		return nil, fmt.Errorf("line timeline: personal one-to-one posts are unsupported")
	}
	textSize := defaultString(options.TextSizeMode, "NORMAL")
	background := defaultString(options.BackgroundColor, "#FFFFFF")
	animation := defaultString(options.TextAnimation, "NONE")
	permission := defaultString(options.ReadPermissionType, "ALL")
	source := defaultString(options.SourceType, "TIMELINE")
	postInfo := map[string]any{"readPermission": map[string]any{
		"type": permission,
		"gids": nonNilStrings(options.ReadPermissionGIDs),
	}}
	if options.HoldingTime != nil {
		postInfo["holdingTime"] = *options.HoldingTime
	}
	contents := map[string]any{
		"contentsStyle": map[string]any{
			"textStyle":  map[string]any{"textSizeMode": textSize, "backgroundColor": background, "textAnimation": animation},
			"mediaStyle": map[string]any{"displayType": "GRID_1_A"},
		},
		"stickers":  makeTimelineStickers(options.StickerIDs, options.StickerPackageIDs),
		"locations": makeTimelineLocations(options.LocationLatitudes, options.LocationLongitudes, options.LocationNames),
		"media":     makeTimelineMedia(options.MediaObjectIDs, options.MediaObjectTypes),
	}
	if options.Text != nil {
		contents["text"] = *options.Text
	}
	if options.SharedPostID != nil {
		contents["sharedPostId"] = *options.SharedPostID
	}
	body, err := json.Marshal(map[string]any{"postInfo": postInfo, "contents": contents})
	if err != nil {
		return nil, fmt.Errorf("line timeline: encode post: %w", err)
	}
	query := url.Values{"homeId": {options.HomeID}, "sourceType": {source}}
	return s.doJSON(ctx, http.MethodPost, "POST", timelineHomePath(options.HomeID)+"/api/v57/post/create.json", query, body)
}

// DeletePost deletes one post.
func (s *TimelineService) DeletePost(ctx context.Context, homeID, postID string) (*TimelineResponse, error) {
	if err := validateTimelineIDs(homeID, postID); err != nil {
		return nil, err
	}
	query := url.Values{"homeId": {homeID}, "postId": {postID}}
	return s.doJSON(ctx, http.MethodPost, "GET", timelineHomePath(homeID)+"/api/v57/post/delete.json", query, nil)
}

// GetPost fetches one post.
func (s *TimelineService) GetPost(ctx context.Context, homeID, postID string) (*TimelineResponse, error) {
	if err := validateTimelineIDs(homeID, postID); err != nil {
		return nil, err
	}
	query := url.Values{"homeId": {homeID}, "postId": {postID}}
	return s.doJSON(ctx, http.MethodGet, "GET", timelineHomePath(homeID)+"/api/v57/post/get.json", query, nil)
}

// ListPost fetches posts in a Timeline home or Talk room.
func (s *TimelineService) ListPost(ctx context.Context, options TimelineListPostOptions) (*TimelineResponse, error) {
	if options.HomeID == "" {
		return nil, fmt.Errorf("line timeline: home ID is empty")
	}
	query := url.Values{
		"homeId":       {options.HomeID},
		"sourceType":   {defaultString(options.SourceType, "TALKROOM")},
		"likeLimit":    {"0"},
		"commentLimit": {"0"},
	}
	if options.PostID != "" {
		query.Set("postId", options.PostID)
	}
	if options.UpdatedTime != nil && *options.UpdatedTime != 0 {
		query.Set("updatedTime", strconv.FormatInt(*options.UpdatedTime, 10))
	}
	return s.doJSON(ctx, http.MethodGet, "GET", timelineHomePath(options.HomeID)+"/api/v57/post/list.json", query, nil)
}

// UpdatePost updates an existing post's contents.
func (s *TimelineService) UpdatePost(ctx context.Context, options TimelineUpdatePostOptions) (*TimelineResponse, error) {
	if err := validateTimelineIDs(options.HomeID, options.PostID); err != nil {
		return nil, err
	}
	if err := validateTimelinePostArrays(options.StickerIDs, options.StickerPackageIDs, options.LocationLatitudes, options.LocationLongitudes, options.LocationNames, options.MediaObjectIDs, options.MediaObjectTypes); err != nil {
		return nil, err
	}
	postInfo := map[string]any{
		"postId":           options.PostID,
		"editableContents": []string{"ALL"},
		"readPermission":   map[string]any{"homeID": options.HomeID},
	}
	if options.HoldingTime != nil {
		postInfo["holdingTime"] = *options.HoldingTime
	}
	contents := map[string]any{
		"sticonMetas": []any{},
		"contentsStyle": map[string]any{
			"textStyle": map[string]any{
				"textSizeMode":  defaultString(options.TextSizeMode, "NORMAL"),
				"textAnimation": defaultString(options.TextAnimation, "NONE"),
			},
			"stickerStyle": map[string]any{"backgroundColor": defaultString(options.BackgroundColor, "#FFFFFF")},
			"mediaStyle":   map[string]any{},
		},
		"stickers":  makeTimelineStickers(options.StickerIDs, options.StickerPackageIDs),
		"textMeta":  []any{},
		"locations": makeTimelineLocations(options.LocationLatitudes, options.LocationLongitudes, options.LocationNames),
		"media":     makeTimelineMedia(options.MediaObjectIDs, options.MediaObjectTypes),
	}
	if options.Text != nil {
		contents["text"] = *options.Text
	}
	if options.SharedPostID != nil {
		contents["sharedPostId"] = *options.SharedPostID
	}
	body, err := json.Marshal(map[string]any{"postInfo": postInfo, "contents": contents})
	if err != nil {
		return nil, fmt.Errorf("line timeline: encode post update: %w", err)
	}
	query := url.Values{"homeId": {options.HomeID}}
	return s.doJSON(ctx, http.MethodPost, "POST", timelineHomePath(options.HomeID)+"/api/v57/post/update.json", query, body)
}

// LikePost reacts to a post.
func (s *TimelineService) LikePost(ctx context.Context, options TimelineLikePostOptions) (*TimelineResponse, error) {
	if options.HomeID == "" || options.ContentID == "" {
		return nil, fmt.Errorf("line timeline: home ID and content ID are required")
	}
	query := url.Values{"homeId": {options.HomeID}}
	body, err := json.Marshal(map[string]string{
		"sourceType": defaultString(options.SourceType, "TIMELINE"),
		"likeType":   defaultString(options.LikeType, "1003"),
		"contentId":  options.ContentID,
	})
	if err != nil {
		return nil, fmt.Errorf("line timeline: encode like: %w", err)
	}
	return s.doJSON(ctx, http.MethodPost, "POST", "/ext/note/nt/api/v57/like/create.json", query, body)
}

// CreateComment adds a comment to a post.
func (s *TimelineService) CreateComment(ctx context.Context, options TimelineCommentOptions) (*TimelineResponse, error) {
	if options.HomeID == "" || options.ContentID == "" {
		return nil, fmt.Errorf("line timeline: home ID and content ID are required")
	}
	contents := options.ContentsList
	if contents == nil {
		contents = []json.RawMessage{}
	}
	body, err := json.Marshal(map[string]any{
		"commentText":  options.CommentText,
		"contentId":    options.ContentID,
		"contentsList": contents,
	})
	if err != nil {
		return nil, fmt.Errorf("line timeline: encode comment: %w", err)
	}
	query := url.Values{"sourceType": {defaultString(options.SourceType, "TIMELINE")}, "homeId": {options.HomeID}}
	return s.doJSON(ctx, http.MethodPost, "POST", "/ext/note/nt/api/v57/comment/create.json", query, body)
}

// SharePost sends a Timeline post into a Talk chat.
func (s *TimelineService) SharePost(ctx context.Context, options TimelineSharePostOptions) (*TimelineResponse, error) {
	if options.HomeID == "" || options.PostID == "" || options.ChatMID == "" {
		return nil, fmt.Errorf("line timeline: home ID, post ID, and chat MID are required")
	}
	body, err := json.Marshal(map[string]any{"postId": options.PostID, "receiveMids": []string{options.ChatMID}})
	if err != nil {
		return nil, fmt.Errorf("line timeline: encode share: %w", err)
	}
	return s.doJSON(ctx, http.MethodPost, "POST", timelineHomePath(options.HomeID)+"/api/v57/post/sendPostToTalk.json", nil, body)
}

// UploadNoteMedia uploads an image or video for a Note post.
func (s *TimelineService) UploadNoteMedia(ctx context.Context, mediaType TimelineMediaType, data []byte) (*TimelineMediaUploadResult, error) {
	if mediaType != TimelineMediaImage && mediaType != TimelineMediaVideo {
		return nil, fmt.Errorf("line timeline upload: unsupported media type %q", mediaType)
	}
	mid, err := s.profileMID(ctx)
	if err != nil {
		return nil, err
	}
	objectID := timelineObjectID(mid)
	response, err := s.uploadNoteObject(ctx, "myhome/h", objectID, mediaType, data)
	if err != nil {
		return nil, err
	}
	return &TimelineMediaUploadResult{ObjectID: objectID, Hash: response.Header.Get("X-Obs-Hash")}, nil
}

// UploadNoteCommentImage uploads an image attachment for a Note comment.
func (s *TimelineService) UploadNoteCommentImage(ctx context.Context, data []byte) (*TimelineMediaUploadResult, error) {
	mid, err := s.profileMID(ctx)
	if err != nil {
		return nil, err
	}
	seed := timelineObjectID(mid)
	response, err := s.uploadNoteObject(ctx, "myhome/cmt", seed, TimelineMediaImage, data)
	if err != nil {
		return nil, err
	}
	objectID := response.Header.Get("X-Obs-Oid")
	if objectID == "" {
		objectID = seed
	}
	return &TimelineMediaUploadResult{ObjectID: objectID, Hash: response.Header.Get("X-Obs-Hash")}, nil
}

func (s *TimelineService) profileMID(ctx context.Context) (string, error) {
	if err := s.InitTimeline(ctx); err != nil {
		return "", err
	}
	mid := s.client.ProfileMID()
	if mid == "" {
		return "", fmt.Errorf("line timeline: profile MID is required")
	}
	return mid, nil
}

func (s *TimelineService) uploadNoteObject(ctx context.Context, path, objectID string, mediaType TimelineMediaType, data []byte) (*http.Response, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("line timeline upload: no data to send")
	}
	if err := s.InitTimeline(ctx); err != nil {
		return nil, err
	}
	extension, contentType := "jpg", "image/jpeg"
	if mediaType == TimelineMediaVideo {
		extension, contentType = "mp4", "video/mp4"
	}
	params, err := json.Marshal(map[string]string{
		"name": objectID + "." + extension,
		"oid":  objectID,
		"type": string(mediaType),
		"ver":  "2.0",
	})
	if err != nil {
		return nil, fmt.Errorf("line timeline upload: encode object metadata: %w", err)
	}
	requestContext, cancel := context.WithTimeout(ctx, s.client.config.LongTimeout)
	defer cancel()
	requestURL := url.URL{Scheme: "https", Host: "obs.line-apps.com", Path: "/" + path + "/upload.nhn"}
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, requestURL.String(), bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("line timeline upload: create request: %w", err)
	}
	request.Header = s.timelineHeaders(http.MethodPost)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Content-Length", strconv.Itoa(len(data)))
	request.Header.Set("X-Obs-Params", base64.StdEncoding.EncodeToString(params))
	response, err := s.client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("line timeline upload: request: %w", err)
	}
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("line timeline upload: transport returned an empty response")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("line timeline upload failed: HTTP %d", response.StatusCode)
	}
	return &http.Response{StatusCode: response.StatusCode, Header: response.Header.Clone()}, nil
}

func (s *TimelineService) doJSON(ctx context.Context, method, headerMethod, path string, query url.Values, body []byte) (*TimelineResponse, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("line timeline: client is nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("line timeline: context is nil")
	}
	if err := s.InitTimeline(ctx); err != nil {
		return nil, err
	}
	requestURL := url.URL{Scheme: s.client.endpoint.Scheme, Host: s.client.endpoint.Host, Path: path}
	if query != nil {
		requestURL.RawQuery = query.Encode()
	}
	requestContext, cancel := context.WithTimeout(ctx, s.client.config.LongTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, method, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("line timeline: create request: %w", err)
	}
	if body == nil {
		request.Body = nil
	}
	request.Header = s.timelineHeaders(headerMethod)
	response, err := s.client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("line timeline: request: %w", err)
	}
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("line timeline: transport returned an empty response")
	}
	defer response.Body.Close()
	if err := obsResponseStatus(response, "Timeline request"); err != nil {
		return nil, err
	}
	data, err := readOBSBody(response.Body, s.client.config.MaxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("line timeline: read response: %w", err)
	}
	var result TimelineResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("line timeline: decode response: %w", err)
	}
	return &result, nil
}

func (s *TimelineService) timelineHeaders(method string) http.Header {
	headers := s.client.Headers(method)
	headers.Set("X-Line-Bdbtemplateversion", "v1")
	headers.Set("X-Lsr", "JP")
	headers.Set("X-Line-ChannelToken", s.token)
	headers.Set("X-Line-Global-Config", "discover.enable=true; follow.enable=true; reboot.phase=scenario")
	headers.Set("X-Line-Mid", s.client.ProfileMID())
	headers.Set("Content-Type", "application/json; charset=UTF-8")
	headers.Set("X-Lhm", method)
	return headers
}

func validateTimelineIDs(homeID, postID string) error {
	if homeID == "" || postID == "" {
		return fmt.Errorf("line timeline: home ID and post ID are required")
	}
	return nil
}

func validateTimelinePostArrays(stickerIDs, packageIDs []string, latitudes, longitudes []float64, locationNames, objectIDs, objectTypes []string) error {
	if len(stickerIDs) != len(packageIDs) || len(latitudes) != len(longitudes) || len(latitudes) != len(locationNames) || len(objectIDs) != len(objectTypes) {
		return fmt.Errorf("line timeline: attachment ID and metadata lists must have matching lengths")
	}
	return nil
}

func makeTimelineStickers(ids, packageIDs []string) []map[string]any {
	stickers := make([]map[string]any, 0, len(ids))
	for index, id := range ids {
		stickers = append(stickers, map[string]any{
			"id":                  id,
			"packageId":           packageIDs[index],
			"packageVersion":      1,
			"hasAnimation":        true,
			"hasSound":            true,
			"stickerResourceType": "ANIMATION",
		})
	}
	return stickers
}

func makeTimelineLocations(latitudes, longitudes []float64, names []string) []map[string]any {
	locations := make([]map[string]any, 0, len(latitudes))
	for index, latitude := range latitudes {
		locations = append(locations, map[string]any{
			"latitude":  latitude,
			"longitude": longitudes[index],
			"name":      names[index],
		})
	}
	return locations
}

func makeTimelineMedia(ids, mediaTypes []string) []map[string]string {
	media := make([]map[string]string, 0, len(ids))
	for index, id := range ids {
		media = append(media, map[string]string{"objectId": id, "type": mediaTypes[index], "obsFace": "[]"})
	}
	return media
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func timelineHomePath(homeID string) string {
	if strings.HasPrefix(homeID, "s") {
		return "/sn"
	}
	return "/mh"
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func timelineObjectID(mid string) string {
	digest := md5.Sum([]byte(fmt.Sprintf("%s-%d", mid, time.Now().UnixMilli())))
	return fmt.Sprintf("%x", digest)
}
