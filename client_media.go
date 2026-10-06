package line

import (
	"context"
	"fmt"

	"github.com/phongsathornpt/line-go/base"
	"github.com/phongsathornpt/line-go/types"
)

// ObjectType identifies a media class used by LINE's object storage service.
type ObjectType = base.ObjectType

const (
	ObjectImage = base.ObjectImage
	ObjectGIF   = base.ObjectGIF
	ObjectVideo = base.ObjectVideo
	ObjectAudio = base.ObjectAudio
	ObjectFile  = base.ObjectFile
)

// DownloadedObject contains media bytes and the filename and MIME type
// reported by LINE or the hosting server.
type DownloadedObject = base.DownloadedObject

// ObjectUploadResult identifies an uploaded object and includes its hash.
type ObjectUploadResult = base.ObjectUploadResult

// MediaUploadOptions describes an E2EE media message sent to a Talk chat.
type MediaUploadOptions struct {
	To          string
	Type        ObjectType
	Data        []byte
	Preview     []byte
	ContentType string
	Filename    string
	DurationMS  *int64
}

// OBS exposes the lower-level media storage API bound to this client.
func (c *Client) OBS() *base.ObjectStorage {
	if c == nil || c.base == nil {
		return nil
	}
	return c.base.OBS()
}

// UploadMediaByE2EE encrypts and sends a media message to a Talk chat.
func (c *Client) UploadMediaByE2EE(ctx context.Context, options MediaUploadOptions) (*Message, error) {
	if c == nil || c.base == nil {
		return nil, fmt.Errorf("line client: upload media requires a client")
	}
	if c.profile == nil || c.profile.MID == "" {
		return nil, fmt.Errorf("line client: upload media requires a signed-in profile")
	}
	message, err := c.base.OBS().UploadMediaByE2EE(ctx, base.E2EEMediaUploadOptions{
		From:        c.profile.MID,
		To:          options.To,
		Type:        options.Type,
		Data:        options.Data,
		Preview:     options.Preview,
		ContentType: options.ContentType,
		Filename:    options.Filename,
		DurationMS:  options.DurationMS,
	})
	if err != nil {
		return nil, err
	}
	return messageFromDTO(message), nil
}

// UploadTalkMedia uploads a plain Talk or Square object using LINE's OBS
// request-sequence behavior.
func (c *Client) UploadTalkMedia(ctx context.Context, options base.TalkMediaUploadOptions) (*ObjectUploadResult, error) {
	if c == nil || c.base == nil {
		return nil, fmt.Errorf("line client: upload media requires a client")
	}
	return c.base.OBS().UploadTalkObject(ctx, options)
}

// DownloadMedia retrieves plain, E2EE, or externally hosted content attached to
// a message. E2EE messages require the client's signed-in profile.
func (c *Client) DownloadMedia(ctx context.Context, message *Message, preview bool) (*DownloadedObject, error) {
	if c == nil || c.base == nil {
		return nil, fmt.Errorf("line client: download media requires a client")
	}
	if message == nil {
		return nil, fmt.Errorf("line client: download media requires a message")
	}
	if url := message.ContentMetadata["DOWNLOAD_URL"]; url != "" {
		if preview {
			url = message.ContentMetadata["PREVIEW_URL"]
			if url == "" {
				return nil, fmt.Errorf("line client: message has no preview URL")
			}
		}
		return c.base.OBS().DownloadURL(ctx, url)
	}
	if len(message.Chunks) > 0 {
		if c.profile == nil || c.profile.MID == "" {
			return nil, fmt.Errorf("line client: decrypting media requires a signed-in profile")
		}
		return c.base.OBS().DownloadMediaByE2EE(ctx, c.profile.MID, messageDTO(message))
	}
	if message.ID == "" {
		return nil, fmt.Errorf("line client: message has no ID")
	}
	return c.base.OBS().DownloadMessageData(ctx, message.ID, preview, isSquareMID(message.To))
}

// UploadMyProfileImage sets a new profile picture through LINE OBS.
func (c *Client) UploadMyProfileImage(ctx context.Context, data []byte) (*ObjectUploadResult, error) {
	if c == nil || c.base == nil {
		return nil, fmt.Errorf("line client: upload profile image requires a client")
	}
	if c.profile == nil || c.profile.MID == "" {
		return nil, fmt.Errorf("line client: upload profile image requires a signed-in profile")
	}
	return c.base.OBS().UploadObjectForService(ctx, base.ObjectUploadOptions{
		Data: data,
		Type: ObjectImage,
		Path: "talk/p/" + c.profile.MID,
	})
}

// UploadMyProfileBackground uploads an image that can be associated with the
// signed-in user's profile background.
func (c *Client) UploadMyProfileBackground(ctx context.Context, data []byte) (*ObjectUploadResult, error) {
	if c == nil || c.base == nil {
		return nil, fmt.Errorf("line client: upload profile background requires a client")
	}
	return c.base.OBS().UploadObjectForService(ctx, base.ObjectUploadOptions{
		Data: data,
		Type: ObjectImage,
		Path: "myhome/h",
	})
}

func messageDTO(message *Message) *types.Message {
	contentType := types.ContentType(message.ContentType)
	return &types.Message{
		From:            optionalString(message.From),
		To:              optionalString(message.To),
		Id:              optionalString(message.ID),
		ContentType:     &contentType,
		ContentMetadata: cloneStringMap(message.ContentMetadata),
		Chunks:          cloneByteSlices(message.Chunks),
	}
}

func isSquareMID(mid string) bool {
	return len(mid) > 0 && (mid[0] == 'm' || mid[0] == 't')
}
