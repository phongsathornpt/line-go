package line

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/phongsathornpt/line-go/base"
	"github.com/phongsathornpt/line-go/types"
)

// Profile is the signed-in user's public LINE profile.
type Profile struct {
	MID                 string
	UserID              string
	Email               string
	Phone               string
	DisplayName         string
	PhoneticName        string
	StatusMessage       string
	PictureStatus       string
	PicturePath         string
	ThumbnailURL        string
	MusicProfile        string
	AllowSearchByUserID bool
	AllowSearchByEmail  bool
}

// ProfileUpdate contains only profile attributes to change. Nil fields are
// omitted from the LINE update request; pointers allow setting empty strings
// and false values explicitly.
type ProfileUpdate struct {
	DisplayName         *string
	PhoneticName        *string
	StatusMessage       *string
	MusicProfile        *string
	AllowSearchByUserID *bool
	AllowSearchByEmail  *bool
	HiddenFromList      *bool
}

// GetMyProfile returns the signed-in user's profile.
func (c *Client) GetMyProfile(ctx context.Context) (*Profile, error) {
	result, err := c.base.Talk().GetProfile(ctx, types.GetProfileArgs{})
	if err != nil {
		return nil, fmt.Errorf("line client: get profile: %w", err)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line client: get profile: %w", missingSuccess("getProfile"))
	}
	profile := profileFromDTO(result.Success)
	if profile.MID != "" {
		c.base.SetProfileMID(profile.MID)
	}
	return profile, nil
}

// UpdateMyProfile applies the supplied sparse profile attributes.
func (c *Client) UpdateMyProfile(ctx context.Context, update ProfileUpdate) error {
	attributes := make(map[int32]*types.ProfileContent)
	put := func(attribute int32, value string) {
		attributes[attribute] = &types.ProfileContent{
			Value: stringPointer(value),
			Meta:  map[string]string{},
		}
	}
	if update.DisplayName != nil {
		put(2, *update.DisplayName)
	}
	if update.PhoneticName != nil {
		put(4, *update.PhoneticName)
	}
	if update.StatusMessage != nil {
		put(16, *update.StatusMessage)
	}
	if update.AllowSearchByUserID != nil {
		put(
			32,
			strconv.FormatBool(*update.AllowSearchByUserID),
		)
	}
	if update.AllowSearchByEmail != nil {
		put(64, strconv.FormatBool(*update.AllowSearchByEmail))
	}
	if update.MusicProfile != nil {
		put(256, *update.MusicProfile)
	}
	if update.HiddenFromList != nil {
		put(1024, strconv.FormatBool(*update.HiddenFromList))
	}
	if len(attributes) == 0 {
		return nil
	}

	sequence, err := c.base.GetReqseq(ctx, "talk")
	if err != nil {
		return fmt.Errorf("line client: update profile: allocate request sequence: %w", err)
	}
	_, err = c.base.Talk().UpdateProfileAttributes(ctx, types.UpdateProfileAttributesArgs{
		ReqSeq: int32Pointer(sequence),
		Request: &types.UpdateProfileAttributesRequest{
			ProfileAttributes: attributes,
		},
	})
	if err != nil {
		return fmt.Errorf("line client: update profile: %w", err)
	}
	return nil
}

// Chat is a high-level view of a LINE Talk room.
type Chat struct {
	client *Client
	Raw    *types.Chat
	MID    string
	Name   string
}

// SendMessage sends a text message to this chat.
func (c *Chat) SendMessage(ctx context.Context, text string) (*Message, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("line chat: send message requires a client")
	}
	return c.client.SendMessage(ctx, SendMessageOptions{To: c.MID, Text: &text})
}

// UpdateName changes this chat's display name.
func (c *Chat) UpdateName(ctx context.Context, name string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("line chat: update name requires a client")
	}
	sequence, err := c.client.base.GetReqseq(ctx, "talk")
	if err != nil {
		return fmt.Errorf("line chat: allocate request sequence: %w", err)
	}
	result, err := c.client.base.Talk().UpdateChat(ctx, types.UpdateChatArgs{
		Request: &types.UpdateChatRequest{
			ReqSeq:           int32Pointer(sequence),
			Chat:             &types.Chat{ChatName: stringPointer(name)},
			UpdatedAttribute: enumPointer(types.Pb1O2NAME),
		},
	})
	if err != nil {
		return fmt.Errorf("line chat: update name: %w", err)
	}
	if result.Success == nil {
		return fmt.Errorf("line chat: update name: %w", missingSuccess("updateChat"))
	}
	return nil
}

// Invite adds contacts to this chat.
func (c *Chat) Invite(ctx context.Context, mids []string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("line chat: invite requires a client")
	}
	result, err := c.client.base.Talk().InviteIntoChat(ctx, types.InviteIntoChatArgs{
		Request: &types.InviteIntoChatRequest{
			ChatMid:        stringPointer(c.MID),
			TargetUserMids: mids,
		},
	})
	if err != nil {
		return fmt.Errorf("line chat: invite contacts: %w", err)
	}
	if result.Success == nil {
		return fmt.Errorf("line chat: invite contacts: %w", missingSuccess("inviteIntoChat"))
	}
	return nil
}

// Kick removes a contact from this chat.
func (c *Chat) Kick(ctx context.Context, mid string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("line chat: kick requires a client")
	}
	result, err := c.client.base.Talk().DeleteOtherFromChat(ctx, types.DeleteOtherFromChatArgs{
		Request: &types.DeleteOtherFromChatRequest{
			ChatMid:        stringPointer(c.MID),
			TargetUserMids: []string{mid},
		},
	})
	if err != nil {
		return fmt.Errorf("line chat: kick contact: %w", err)
	}
	if result.Success == nil {
		return fmt.Errorf("line chat: kick contact: %w", missingSuccess("deleteOtherFromChat"))
	}
	return nil
}

// Leave removes the current user from this chat.
func (c *Chat) Leave(ctx context.Context) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("line chat: leave requires a client")
	}
	result, err := c.client.base.Talk().DeleteSelfFromChat(ctx, types.DeleteSelfFromChatArgs{
		Request: &types.DeleteSelfFromChatRequest{ChatMid: stringPointer(c.MID)},
	})
	if err != nil {
		return fmt.Errorf("line chat: leave: %w", err)
	}
	if result.Success == nil {
		return fmt.Errorf("line chat: leave: %w", missingSuccess("deleteSelfFromChat"))
	}
	return nil
}

// FetchMessages returns the most recent messages from this chat. A zero limit
// uses LINEJS's default of ten messages.
func (c *Chat) FetchMessages(ctx context.Context, limit int32) ([]*Message, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("line chat: fetch messages requires a client")
	}
	if limit == 0 {
		limit = 10
	}
	boxes, err := c.client.base.Talk().GetMessageBoxes(ctx, types.GetMessageBoxesArgs{
		MessageBoxListRequest: &types.MessageBoxListRequest{},
	})
	if err != nil {
		return nil, fmt.Errorf("line chat: fetch messages: list message boxes: %w", err)
	}
	if boxes.Success == nil {
		return nil, fmt.Errorf("line chat: fetch messages: %w", missingSuccess("getMessageBoxes"))
	}
	var chatBox *types.ExtendedMessageBox
	for _, box := range boxes.Success.MessageBoxes {
		if box != nil && box.Id != nil && *box.Id == c.MID {
			chatBox = box
			break
		}
	}
	if chatBox == nil {
		return nil, fmt.Errorf("line chat: message box for %q was not found", c.MID)
	}
	missingLastMessage := chatBox.LastDeliveredMessageId == nil
	missingMessageID := !missingLastMessage && chatBox.LastDeliveredMessageId.MessageId == nil
	missingDeliveredTime := !missingLastMessage && chatBox.LastDeliveredMessageId.DeliveredTime == nil
	if missingLastMessage || missingMessageID || missingDeliveredTime {
		return nil, fmt.Errorf("line chat: message box for %q has no last delivered message", c.MID)
	}

	result, err := c.client.base.Talk().GetPreviousMessagesV2WithRequest(ctx, types.GetPreviousMessagesV2WithRequestArgs{
		Request: &types.GetPreviousMessagesV2Request{
			MessageBoxId: stringPointer(c.MID),
			EndMessageId: &types.MessageBoxV2MessageId{
				MessageId:     chatBox.LastDeliveredMessageId.MessageId,
				DeliveredTime: chatBox.LastDeliveredMessageId.DeliveredTime,
			},
			MessagesCount: int32Pointer(limit),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("line chat: fetch messages: load history: %w", err)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line chat: fetch messages: %w", missingSuccess("getPreviousMessagesV2WithRequest"))
	}
	messages := make([]*Message, 0, len(result.Success))
	for _, raw := range result.Success {
		if raw == nil {
			continue
		}
		if raw.ContentMetadata["e2eeVersion"] != "" {
			if c.client.profile == nil {
				return nil, fmt.Errorf("line chat: decrypt history requires a signed-in profile")
			}
			messageID := ""
			if raw.Id != nil {
				messageID = *raw.Id
			}
			if err := c.client.base.E2EE().DecryptMessage(ctx, c.client.profile.MID, raw); err != nil {
				return nil, fmt.Errorf("line chat: decrypt message %q: %w", messageID, err)
			}
		}
		messages = append(messages, messageFromDTO(raw))
	}
	return messages, nil
}

// GetBGM returns the chat's background music, or nil when none is set.
func (c *Chat) GetBGM(ctx context.Context) (*types.ChatRoomBGM, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("line chat: get BGM requires a client")
	}
	result, err := c.client.base.Talk().GetChatRoomBGMs(ctx, types.GetChatRoomBGMsArgs{
		ChatRoomMids: []string{c.MID},
	})
	if err != nil {
		return nil, fmt.Errorf("line chat: get BGM: %w", err)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line chat: get BGM: %w", missingSuccess("getChatRoomBGMs"))
	}
	return result.Success[c.MID], nil
}

// SetBGM sets or clears this chat's background music. A nil value clears it.
func (c *Chat) SetBGM(ctx context.Context, bgmInfo *string) (*types.ChatRoomBGM, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("line chat: set BGM requires a client")
	}
	value := ""
	if bgmInfo != nil {
		value = *bgmInfo
	}
	sequence, err := c.client.base.GetReqseq(ctx, "talk")
	if err != nil {
		return nil, fmt.Errorf("line chat: allocate request sequence: %w", err)
	}
	result, err := c.client.base.Talk().UpdateChatRoomBGM(ctx, types.UpdateChatRoomBGMArgs{
		ReqSeq:          int32Pointer(sequence),
		ChatRoomMid:     stringPointer(c.MID),
		ChatRoomBGMInfo: stringPointer(value),
	})
	if err != nil {
		return nil, fmt.Errorf("line chat: set BGM: %w", err)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line chat: set BGM: %w", missingSuccess("updateChatRoomBGM"))
	}
	return result.Success, nil
}

// FetchJoinedChats returns the signed-in user's joined Talk rooms.
func (c *Client) FetchJoinedChats(ctx context.Context) ([]*Chat, error) {
	joined, err := c.base.Talk().GetAllChatMids(ctx, types.GetAllChatMidsArgs{
		Request:    &types.GetAllChatMidsRequest{WithMemberChats: boolPointer(true)},
		SyncReason: enumPointer(types.Pb1V7INTERNAL),
	})
	if err != nil {
		return nil, fmt.Errorf("line client: fetch joined chats: list chat IDs: %w", err)
	}
	if joined.Success == nil {
		return nil, fmt.Errorf("line client: fetch joined chats: %w", missingSuccess("getAllChatMids"))
	}
	if len(joined.Success.MemberChatMids) == 0 {
		return []*Chat{}, nil
	}

	result, err := c.base.Talk().GetChats(ctx, types.GetChatsArgs{
		Request: &types.GetChatsRequest{ChatMids: joined.Success.MemberChatMids},
	})
	if err != nil {
		return nil, fmt.Errorf("line client: fetch joined chats: load chats: %w", err)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line client: fetch joined chats: %w", missingSuccess("getChats"))
	}
	chats := make([]*Chat, 0, len(result.Success.Chats))
	for _, raw := range result.Success.Chats {
		if raw == nil || raw.ChatMid == nil {
			continue
		}
		chats = append(chats, chatFromDTO(c, raw))
	}
	return chats, nil
}

// GetChat fetches one Talk room, including its members and invitees.
func (c *Client) GetChat(ctx context.Context, mid string) (*Chat, error) {
	if mid == "" {
		return nil, fmt.Errorf("line client: get chat: chat MID is empty")
	}
	result, err := c.base.Talk().GetChats(ctx, types.GetChatsArgs{
		Request: &types.GetChatsRequest{
			ChatMids:     []string{mid},
			WithMembers:  boolPointer(true),
			WithInvitees: boolPointer(true),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("line client: get chat %q: %w", mid, err)
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line client: get chat: %w", missingSuccess("getChats"))
	}
	for _, raw := range result.Success.Chats {
		if raw != nil && raw.ChatMid != nil && *raw.ChatMid == mid {
			return chatFromDTO(c, raw), nil
		}
	}
	return nil, fmt.Errorf("line client: chat %q was not returned", mid)
}

// User is a high-level view of a LINE contact.
type User struct {
	client  *Client
	Raw     *types.GetContactV3Response
	Contact *types.Contact
	MID     string
}

// SendMessage sends a text message to this contact.
func (u *User) SendMessage(ctx context.Context, text string) (*Message, error) {
	if u == nil || u.client == nil {
		return nil, fmt.Errorf("line user: send message requires a client")
	}
	return u.client.SendMessage(ctx, SendMessageOptions{To: u.MID, Text: &text})
}

// Rename sets this contact's display-name override. An empty name clears it.
func (u *User) Rename(ctx context.Context, displayName string) error {
	return u.updateContactSetting(ctx, types.ContactSettingCONTACTSETTINGDISPLAYNAMEOVERRIDE, displayName)
}

// SetFavorite sets whether this contact is a favorite.
func (u *User) SetFavorite(ctx context.Context, favorite bool) error {
	return u.updateContactSetting(ctx, types.ContactSettingCONTACTSETTINGFAVORITE, strconv.FormatBool(favorite))
}

// SetNotificationDisabled controls notifications for this contact's chats.
func (u *User) SetNotificationDisabled(ctx context.Context, disabled bool) error {
	return u.updateContactSetting(ctx, types.ContactSettingCONTACTSETTINGNOTIFICATIONDISABLE, strconv.FormatBool(disabled))
}

// SetHidden controls whether this contact is hidden from the friend list.
func (u *User) SetHidden(ctx context.Context, hidden bool) error {
	return u.updateContactSetting(ctx, types.ContactSettingCONTACTSETTINGCONTACTHIDE, strconv.FormatBool(hidden))
}

// FetchUsers returns all friends exposed by LINE's V3 contacts API.
func (c *Client) FetchUsers(ctx context.Context) ([]*User, error) {
	friendResult, err := c.base.Relation().GetUserFriendIds(ctx, types.GetUserFriendIdsArgs{
		Request: &types.GetUserFriendIdsRequest{BlockStatus: enumPointer(types.F61EnumC10204a0ALL)},
	})
	if err != nil {
		return nil, fmt.Errorf("line client: fetch users: list friend IDs: %w", err)
	}
	if friendResult.Success == nil {
		return nil, fmt.Errorf("line client: fetch users: %w", missingSuccess("getUserFriendIds"))
	}
	mids := friendResult.Success.UserFriendMids
	users, err := c.fetchUsersByMID(ctx, mids)
	if err == nil {
		return users, nil
	}
	if !isAPINotCapable(err) {
		return nil, err
	}

	legacy, legacyErr := c.base.Talk().GetContactsV2(ctx, mids)
	if legacyErr == nil {
		users = make([]*User, 0, len(legacy.Contacts))
		for _, mid := range mids {
			entry := legacy.Contacts[mid]
			if entry == nil {
				continue
			}
			users = append(users, &User{client: c, Contact: entry.Contact, MID: mid})
		}
		if len(users) > 0 {
			return users, nil
		}
	} else if !isAPINotCapable(legacyErr) {
		return nil, legacyErr
	}

	users = make([]*User, 0, len(mids))
	for _, mid := range mids {
		user, err := c.GetUser(ctx, mid)
		if err == nil {
			users = append(users, user)
		}
	}
	return users, nil
}

// GetUser fetches one contact by MID through LINE's V3 contacts API.
func (c *Client) GetUser(ctx context.Context, mid string) (*User, error) {
	if mid == "" {
		return nil, fmt.Errorf("line client: get user: user MID is empty")
	}
	users, err := c.fetchUsersByMID(ctx, []string{mid})
	if err != nil {
		return nil, fmt.Errorf("line client: get user %q: %w", mid, err)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("line client: user %q was not returned", mid)
	}
	return users[0], nil
}

func (c *Client) fetchUsersByMID(ctx context.Context, mids []string) ([]*User, error) {
	if len(mids) == 0 {
		return []*User{}, nil
	}
	targets := make([]*types.GetContactV3Target, 0, len(mids))
	for _, mid := range mids {
		targets = append(targets, &types.GetContactV3Target{TargetUserMid: stringPointer(mid)})
	}
	result, err := c.base.Relation().GetContactsV3(ctx, types.GetContactsV3Args{
		Request: &types.GetContactsV3Request{TargetUsers: targets},
	})
	if err != nil {
		return nil, fmt.Errorf("get contacts: %w", err)
	}
	if result.Success == nil {
		return nil, missingSuccess("getContactsV3")
	}
	users := make([]*User, 0, len(result.Success.Responses))
	for _, raw := range result.Success.Responses {
		if raw == nil || raw.TargetUserMid == nil {
			continue
		}
		users = append(users, &User{client: c, Raw: raw, MID: *raw.TargetUserMid})
	}
	return users, nil
}

func (u *User) updateContactSetting(ctx context.Context, flag types.ContactSetting, value string) error {
	if u == nil || u.client == nil {
		return fmt.Errorf("line user: update contact setting requires a client")
	}
	sequence, err := u.client.base.GetReqseq(ctx, "talk")
	if err != nil {
		return fmt.Errorf("line user: allocate request sequence: %w", err)
	}
	_, err = u.client.base.Talk().UpdateContactSetting(ctx, types.UpdateContactSettingArgs{
		ReqSeq: int32Pointer(sequence),
		Mid:    stringPointer(u.MID),
		Flag:   enumPointer(flag),
		Value:  stringPointer(value),
	})
	if err != nil {
		return fmt.Errorf("line user: update contact setting: %w", err)
	}
	return nil
}

func profileFromDTO(raw *types.Profile) *Profile {
	result := new(Profile)
	if raw.Mid != nil {
		result.MID = *raw.Mid
	}
	if raw.Userid != nil {
		result.UserID = *raw.Userid
	}
	if raw.Email != nil {
		result.Email = *raw.Email
	}
	if raw.Phone != nil {
		result.Phone = *raw.Phone
	}
	if raw.DisplayName != nil {
		result.DisplayName = *raw.DisplayName
	}
	if raw.PhoneticName != nil {
		result.PhoneticName = *raw.PhoneticName
	}
	if raw.StatusMessage != nil {
		result.StatusMessage = *raw.StatusMessage
	}
	if raw.PictureStatus != nil {
		result.PictureStatus = *raw.PictureStatus
	}
	if raw.PicturePath != nil {
		result.PicturePath = *raw.PicturePath
	}
	if raw.ThumbnailUrl != nil {
		result.ThumbnailURL = *raw.ThumbnailUrl
	}
	if raw.MusicProfile != nil {
		result.MusicProfile = *raw.MusicProfile
	}
	if raw.AllowSearchByUserid != nil {
		result.AllowSearchByUserID = *raw.AllowSearchByUserid
	}
	if raw.AllowSearchByEmail != nil {
		result.AllowSearchByEmail = *raw.AllowSearchByEmail
	}
	return result
}

func chatFromDTO(client *Client, raw *types.Chat) *Chat {
	chat := &Chat{client: client, Raw: raw}
	if raw.ChatMid != nil {
		chat.MID = *raw.ChatMid
	}
	if raw.ChatName != nil {
		chat.Name = *raw.ChatName
	}
	return chat
}

func isAPINotCapable(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "api method not capable")
}

func missingSuccess(method string) error {
	return fmt.Errorf("%w: %s", base.ErrMissingServiceSuccess, method)
}

func enumPointer[T ~int32](value T) *T { return &value }

func stringPointer(value string) *string { return &value }

func boolPointer(value bool) *bool { return &value }

func int32Pointer(value int32) *int32 { return &value }
