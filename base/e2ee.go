package base

import (
	"context"
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"

	cryptoe2ee "github.com/phongsathornpt/line-go/internal/crypto/e2ee"
	"github.com/phongsathornpt/line-go/storage"
	"github.com/phongsathornpt/line-go/thrift"
	"github.com/phongsathornpt/line-go/types"
)

// E2EEKeyPair contains raw Curve25519 key bytes compatible with LINE's E2EE
// Thrift fields and TweetNaCl.
type E2EEKeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

// E2EEKey is a registered or login-restored local key pair.
type E2EEKey struct {
	KeyID       int32
	PrivateKey  []byte
	PublicKey   []byte
	E2EEVersion int32
}

// E2EELoginKeyChain describes the encrypted key-chain fields returned during
// QR login. PublicKey and EncryptedKeyChain contain decoded binary bytes.
type E2EELoginKeyChain struct {
	KeyID             int32
	PublicKey         []byte
	EncryptedKeyChain []byte
	E2EEVersion       int32
}

// E2EEEncryptedMessage contains the encrypted message chunks and protocol
// metadata LINE stores on a Talk message.
type E2EEEncryptedMessage struct {
	Chunks          [][]byte
	ContentMetadata map[string]string
	SpecVersion     int32
}

// E2EEGroupKey is a locally unwrapped group key generation.
type E2EEGroupKey struct {
	PrivateKey  []byte `json:"privKey"`
	KeyID       int32  `json:"keyId"`
	SpecVersion int32  `json:"specVersion,omitempty"`
}

// E2EEService handles LINE E2EE login, key negotiation, group keys, and message
// encryption.
type E2EEService struct {
	client *BaseClient

	loginKeyMu sync.Mutex
	loginKey   *E2EEKey
}

type persistedE2EEKey struct {
	KeyID       int32  `json:"keyId"`
	PrivateKey  string `json:"privKey"`
	PublicKey   string `json:"pubKey"`
	E2EEVersion int32  `json:"e2eeVersion"`
}

// CreateQRSecret makes the X25519 secret and URL query suffix used by the
// legacy and secure QR login flows.
func (s *E2EEService) CreateQRSecret() (E2EEKeyPair, string, error) {
	if s == nil || s.client == nil {
		return E2EEKeyPair{}, "", fmt.Errorf("line e2ee: client is nil")
	}
	pair, err := cryptoe2ee.GenerateKeyPair()
	if err != nil {
		return E2EEKeyPair{}, "", err
	}
	encodedPublicKey := base64.StdEncoding.EncodeToString(pair.Public)
	query := "?secret=" + url.QueryEscape(encodedPublicKey) + "&e2eeVersion=1"
	return E2EEKeyPair{PrivateKey: pair.Private, PublicKey: pair.Public}, query, nil
}

// RegisterKeyPair creates and registers a new E2EE key pair, then persists it
// under the upstream e2eeKeys:<keyId> key.
func (s *E2EEService) RegisterKeyPair(ctx context.Context) (*E2EEKey, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("line e2ee register: client is nil")
	}
	pair, err := cryptoe2ee.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	version := int32(1)
	keyID := int32(0)
	createdTime := int64(0)
	keyData := append([]byte(nil), pair.Public...)
	result, err := s.client.Talk().RegisterE2EEPublicKey(ctx, types.RegisterE2EEPublicKeyArgs{
		PublicKey: &types.Pb1C13097n4{
			Version:     &version,
			KeyId:       &keyID,
			KeyData:     &keyData,
			CreatedTime: &createdTime,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("line e2ee register: %w", err)
	}
	if result.E != nil {
		return nil, talkServiceError("registerE2EEPublicKey", result.E)
	}
	if result.Success == nil || result.Success.KeyId == nil {
		return nil, fmt.Errorf("line e2ee register: response has no key id")
	}
	key := &E2EEKey{
		KeyID:       *result.Success.KeyId,
		PrivateKey:  pair.Private,
		PublicKey:   pair.Public,
		E2EEVersion: 1,
	}
	if err := s.saveKey(ctx, key); err != nil {
		return nil, fmt.Errorf("line e2ee register: persist key: %w", err)
	}
	return key, nil
}

// GetKey loads a locally persisted key by its LINE key ID.
func (s *E2EEService) GetKey(ctx context.Context, keyID int32) (*E2EEKey, bool, error) {
	if s == nil || s.client == nil {
		return nil, false, fmt.Errorf("line e2ee get key: client is nil")
	}
	encoded, found, err := s.client.storage.Get(ctx, storage.KeyE2EEPrivateKey(strconv.FormatInt(int64(keyID), 10)))
	if err != nil || !found {
		return nil, found, err
	}
	value, ok := encoded.(string)
	if !ok {
		return nil, true, fmt.Errorf("line e2ee get key: stored key has type %T, want string", encoded)
	}
	stored, err := decodeStoredE2EEKey(value)
	if err != nil {
		return nil, true, fmt.Errorf("line e2ee get key: %w", err)
	}
	if stored.KeyID != keyID {
		return nil, true, fmt.Errorf("line e2ee get key: stored key id %d does not match %d", stored.KeyID, keyID)
	}
	return stored, true, nil
}

// GetSelfKey loads the saved E2EE key alias for the signed-in account MID.
func (s *E2EEService) GetSelfKey(ctx context.Context, mid string) (*E2EEKey, bool, error) {
	if s == nil || s.client == nil {
		return nil, false, fmt.Errorf("line e2ee get self key: client is nil")
	}
	if mid == "" {
		return nil, false, fmt.Errorf("line e2ee get self key: MID is empty")
	}
	encoded, found, err := s.client.storage.Get(ctx, storage.KeyE2EEPrivateKey(mid))
	if err != nil || !found {
		return nil, found, err
	}
	value, ok := encoded.(string)
	if !ok {
		return nil, true, fmt.Errorf("line e2ee get self key: stored key has type %T, want string", encoded)
	}
	key, err := decodeStoredE2EEKey(value)
	if err != nil {
		return nil, true, fmt.Errorf("line e2ee get self key: %w", err)
	}
	return key, true, nil
}

// SaveSelfKey stores a key under both its numeric key ID and the account MID,
// matching LINEJS's self-key lookup convention.
func (s *E2EEService) SaveSelfKey(ctx context.Context, mid string, key *E2EEKey) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("line e2ee save self key: client is nil")
	}
	if mid == "" {
		return fmt.Errorf("line e2ee save self key: MID is empty")
	}
	if err := s.saveKey(ctx, key); err != nil {
		return err
	}
	encoded, err := json.Marshal(persistedE2EEKey{
		KeyID:       key.KeyID,
		PrivateKey:  base64.StdEncoding.EncodeToString(key.PrivateKey),
		PublicKey:   base64.StdEncoding.EncodeToString(key.PublicKey),
		E2EEVersion: key.E2EEVersion,
	})
	if err != nil {
		return err
	}
	return s.client.storage.Set(ctx, storage.KeyE2EEPrivateKey(mid), string(encoded))
}

// DecryptLoginKeyChain decrypts a QR-login key chain and stores every valid
// generation by key ID. The selected key remains pending until VerifyLoginKey
// checks it against LINE's registered public key after token installation.
func (s *E2EEService) DecryptLoginKeyChain(
	ctx context.Context,
	input E2EELoginKeyChain,
	secret []byte,
) (*E2EEKey, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("line e2ee decode key chain: client is nil")
	}
	if input.KeyID <= 0 {
		return nil, fmt.Errorf("line e2ee decode key chain: key id must be positive")
	}
	shared, err := cryptoe2ee.SharedSecret(secret, input.PublicKey)
	if err != nil {
		return nil, err
	}
	aesKey, aesIV := cryptoe2ee.GenerateSharedAESKey(shared)
	plaintext, err := cryptoe2ee.DecryptCBC(aesKey, aesIV, input.EncryptedKeyChain)
	if err != nil {
		return nil, fmt.Errorf("line e2ee decode key chain: decrypt: %w", err)
	}
	fields, err := thrift.UnmarshalStruct(thrift.ProtocolCompact, plaintext)
	if err != nil {
		return nil, fmt.Errorf("line e2ee decode key chain: decode Thrift struct: %w", err)
	}
	var chain types.E2EEKeyChain
	if err := thrift.UnmarshalStructValue(fields, &chain); err != nil {
		return nil, fmt.Errorf("line e2ee decode key chain: decode key entries: %w", err)
	}
	if len(chain.Keychain) == 0 {
		return nil, fmt.Errorf("line e2ee decode key chain: no key entries")
	}
	var selected *E2EEKey
	seen := make(map[int32]struct{}, len(chain.Keychain))
	keys := make([]*E2EEKey, 0, len(chain.Keychain))
	for index, entry := range chain.Keychain {
		if entry == nil || entry.KeyId == nil || entry.PrivateKey == nil || entry.PublicKey == nil {
			return nil, fmt.Errorf("line e2ee decode key chain: entry %d is incomplete", index)
		}
		keyID := *entry.KeyId
		if _, duplicate := seen[keyID]; duplicate {
			return nil, fmt.Errorf("line e2ee decode key chain: duplicate key id %d", keyID)
		}
		seen[keyID] = struct{}{}
		privateKey := []byte(*entry.PrivateKey)
		publicKey := []byte(*entry.PublicKey)
		if !cryptoe2ee.VerifyKeyPair(privateKey, publicKey) {
			return nil, fmt.Errorf("line e2ee decode key chain: entry %d has an invalid X25519 key pair", index)
		}
		key := &E2EEKey{
			KeyID:       keyID,
			PrivateKey:  privateKey,
			PublicKey:   publicKey,
			E2EEVersion: input.E2EEVersion,
		}
		keys = append(keys, key)
		if keyID == input.KeyID {
			selected = key
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("line e2ee decode key chain: selected key id %d is absent", input.KeyID)
	}
	for _, key := range keys {
		if err := s.saveKey(ctx, key); err != nil {
			return nil, fmt.Errorf("line e2ee decode key chain: persist key %d: %w", key.KeyID, err)
		}
	}
	s.loginKeyMu.Lock()
	s.loginKey = cloneE2EEKey(selected)
	s.loginKeyMu.Unlock()
	return cloneE2EEKey(selected), nil
}

// VerifyLoginKey confirms a restored QR-login key against LINE's registered
// public-key list. It must run after the new access token has been installed.
func (s *E2EEService) VerifyLoginKey(ctx context.Context) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("line e2ee verify login key: client is nil")
	}
	s.loginKeyMu.Lock()
	key := cloneE2EEKey(s.loginKey)
	s.loginKeyMu.Unlock()
	if key == nil {
		return nil
	}
	registered, err := s.client.Talk().GetE2EEPublicKeys(ctx)
	if err != nil {
		return err
	}
	for _, item := range registered {
		if item == nil || item.KeyId == nil || *item.KeyId != key.KeyID || item.KeyData == nil {
			continue
		}
		if !cryptoe2ee.VerifyKeyPair(key.PrivateKey, *item.KeyData) {
			return fmt.Errorf("line e2ee verify login key: key %d does not match LINE's registered public key", key.KeyID)
		}
		break
	}
	s.loginKeyMu.Lock()
	s.loginKey = nil
	s.loginKeyMu.Unlock()
	return nil
}

// EncryptDeviceSecret applies LINE's E2EE device-secret transformation.
func (s *E2EEService) EncryptDeviceSecret(publicKey, privateKey, encryptedKeyChain []byte) ([]byte, error) {
	shared, err := cryptoe2ee.SharedSecret(privateKey, publicKey)
	if err != nil {
		return nil, err
	}
	key, _ := cryptoe2ee.GenerateSharedAESKey(shared)
	hash := sha256.Sum256(encryptedKeyChain)
	transformed, err := cryptoe2ee.XORSplitHalves(hash[:])
	if err != nil {
		return nil, err
	}
	return cryptoe2ee.EncryptECB(key, transformed)
}

// EncryptMessage encrypts a text, location, or JSON message for a Talk
// recipient using LINE's E2EE v2 envelope.
func (s *E2EEService) EncryptMessage(
	ctx context.Context,
	from,
	to string,
	data any,
	contentType types.ContentType,
	contentMetadata map[string]string,
) (*E2EEEncryptedMessage, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("line e2ee encrypt message: client is nil")
	}
	if from == "" || to == "" {
		return nil, fmt.Errorf("line e2ee encrypt message: sender and recipient MIDs are required")
	}
	selfKey, found, err := s.GetSelfKey(ctx, from)
	if err != nil {
		return nil, fmt.Errorf("line e2ee encrypt message: load sender key: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("line e2ee encrypt message: no local key is stored for account %q", from)
	}
	var receiverKeyID int32
	var specVersion int32 = 2
	var shared []byte
	if isUserMID(to) {
		peer, err := s.getPeerPublicKey(ctx, to, nil)
		if err != nil {
			return nil, fmt.Errorf("line e2ee encrypt message: load recipient key: %w", err)
		}
		receiverKeyID = peer.keyID
		specVersion = peer.specVersion
		shared, err = cryptoe2ee.SharedSecret(selfKey.PrivateKey, peer.publicKey)
	} else {
		groupKey, err := s.GroupKey(ctx, from, to, nil)
		if err != nil {
			return nil, fmt.Errorf("line e2ee encrypt message: load group key: %w", err)
		}
		receiverKeyID = groupKey.KeyID
		if groupKey.SpecVersion > 0 {
			specVersion = groupKey.SpecVersion
		}
		shared, err = cryptoe2ee.SharedSecret(groupKey.PrivateKey, selfKey.PublicKey)
	}
	if err != nil {
		return nil, err
	}
	plaintext, err := e2eePayload(data, contentType)
	if err != nil {
		return nil, fmt.Errorf("line e2ee encrypt message: encode payload: %w", err)
	}
	salt, err := cryptoe2ee.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	nonce, err := cryptoe2ee.RandomBytes(12)
	if err != nil {
		return nil, err
	}
	keyInput := make([]byte, 0, len(shared)+len(salt)+3)
	keyInput = append(keyInput, shared...)
	keyInput = append(keyInput, salt...)
	keyInput = append(keyInput, "Key"...)
	gcmKey := sha256.Sum256(keyInput)
	additionalData := generateE2EEAAD(to, from, selfKey.KeyID, receiverKeyID, specVersion, int32(contentType))
	ciphertext, err := cryptoe2ee.EncryptGCM(gcmKey[:], nonce, plaintext, additionalData)
	if err != nil {
		return nil, err
	}
	return &E2EEEncryptedMessage{
		Chunks: [][]byte{
			salt,
			ciphertext,
			nonce,
			encodeE2EEKeyID(selfKey.KeyID),
			encodeE2EEKeyID(receiverKeyID),
		},
		ContentMetadata: e2eeContentMetadata(contentMetadata, contentType),
		SpecVersion:     specVersion,
	}, nil
}

// DecryptMessage decrypts an incoming or self-sent E2EE Talk message in place.
func (s *E2EEService) DecryptMessage(ctx context.Context, selfMID string, message *types.Message) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("line e2ee decrypt message: client is nil")
	}
	if message == nil || message.From == nil || message.To == nil || message.ContentType == nil {
		return fmt.Errorf("line e2ee decrypt message: message is missing sender, recipient, or content type")
	}
	if selfMID == "" {
		return fmt.Errorf("line e2ee decrypt message: account MID is empty")
	}
	toIsUser := isUserMID(*message.To)
	if message.ToType != nil {
		toIsUser = *message.ToType == types.MIDTypeUSER
	}
	if len(message.Chunks) < 5 {
		return fmt.Errorf("line e2ee decrypt message: received %d chunks, want at least 5", len(message.Chunks))
	}
	senderKeyID, err := decodeE2EEKeyID(message.Chunks[3])
	if err != nil {
		return fmt.Errorf("line e2ee decrypt message: decode sender key id: %w", err)
	}
	receiverKeyID, err := decodeE2EEKeyID(message.Chunks[4])
	if err != nil {
		return fmt.Errorf("line e2ee decrypt message: decode receiver key id: %w", err)
	}
	isSelf := *message.From == selfMID
	selfKeyID := receiverKeyID
	peerMID := *message.From
	peerKeyID := senderKeyID
	if isSelf {
		selfKeyID = senderKeyID
		peerMID = *message.To
		peerKeyID = receiverKeyID
	}
	var selfKey *E2EEKey
	var found bool
	if toIsUser {
		selfKey, found, err = s.GetKey(ctx, selfKeyID)
		if err != nil {
			return err
		}
	}
	if !found {
		selfKey, found, err = s.GetSelfKey(ctx, selfMID)
		if err != nil {
			return err
		}
	}
	if !found {
		return fmt.Errorf("line e2ee decrypt message: local key %d is unavailable", selfKeyID)
	}
	var shared []byte
	if toIsUser {
		peer, err := s.getPeerPublicKey(ctx, peerMID, &peerKeyID)
		if err != nil {
			return fmt.Errorf("line e2ee decrypt message: load sender key: %w", err)
		}
		shared, err = cryptoe2ee.SharedSecret(selfKey.PrivateKey, peer.publicKey)
	} else {
		groupKey, groupErr := s.GroupKey(ctx, selfMID, *message.To, &receiverKeyID)
		if groupErr != nil {
			return fmt.Errorf("line e2ee decrypt message: load group key: %w", groupErr)
		}
		peerPublicKey := selfKey.PublicKey
		if !isSelf {
			peer, peerErr := s.getPeerPublicKey(ctx, peerMID, &peerKeyID)
			if peerErr != nil {
				return fmt.Errorf("line e2ee decrypt message: load sender key: %w", peerErr)
			}
			peerPublicKey = peer.publicKey
		}
		shared, err = cryptoe2ee.SharedSecret(groupKey.PrivateKey, peerPublicKey)
	}
	if err != nil {
		return err
	}
	metadata := message.ContentMetadata
	if metadata == nil {
		metadata = make(map[string]string)
	}
	version := metadata["e2eeVersion"]
	if version == "" {
		version = "2"
	}
	var plaintext []byte
	if version == "2" {
		if len(message.Chunks[0]) != 16 || len(message.Chunks[2]) != 12 {
			return fmt.Errorf("line e2ee decrypt message: invalid v2 salt or nonce size")
		}
		keyInput := make([]byte, 0, len(shared)+len(message.Chunks[0])+3)
		keyInput = append(keyInput, shared...)
		keyInput = append(keyInput, message.Chunks[0]...)
		keyInput = append(keyInput, "Key"...)
		gcmKey := sha256.Sum256(keyInput)
		additionalData := generateE2EEAAD(
			*message.To,
			*message.From,
			senderKeyID,
			receiverKeyID,
			2,
			int32(*message.ContentType),
		)
		plaintext, err = cryptoe2ee.DecryptGCM(gcmKey[:], message.Chunks[2], message.Chunks[1], additionalData)
	} else {
		plaintext, err = decryptE2EEV1(shared, message.Chunks[0], message.Chunks[1])
	}
	if err != nil {
		return err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return fmt.Errorf("line e2ee decrypt message: decode JSON payload: %w", err)
	}
	if text, ok := payload["text"]; ok {
		var decoded string
		if err := json.Unmarshal(text, &decoded); err != nil {
			return fmt.Errorf("line e2ee decrypt message: decode text: %w", err)
		}
		message.Text = &decoded
	}
	if location, ok := payload["location"]; ok {
		var decoded types.Location
		if err := json.Unmarshal(location, &decoded); err != nil {
			return fmt.Errorf("line e2ee decrypt message: decode location: %w", err)
		}
		message.Location = &decoded
	}
	for name, value := range payload {
		if name == "text" {
			continue
		}
		var decoded string
		if err := json.Unmarshal(value, &decoded); err == nil {
			metadata[name] = decoded
			continue
		}
		metadata[name] = string(value)
	}
	message.ContentMetadata = metadata
	return nil
}

// E2EEMediaMessageData is the encrypted message descriptor needed to retrieve
// and decrypt its separately stored media object.
type E2EEMediaMessageData struct {
	FileName    string
	KeyMaterial string
}

// DecryptMediaMessageData decrypts the E2EE message envelope that carries a
// media filename and file key, without mutating the caller's message DTO.
func (s *E2EEService) DecryptMediaMessageData(
	ctx context.Context,
	selfMID string,
	message *types.Message,
) (E2EEMediaMessageData, error) {
	if message == nil {
		return E2EEMediaMessageData{}, fmt.Errorf("line e2ee media: message is nil")
	}
	copyMessage := *message
	copyMessage.ContentMetadata = cloneTalkMetadata(message.ContentMetadata)
	if err := s.DecryptMessage(ctx, selfMID, &copyMessage); err != nil {
		return E2EEMediaMessageData{}, fmt.Errorf("line e2ee media: decrypt message descriptor: %w", err)
	}
	data := E2EEMediaMessageData{
		FileName:    copyMessage.ContentMetadata["fileName"],
		KeyMaterial: copyMessage.ContentMetadata["keyMaterial"],
	}
	if data.FileName == "" || data.KeyMaterial == "" {
		return E2EEMediaMessageData{}, fmt.Errorf("line e2ee media: decrypted message is missing filename or key material")
	}
	return data, nil
}

type e2eePeerPublicKey struct {
	keyID       int32
	publicKey   []byte
	specVersion int32
}

func (s *E2EEService) getPeerPublicKey(ctx context.Context, mid string, requestedKeyID *int32) (e2eePeerPublicKey, error) {
	if !isUserMID(mid) {
		return e2eePeerPublicKey{}, fmt.Errorf("MID %q is not a user MID", mid)
	}
	if requestedKeyID != nil {
		cacheKey := storage.KeyE2EEPublicKey(mid + ":" + strconv.FormatInt(int64(*requestedKeyID), 10))
		value, found, err := s.client.storage.Get(ctx, cacheKey)
		if err != nil {
			return e2eePeerPublicKey{}, err
		}
		if found {
			encoded, ok := value.(string)
			if !ok {
				return e2eePeerPublicKey{}, fmt.Errorf("cached public key has type %T, want string", value)
			}
			key, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return e2eePeerPublicKey{}, fmt.Errorf("decode cached public key: %w", err)
			}
			return e2eePeerPublicKey{keyID: *requestedKeyID, publicKey: key, specVersion: 2}, nil
		}
	}
	result, err := s.client.Talk().NegotiateE2EEPublicKey(ctx, types.NegotiateE2EEPublicKeyArgs{Mid: stringPointer(mid)})
	if err != nil {
		return e2eePeerPublicKey{}, err
	}
	if result.Success == nil || result.Success.PublicKey == nil || result.Success.PublicKey.KeyId == nil || result.Success.PublicKey.KeyData == nil {
		return e2eePeerPublicKey{}, fmt.Errorf("E2EE key negotiation returned an incomplete public key")
	}
	if result.Success.SpecVersion != nil && *result.Success.SpecVersion == -1 {
		return e2eePeerPublicKey{}, fmt.Errorf("recipient %q does not support E2EE", mid)
	}
	keyID := *result.Success.PublicKey.KeyId
	if requestedKeyID != nil && keyID != *requestedKeyID {
		return e2eePeerPublicKey{}, fmt.Errorf("recipient %q has key id %d, message requires key id %d", mid, keyID, *requestedKeyID)
	}
	publicKey := append([]byte(nil), (*result.Success.PublicKey.KeyData)...)
	if len(publicKey) != 32 {
		return e2eePeerPublicKey{}, fmt.Errorf("recipient %q public key has length %d, want 32", mid, len(publicKey))
	}
	version := int32(2)
	if result.Success.SpecVersion != nil {
		version = *result.Success.SpecVersion
	}
	cacheKey := storage.KeyE2EEPublicKey(mid + ":" + strconv.FormatInt(int64(keyID), 10))
	if err := s.client.storage.Set(ctx, cacheKey, base64.StdEncoding.EncodeToString(publicKey)); err != nil {
		return e2eePeerPublicKey{}, fmt.Errorf("persist recipient public key: %w", err)
	}
	return e2eePeerPublicKey{keyID: keyID, publicKey: publicKey, specVersion: version}, nil
}

// GroupKey loads a requested group-key generation, fetches the current
// generation, or registers one when the group has none yet.
func (s *E2EEService) GroupKey(
	ctx context.Context,
	selfMID,
	chatMID string,
	requestedKeyID *int32,
) (*E2EEGroupKey, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("line e2ee group key: client is nil")
	}
	if selfMID == "" || chatMID == "" {
		return nil, fmt.Errorf("line e2ee group key: account and chat MIDs are required")
	}
	if requestedKeyID != nil {
		if cached, found, err := s.cachedGroupKey(ctx, chatMID, *requestedKeyID); err != nil {
			return nil, err
		} else if found {
			return cached, nil
		}
		result, err := s.client.Talk().GetE2EEGroupSharedKey(ctx, types.GetE2EEGroupSharedKeyArgs{
			KeyVersion: int32Pointer(2),
			ChatMid:    stringPointer(chatMID),
			GroupKeyId: requestedKeyID,
		})
		if err == nil && result != nil && result.Success != nil {
			return s.unwrapGroupKey(ctx, selfMID, chatMID, result.Success)
		}
		if err != nil && !isE2EEKeyNotFound(err) {
			return nil, fmt.Errorf("line e2ee group key: fetch generation %d: %w", *requestedKeyID, err)
		}
	}
	last, err := s.client.Talk().GetLastE2EEGroupSharedKey(ctx, types.GetLastE2EEGroupSharedKeyArgs{
		KeyVersion: int32Pointer(2),
		ChatMid:    stringPointer(chatMID),
	})
	if err == nil && last != nil && last.Success != nil {
		return s.unwrapGroupKey(ctx, selfMID, chatMID, last.Success)
	}
	if err != nil && !isE2EEKeyNotFound(err) {
		return nil, fmt.Errorf("line e2ee group key: fetch latest generation: %w", err)
	}
	return s.TryRegisterGroupKey(ctx, selfMID, chatMID)
}

// TryRegisterGroupKey creates a group shared secret, encrypts a copy for each
// currently registered group member, and registers the wrapped copies with LINE.
func (s *E2EEService) TryRegisterGroupKey(ctx context.Context, selfMID, chatMID string) (*E2EEGroupKey, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("line e2ee register group key: client is nil")
	}
	result, err := s.client.Talk().GetLastE2EEPublicKeys(ctx, types.GetLastE2EEPublicKeysArgs{
		ChatMid: stringPointer(chatMID),
	})
	if err != nil {
		return nil, fmt.Errorf("line e2ee register group key: load member public keys: %w", err)
	}
	if result == nil || len(result.Success) == 0 {
		return nil, fmt.Errorf("line e2ee register group key: LINE returned no member public keys")
	}
	selfPublicKey := result.Success[selfMID]
	if selfPublicKey == nil || selfPublicKey.KeyId == nil {
		return nil, fmt.Errorf("line e2ee register group key: account %q has no registered public key", selfMID)
	}
	selfKey, found, err := s.GetKey(ctx, *selfPublicKey.KeyId)
	if err != nil {
		return nil, err
	}
	if !found {
		selfKey, found, err = s.GetSelfKey(ctx, selfMID)
		if err != nil {
			return nil, err
		}
	}
	if !found || selfKey.KeyID != *selfPublicKey.KeyId {
		return nil, fmt.Errorf("line e2ee register group key: local key %d is unavailable", *selfPublicKey.KeyId)
	}
	groupPrivateKey, err := cryptoe2ee.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	members := make([]string, 0, len(result.Success))
	keyIDs := make([]int32, 0, len(result.Success))
	encryptedKeys := make([][]byte, 0, len(result.Success))
	for mid, publicKey := range result.Success {
		if publicKey == nil || publicKey.KeyId == nil || publicKey.KeyData == nil {
			return nil, fmt.Errorf("line e2ee register group key: member %q has an incomplete public key", mid)
		}
		shared, err := cryptoe2ee.SharedSecret(selfKey.PrivateKey, *publicKey.KeyData)
		if err != nil {
			return nil, fmt.Errorf("line e2ee register group key: derive member %q secret: %w", mid, err)
		}
		aesKey, aesIV := cryptoe2ee.GenerateSharedAESKey(shared)
		wrapped, err := cryptoe2ee.EncryptCBCPKCS7(aesKey, aesIV, groupPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("line e2ee register group key: wrap for member %q: %w", mid, err)
		}
		members = append(members, mid)
		keyIDs = append(keyIDs, *publicKey.KeyId)
		encryptedKeys = append(encryptedKeys, wrapped)
	}
	registered, err := s.client.Talk().RegisterE2EEGroupKey(ctx, types.RegisterE2EEGroupKeyArgs{
		KeyVersion:          int32Pointer(1),
		ChatMid:             stringPointer(chatMID),
		Members:             members,
		KeyIds:              keyIDs,
		EncryptedSharedKeys: encryptedKeys,
	})
	if err != nil {
		return nil, fmt.Errorf("line e2ee register group key: %w", err)
	}
	if registered == nil || registered.Success == nil {
		return nil, fmt.Errorf("line e2ee register group key: response has no key")
	}
	return s.unwrapGroupKey(ctx, selfMID, chatMID, registered.Success)
}

func (s *E2EEService) unwrapGroupKey(
	ctx context.Context,
	selfMID,
	chatMID string,
	wrapped *types.Pb1U3,
) (*E2EEGroupKey, error) {
	if wrapped == nil || wrapped.GroupKeyId == nil || wrapped.Creator == nil || wrapped.CreatorKeyId == nil ||
		wrapped.ReceiverKeyId == nil || wrapped.EncryptedSharedKey == nil {
		return nil, fmt.Errorf("line e2ee group key: server returned incomplete key material")
	}
	selfKey, found, err := s.GetKey(ctx, *wrapped.ReceiverKeyId)
	if err != nil {
		return nil, err
	}
	if !found {
		selfKey, found, err = s.GetSelfKey(ctx, selfMID)
		if err != nil {
			return nil, err
		}
	}
	if !found || selfKey.KeyID != *wrapped.ReceiverKeyId {
		return nil, fmt.Errorf("line e2ee group key: local receiver key %d is unavailable", *wrapped.ReceiverKeyId)
	}
	creator, err := s.getPeerPublicKey(ctx, *wrapped.Creator, wrapped.CreatorKeyId)
	if err != nil {
		return nil, fmt.Errorf("line e2ee group key: load creator public key: %w", err)
	}
	shared, err := cryptoe2ee.SharedSecret(selfKey.PrivateKey, creator.publicKey)
	if err != nil {
		return nil, err
	}
	aesKey, aesIV := cryptoe2ee.GenerateSharedAESKey(shared)
	groupPrivateKey, err := cryptoe2ee.DecryptCBCPKCS7(aesKey, aesIV, []byte(*wrapped.EncryptedSharedKey))
	if err != nil {
		return nil, fmt.Errorf("line e2ee group key: unwrap shared key: %w", err)
	}
	version := int32(2)
	if wrapped.SpecVersion != nil {
		version = *wrapped.SpecVersion
	}
	groupKey := &E2EEGroupKey{PrivateKey: groupPrivateKey, KeyID: *wrapped.GroupKeyId, SpecVersion: version}
	if err := s.saveGroupKey(ctx, chatMID, groupKey); err != nil {
		return nil, fmt.Errorf("line e2ee group key: persist key: %w", err)
	}
	return groupKey, nil
}

func (s *E2EEService) cachedGroupKey(ctx context.Context, chatMID string, keyID int32) (*E2EEGroupKey, bool, error) {
	cacheKey := fmt.Sprintf("e2eeGroupKeys:%s:%d", chatMID, keyID)
	value, found, err := s.client.storage.Get(ctx, cacheKey)
	if err != nil || !found {
		return nil, found, err
	}
	encoded, ok := value.(string)
	if !ok {
		return nil, true, fmt.Errorf("line e2ee group key: cached key has type %T, want string", value)
	}
	var key E2EEGroupKey
	if err := json.Unmarshal([]byte(encoded), &key); err != nil {
		return nil, true, fmt.Errorf("line e2ee group key: decode cached key: %w", err)
	}
	if key.KeyID != keyID || len(key.PrivateKey) != 32 {
		return nil, true, fmt.Errorf("line e2ee group key: cached key %d is inconsistent", keyID)
	}
	return &key, true, nil
}

func (s *E2EEService) saveGroupKey(ctx context.Context, chatMID string, key *E2EEGroupKey) error {
	if key == nil {
		return fmt.Errorf("group key is nil")
	}
	encoded, err := json.Marshal(key)
	if err != nil {
		return err
	}
	if err := s.client.storage.Set(ctx, fmt.Sprintf("e2eeGroupKeys:%s:%d", chatMID, key.KeyID), string(encoded)); err != nil {
		return err
	}
	return s.client.storage.Set(ctx, storage.KeyE2EEGroupKey(chatMID), string(encoded))
}

func isE2EEKeyNotFound(err error) bool {
	var serviceError *ServiceError
	return errors.As(err, &serviceError) && serviceError.Code == int32(types.ErrorCodeNOTFOUND)
}

func e2eePayload(data any, contentType types.ContentType) ([]byte, error) {
	var payload any
	switch value := data.(type) {
	case string:
		payload = map[string]string{"text": value}
	case *types.Location:
		payload = map[string]*types.Location{"location": value}
	case types.Location:
		payload = map[string]types.Location{"location": value}
	default:
		payload = data
	}
	if contentType == types.ContentTypeLOCATION {
		switch data.(type) {
		case *types.Location, types.Location:
		default:
			return nil, fmt.Errorf("location content requires a Location payload")
		}
	}
	return json.Marshal(payload)
}

func e2eeContentMetadata(source map[string]string, contentType types.ContentType) map[string]string {
	result := make(map[string]string, len(source)+3)
	for key, value := range source {
		result[key] = value
	}
	result["e2eeVersion"] = "2"
	result["contentType"] = strconv.FormatInt(int64(contentType), 10)
	result["e2eeMark"] = "2"
	return result
}

func generateE2EEAAD(to, from string, senderKeyID, receiverKeyID, specVersion, contentType int32) []byte {
	result := make([]byte, 0, len(to)+len(from)+20)
	result = append(result, to...)
	result = append(result, from...)
	var encoded [4]byte
	for _, value := range []int32{senderKeyID, receiverKeyID, specVersion, contentType} {
		binary.BigEndian.PutUint32(encoded[:], uint32(value))
		result = append(result, encoded[:]...)
	}
	return result
}

func encodeE2EEKeyID(keyID int32) []byte {
	encoded := make([]byte, 4)
	binary.BigEndian.PutUint32(encoded, uint32(keyID))
	return encoded
}

func decodeE2EEKeyID(encoded []byte) (int32, error) {
	if len(encoded) != 4 {
		return 0, fmt.Errorf("key id chunk has length %d, want 4", len(encoded))
	}
	return int32(binary.BigEndian.Uint32(encoded)), nil
}

func isUserMID(mid string) bool {
	return len(mid) > 1 && mid[0] == 'u'
}

func decryptE2EEV1(shared, salt, ciphertext []byte) ([]byte, error) {
	keyInput := make([]byte, 0, len(shared)+len(salt)+3)
	keyInput = append(keyInput, shared...)
	keyInput = append(keyInput, salt...)
	keyInput = append(keyInput, "Key"...)
	aesKey := sha256.Sum256(keyInput)
	ivInput := make([]byte, 0, len(shared)+len(salt)+2)
	ivInput = append(ivInput, shared...)
	ivInput = append(ivInput, salt...)
	ivInput = append(ivInput, "IV"...)
	ivHash := sha256.Sum256(ivInput)
	iv := make([]byte, 16)
	for index := range iv {
		iv[index] = ivHash[index] ^ ivHash[index+16]
	}
	plaintext, err := cryptoe2ee.DecryptCBC(aesKey[:], iv, ciphertext)
	if err != nil {
		return nil, err
	}
	padding := int(plaintext[len(plaintext)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(plaintext) {
		return plaintext, nil
	}
	for _, value := range plaintext[len(plaintext)-padding:] {
		if int(value) != padding {
			return plaintext, nil
		}
	}
	return plaintext[:len(plaintext)-padding], nil
}

func (s *E2EEService) saveKey(ctx context.Context, key *E2EEKey) error {
	if key == nil {
		return fmt.Errorf("key is nil")
	}
	stored := persistedE2EEKey{
		KeyID:       key.KeyID,
		PrivateKey:  base64.StdEncoding.EncodeToString(key.PrivateKey),
		PublicKey:   base64.StdEncoding.EncodeToString(key.PublicKey),
		E2EEVersion: key.E2EEVersion,
	}
	encoded, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	return s.client.storage.Set(ctx, storage.KeyE2EEPrivateKey(strconv.FormatInt(int64(key.KeyID), 10)), string(encoded))
}

func decodeStoredE2EEKey(value string) (*E2EEKey, error) {
	var stored persistedE2EEKey
	if err := json.Unmarshal([]byte(value), &stored); err != nil {
		return nil, fmt.Errorf("decode stored key: %w", err)
	}
	privateKey, err := base64.StdEncoding.DecodeString(stored.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(stored.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if !cryptoe2ee.VerifyKeyPair(privateKey, publicKey) {
		return nil, fmt.Errorf("stored key %d is not a valid X25519 key pair", stored.KeyID)
	}
	return &E2EEKey{
		KeyID:       stored.KeyID,
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
		E2EEVersion: stored.E2EEVersion,
	}, nil
}

func cloneE2EEKey(key *E2EEKey) *E2EEKey {
	if key == nil {
		return nil
	}
	return &E2EEKey{
		KeyID:       key.KeyID,
		PrivateKey:  append([]byte(nil), key.PrivateKey...),
		PublicKey:   append([]byte(nil), key.PublicKey...),
		E2EEVersion: key.E2EEVersion,
	}
}
