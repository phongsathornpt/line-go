// Package e2ee contains the cryptographic primitives used by LINE's E2EE
// login and message-key workflows.
package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// EncryptMedia encrypts a file payload with LINE's E2EE Next file format. The
// returned bytes are AES-CTR ciphertext followed by its HMAC-SHA256 tag.
func EncryptMedia(plaintext, keyMaterial []byte) (encrypted, material []byte, err error) {
	if len(keyMaterial) == 0 {
		keyMaterial, err = RandomBytes(32)
		if err != nil {
			return nil, nil, err
		}
	}
	if len(keyMaterial) != 32 {
		return nil, nil, fmt.Errorf("e2ee media: key material has %d bytes, want 32", len(keyMaterial))
	}
	encKey, macKey, counter := deriveMediaKeys(keyMaterial)
	ciphertext, err := cryptMediaCTR(encKey, counter, plaintext)
	if err != nil {
		return nil, nil, err
	}
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(ciphertext)
	return append(ciphertext, mac.Sum(nil)...), append([]byte(nil), keyMaterial...), nil
}

// DecryptMedia verifies and decrypts LINE's E2EE Next file format.
func DecryptMedia(encrypted, keyMaterial []byte) ([]byte, error) {
	if len(keyMaterial) != 32 {
		return nil, fmt.Errorf("e2ee media: key material has %d bytes, want 32", len(keyMaterial))
	}
	if len(encrypted) < sha256.Size {
		return nil, fmt.Errorf("e2ee media: encrypted payload is %d bytes, shorter than its MAC", len(encrypted))
	}
	encKey, macKey, counter := deriveMediaKeys(keyMaterial)
	ciphertext := encrypted[:len(encrypted)-sha256.Size]
	signature := encrypted[len(encrypted)-sha256.Size:]
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(ciphertext)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, fmt.Errorf("e2ee media: HMAC verification failed")
	}
	return cryptMediaCTR(encKey, counter, ciphertext)
}

func deriveMediaKeys(keyMaterial []byte) (encKey, macKey, counter []byte) {
	// RFC 5869 HKDF-SHA256 with empty salt and LINE's FileEncryption info.
	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	_, _ = extract.Write(keyMaterial)
	prk := extract.Sum(nil)
	info := []byte("FileEncryption")
	derived := make([]byte, 0, 76)
	var previous []byte
	for block := byte(1); len(derived) < cap(derived); block++ {
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(previous)
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{block})
		previous = expand.Sum(nil)
		derived = append(derived, previous...)
	}
	derived = derived[:76]
	counter = make([]byte, aes.BlockSize)
	copy(counter, derived[64:76])
	return derived[:32], derived[32:64], counter
}

func cryptMediaCTR(key, counter, input []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("e2ee media: initialize AES: %w", err)
	}
	output := make([]byte, len(input))
	cipher.NewCTR(block, counter).XORKeyStream(output, input)
	return output, nil
}

// KeyPair is an X25519 key pair in the raw 32-byte representation used by
// TweetNaCl and LINE's E2EE Thrift fields.
type KeyPair struct {
	Private []byte
	Public  []byte
}

// GenerateKeyPair creates a random X25519 key pair.
func GenerateKeyPair() (KeyPair, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("e2ee: generate X25519 key: %w", err)
	}
	return KeyPair{
		Private: privateKey.Bytes(),
		Public:  privateKey.PublicKey().Bytes(),
	}, nil
}

// SharedSecret derives the X25519 shared secret from raw key bytes.
func SharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	private, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("e2ee: invalid X25519 private key: %w", err)
	}
	public, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("e2ee: invalid X25519 public key: %w", err)
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, fmt.Errorf("e2ee: derive X25519 shared secret: %w", err)
	}
	return shared, nil
}

// VerifyKeyPair reports whether publicKey is derived from privateKey.
func VerifyKeyPair(privateKey, publicKey []byte) bool {
	if len(privateKey) != 32 || len(publicKey) != 32 {
		return false
	}
	private, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return false
	}
	return equalBytes(private.PublicKey().Bytes(), publicKey)
}

// GenerateSharedAESKey derives LINE's AES-CBC key and IV from an X25519
// shared secret.
func GenerateSharedAESKey(sharedSecret []byte) ([]byte, []byte) {
	keyHash := sha256.Sum256(appendCopy(sharedSecret, []byte("Key")...))
	ivHash := sha256.Sum256(appendCopy(sharedSecret, []byte("IV")...))
	iv := make([]byte, aes.BlockSize)
	for index := range iv {
		iv[index] = ivHash[index] ^ ivHash[index+aes.BlockSize]
	}
	return keyHash[:], iv
}

// DecryptCBC decrypts AES-CBC data without PKCS#7 padding. LINE's encrypted
// key chains contain their own fixed-size Thrift values and use no padding.
func DecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("e2ee: create AES-CBC cipher: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("e2ee: AES-CBC IV has length %d, want %d", len(iv), aes.BlockSize)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("e2ee: AES-CBC input length %d is not a positive block multiple", len(ciphertext))
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

// EncryptCBC encrypts AES-CBC data without padding. plaintext must already be
// aligned to the AES block size, matching LINE's key-chain format.
func EncryptCBC(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("e2ee: create AES-CBC cipher: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("e2ee: AES-CBC IV has length %d, want %d", len(iv), aes.BlockSize)
	}
	if len(plaintext) == 0 || len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("e2ee: AES-CBC input length %d is not a positive block multiple", len(plaintext))
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// EncryptCBCPKCS7 applies PKCS#7 padding before AES-CBC encryption, matching
// Node's default createCipheriv padding behavior used for wrapped group keys.
func EncryptCBCPKCS7(key, iv, plaintext []byte) ([]byte, error) {
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for index := len(plaintext); index < len(padded); index++ {
		padded[index] = byte(padding)
	}
	return EncryptCBC(key, iv, padded)
}

// DecryptCBCPKCS7 decrypts AES-CBC data and removes valid PKCS#7 padding.
func DecryptCBCPKCS7(key, iv, ciphertext []byte) ([]byte, error) {
	plaintext, err := DecryptCBC(key, iv, ciphertext)
	if err != nil {
		return nil, err
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("e2ee: AES-CBC plaintext is empty")
	}
	padding := int(plaintext[len(plaintext)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(plaintext) {
		return nil, fmt.Errorf("e2ee: invalid PKCS#7 padding size %d", padding)
	}
	for _, value := range plaintext[len(plaintext)-padding:] {
		if int(value) != padding {
			return nil, fmt.Errorf("e2ee: invalid PKCS#7 padding byte")
		}
	}
	return plaintext[:len(plaintext)-padding], nil
}

// EncryptECB encrypts AES-ECB data without padding, as required by LINE's
// device-secret handshake.
func EncryptECB(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("e2ee: create AES-ECB cipher: %w", err)
	}
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("e2ee: AES-ECB input length %d is not a block multiple", len(plaintext))
	}
	ciphertext := make([]byte, len(plaintext))
	for offset := 0; offset < len(plaintext); offset += aes.BlockSize {
		block.Encrypt(ciphertext[offset:offset+aes.BlockSize], plaintext[offset:offset+aes.BlockSize])
	}
	return ciphertext, nil
}

// DecryptECB decrypts AES-ECB data without padding.
func DecryptECB(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("e2ee: create AES-ECB cipher: %w", err)
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("e2ee: AES-ECB input length %d is not a block multiple", len(ciphertext))
	}
	plaintext := make([]byte, len(ciphertext))
	for offset := 0; offset < len(ciphertext); offset += aes.BlockSize {
		block.Decrypt(plaintext[offset:offset+aes.BlockSize], ciphertext[offset:offset+aes.BlockSize])
	}
	return plaintext, nil
}

// EncryptGCM authenticates and encrypts plaintext with AES-GCM. The returned
// slice uses LINE's wire layout: ciphertext followed by the authentication tag.
func EncryptGCM(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("e2ee: create AES-GCM cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("e2ee: create AES-GCM mode: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("e2ee: AES-GCM nonce has length %d, want %d", len(nonce), aead.NonceSize())
	}
	return aead.Seal(nil, nonce, plaintext, additionalData), nil
}

// DecryptGCM authenticates and decrypts LINE's ciphertext-plus-tag layout.
func DecryptGCM(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("e2ee: create AES-GCM cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("e2ee: create AES-GCM mode: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("e2ee: AES-GCM nonce has length %d, want %d", len(nonce), aead.NonceSize())
	}
	if len(ciphertext) < aead.Overhead() {
		return nil, fmt.Errorf("e2ee: AES-GCM ciphertext is shorter than its %d-byte tag", aead.Overhead())
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("e2ee: authenticate AES-GCM message: %w", err)
	}
	return plaintext, nil
}

// XORSplitHalves XORs the two equal halves of a buffer.
func XORSplitHalves(value []byte) ([]byte, error) {
	if len(value) == 0 || len(value)%2 != 0 {
		return nil, fmt.Errorf("e2ee: XOR input length %d must be positive and even", len(value))
	}
	half := len(value) / 2
	result := make([]byte, half)
	for index := range result {
		result[index] = value[index] ^ value[index+half]
	}
	return result, nil
}

// RandomBytes returns cryptographically secure random bytes. It is exposed for
// E2EE protocol values that LINE expects to be random but not key pairs.
func RandomBytes(length int) ([]byte, error) {
	if length < 0 {
		return nil, fmt.Errorf("e2ee: random byte count cannot be negative")
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return nil, fmt.Errorf("e2ee: read random bytes: %w", err)
	}
	return value, nil
}

func appendCopy(value []byte, suffix ...byte) []byte {
	result := make([]byte, 0, len(value)+len(suffix))
	result = append(result, value...)
	return append(result, suffix...)
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
