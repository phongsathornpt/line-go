package storage

// Well-known keys used by the LINEJS client.
const (
	KeyCertificate       = "cert"
	KeyQRCodeCertificate = "qrCert"
	KeyRefreshToken      = "refreshToken"
	KeyExpiresAt         = "expire"
	KeyRequestSequence   = "reqseq"
)

// KeyE2EEPrivateKey returns the storage key for a local E2EE key pair.
func KeyE2EEPrivateKey(keyID string) string {
	return "e2eeKeys:" + keyID
}

// KeyE2EEPublicKey returns the storage key for a cached peer E2EE key.
func KeyE2EEPublicKey(keyID string) string {
	return "e2eePublicKeys:" + keyID
}

// KeyE2EEGroupKey returns the storage key for an E2EE group key.
func KeyE2EEGroupKey(chatMID string) string {
	return "e2eeGroupKeys:" + chatMID
}
