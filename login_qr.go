package line

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/phongsathornpt/line-go/base"
)

// SecureQRLoginOptions controls the user-visible QR and PIN callbacks, plus
// optional long-poll overrides. Zero poll values use LINE's response defaults.
type SecureQRLoginOptions struct {
	OnQRCode     func(string)
	OnPinCode    func(string)
	PollCount    int
	PollInterval time.Duration
}

// LoginWithQR selects LINEJS's secure or legacy QR flow from the configured
// device profile. Devices with token-v3 QR support use ForSecure; older device
// profiles use the legacy challenge methods.
func LoginWithQR(ctx context.Context, clientOptions ClientOptions, loginOptions SecureQRLoginOptions) (*Client, error) {
	if supportsSecureQR(clientOptions.Device) {
		return LoginWithSecureQR(ctx, clientOptions, loginOptions)
	}
	return LoginWithLegacyQR(ctx, clientOptions, loginOptions)
}

// LoginWithLegacyQR runs the pre-ForSecure QR flow used by older LINE device
// profiles and returns a client with its profile loaded.
func LoginWithLegacyQR(
	ctx context.Context,
	clientOptions ClientOptions,
	loginOptions SecureQRLoginOptions,
) (*Client, error) {
	client, err := NewClient(clientOptions)
	if err != nil {
		return nil, err
	}
	loginService := client.base.Login()
	sessionID, err := loginService.CreateSession(ctx)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line QR login: create session: %w", err))
	}
	callbackURL, err := loginService.CreateQrCode(ctx, sessionID)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line QR login: create QR code: %w", err))
	}
	secret, suffix, err := client.base.E2EE().CreateQRSecret()
	if err != nil {
		return closeAfterLoginFailure(client, err)
	}
	if loginOptions.OnQRCode != nil {
		loginOptions.OnQRCode(callbackURL + suffix)
	}
	pollCount := loginOptions.PollCount
	if pollCount <= 0 {
		pollCount = 1
	}
	pollInterval := loginOptions.PollInterval
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second
	}
	verified, err := loginService.CheckQrCodeVerified(ctx, sessionID, pollCount, pollInterval)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line QR login: wait for QR approval: %w", err))
	}
	if !verified {
		return closeAfterLoginFailure(client, fmt.Errorf("line QR login: approval polling expired"))
	}
	certificate, _, err := loginService.GetQrCertificate(ctx)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line QR login: load certificate: %w", err))
	}
	if err := loginService.VerifyCertificate(ctx, sessionID, certificate); err != nil {
		pin, pinErr := loginService.CreatePinCode(ctx, sessionID)
		if pinErr != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line QR login: create fallback PIN: %w (certificate verification: %v)", pinErr, err))
		}
		if loginOptions.OnPinCode != nil {
			loginOptions.OnPinCode(pin)
		}
		verified, pinErr = loginService.CheckPinCodeVerified(ctx, sessionID, pollCount, pollInterval)
		if pinErr != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line QR login: wait for PIN approval: %w", pinErr))
		}
		if !verified {
			return closeAfterLoginFailure(client, fmt.Errorf("line QR login: PIN approval polling expired"))
		}
	}
	credentials, err := loginService.QrCodeLoginV2(ctx, sessionID)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line QR login: exchange challenge: %w", err))
	}
	if credentials.Certificate != "" {
		if err := loginService.StoreQrCertificate(ctx, credentials.Certificate); err != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line QR login: persist certificate: %w", err))
		}
	}
	client.base.SetAuthToken(credentials.AccessToken)
	if credentials.RefreshToken != "" {
		if err := client.base.Storage().Set(ctx, "refreshToken", credentials.RefreshToken); err != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line QR login: persist refresh token: %w", err))
		}
	}
	if credentials.ExpiresAt != nil {
		if err := client.base.Storage().Set(ctx, "expire", *credentials.ExpiresAt); err != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line QR login: persist expiry: %w", err))
		}
	}
	keychain, found, err := parseQRLoginKeyChain(credentials.Metadata, credentials.E2EEInfo)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line QR login: parse E2EE key chain: %w", err))
	}
	var selfKey *base.E2EEKey
	if found {
		selfKey, err = client.base.E2EE().DecryptLoginKeyChain(ctx, keychain, secret.PrivateKey)
	} else {
		selfKey, err = client.base.E2EE().RegisterKeyPair(ctx)
	}
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line QR login: initialize E2EE key: %w", err))
	}
	if err := client.base.E2EE().VerifyLoginKey(ctx); err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line QR login: verify E2EE key: %w", err))
	}
	profile, err := client.GetMyProfile(ctx)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line QR login: initialize profile: %w", err))
	}
	if err := client.base.E2EE().SaveSelfKey(ctx, profile.MID, selfKey); err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line QR login: persist account E2EE key: %w", err))
	}
	client.profile = profile
	return client, nil
}

// LoginWithSecureQR runs LINE's ForSecure QR login flow and returns a client
// with the authenticated profile loaded.
func LoginWithSecureQR(
	ctx context.Context,
	clientOptions ClientOptions,
	loginOptions SecureQRLoginOptions,
) (*Client, error) {
	client, err := NewClient(clientOptions)
	if err != nil {
		return nil, err
	}
	loginService := client.base.Login()
	sessionID, err := loginService.CreateSession(ctx)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: create session: %w", err))
	}
	challenge, err := loginService.CreateQrCodeForSecure(ctx, sessionID)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: create challenge: %w", err))
	}
	secret, suffix, err := client.base.E2EE().CreateQRSecret()
	if err != nil {
		return closeAfterLoginFailure(client, err)
	}
	if loginOptions.PollCount > 0 {
		challenge.LongPollCount = loginOptions.PollCount
	}
	if loginOptions.PollInterval > 0 {
		challenge.LongPollInterval = loginOptions.PollInterval
	}
	if loginOptions.OnQRCode != nil {
		loginOptions.OnQRCode(challenge.CallbackURL + suffix)
	}
	verified, err := loginService.CheckQrCodeVerified(ctx, sessionID, challenge.LongPollCount, challenge.LongPollInterval)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: wait for QR approval: %w", err))
	}
	if !verified {
		return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: QR approval polling expired"))
	}

	certificate, _, err := loginService.GetQrCertificate(ctx)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: load QR certificate: %w", err))
	}
	if err := loginService.VerifyCertificate(ctx, sessionID, certificate); err != nil {
		pin, pinErr := loginService.CreatePinCode(ctx, sessionID)
		if pinErr != nil {
			return closeAfterLoginFailure(client, fmt.Errorf(
				"line secure QR login: create fallback PIN: %w (certificate verification: %v)",
				pinErr,
				err,
			))
		}
		if loginOptions.OnPinCode != nil {
			loginOptions.OnPinCode(pin)
		}
		verified, pinErr = loginService.CheckPinCodeVerified(
			ctx,
			sessionID,
			challenge.LongPollCount,
			challenge.LongPollInterval,
		)
		if pinErr != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: wait for PIN approval: %w", pinErr))
		}
		if !verified {
			return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: PIN approval polling expired"))
		}
	}

	credentials, err := loginService.QrCodeLoginV2ForSecure(ctx, sessionID, challenge.Nonce)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: exchange challenge: %w", err))
	}
	if credentials.Certificate != "" {
		if err := loginService.StoreQrCertificate(ctx, credentials.Certificate); err != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: persist certificate: %w", err))
		}
	}
	client.base.SetAuthToken(credentials.AccessToken)
	if credentials.RefreshToken != "" {
		if err := client.base.Storage().Set(ctx, "refreshToken", credentials.RefreshToken); err != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: persist refresh token: %w", err))
		}
	}
	if credentials.ExpiresAt != nil {
		if err := client.base.Storage().Set(ctx, "expire", *credentials.ExpiresAt); err != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: persist expiry: %w", err))
		}
	}

	keychain, found, err := parseQRLoginKeyChain(credentials.Metadata, credentials.E2EEInfo)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: parse E2EE key chain: %w", err))
	}
	var selfKey *base.E2EEKey
	if found {
		selfKey, err = client.base.E2EE().DecryptLoginKeyChain(ctx, keychain, secret.PrivateKey)
		if err != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: restore E2EE key chain: %w", err))
		}
	} else {
		selfKey, err = client.base.E2EE().RegisterKeyPair(ctx)
		if err != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: register E2EE key: %w", err))
		}
	}
	if err := client.base.E2EE().VerifyLoginKey(ctx); err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: verify E2EE key: %w", err))
	}
	profile, err := client.GetMyProfile(ctx)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: initialize profile: %w", err))
	}
	if err := client.base.E2EE().SaveSelfKey(ctx, profile.MID, selfKey); err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line secure QR login: persist account E2EE key: %w", err))
	}
	client.profile = profile
	return client, nil
}

func parseQRLoginKeyChain(metadata map[string]string, directInfo any) (base.E2EELoginKeyChain, bool, error) {
	var raw string
	for key, value := range metadata {
		if strings.EqualFold(key, "e2eeInfo") {
			raw = value
			break
		}
	}
	if raw == "" {
		if text, ok := directInfo.(string); ok {
			raw = text
		}
	}
	if raw == "" {
		return base.E2EELoginKeyChain{}, false, nil
	}
	var data map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&data); err != nil {
		return base.E2EELoginKeyChain{}, false, nil
	}
	if nested, ok := data["metadata"].(map[string]any); ok {
		data = nested
	}
	keyID := jsonInt32(data["keyId"])
	publicKey := jsonString(data["publicKey"])
	encryptedKeyChain := jsonString(data["encryptedKeyChain"])
	e2eeVersion := jsonInt32(data["e2eeVersion"])
	if keyID == 0 || publicKey == "" || encryptedKeyChain == "" {
		return base.E2EELoginKeyChain{}, false, nil
	}
	publicBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return base.E2EELoginKeyChain{}, false, fmt.Errorf("decode public key: %w", err)
	}
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedKeyChain)
	if err != nil {
		return base.E2EELoginKeyChain{}, false, fmt.Errorf("decode encrypted key chain: %w", err)
	}
	return base.E2EELoginKeyChain{
		KeyID:             keyID,
		PublicKey:         publicBytes,
		EncryptedKeyChain: encryptedBytes,
		E2EEVersion:       e2eeVersion,
	}, true, nil
}

func jsonInt32(value any) int32 {
	switch typed := value.(type) {
	case json.Number:
		var parsed int64
		if value, err := typed.Int64(); err == nil && value >= -1<<31 && value <= 1<<31-1 {
			parsed = value
		}
		return int32(parsed)
	case float64:
		return int32(typed)
	default:
		return 0
	}
}

func jsonString(value any) string {
	text, _ := value.(string)
	return text
}

func closeAfterLoginFailure(client *Client, cause error) (*Client, error) {
	_ = client.Close()
	return nil, cause
}

func supportsSecureQR(device Device) bool {
	switch device {
	case DeviceDesktopWindows, DeviceDesktopMac, DeviceIOS, DeviceAndroid, DeviceAndroidSecondary:
		return true
	default:
		return false
	}
}
