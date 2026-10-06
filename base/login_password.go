package base

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"

	cryptoe2ee "github.com/phongsathornpt/line-go/internal/crypto/e2ee"
	"github.com/phongsathornpt/line-go/storage"
	"github.com/phongsathornpt/line-go/thrift"
	"github.com/phongsathornpt/line-go/types"
)

const (
	loginTalkPath       = "/api/v3/TalkService.do"
	loginV3Path         = "/api/v3p/rs"
	loginV4Path         = "/api/v4p/rs"
	loginV3VerifierPath = "/Q"
	loginE2EEInfoPath   = "/LF1"
	defaultLoginPIN     = "114514"
)

var loginEmailPattern = regexp.MustCompile("^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+([.][A-Za-z0-9-]+)*$")

// PasswordLoginOptions controls LINE email/password login. E2EE is enabled by
// default. V3 defaults on devices that support LINE's token-v3 login flow.
type PasswordLoginOptions struct {
	Email       string
	Password    string
	PinCode     string
	V3          *bool
	DisableE2EE bool
	OnPinCode   func(string)
}

// PasswordLoginResult contains the credentials and key restored by login.
type PasswordLoginResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    *int64
	Certificate  string
	E2EEKey      *E2EEKey
}

// PasswordLogin performs LINE's RSA-protected email/password login and the
// verifier/PIN step required for a new device. Modern devices use token-v3
// login; older profiles use loginZ. E2EE key-chain restoration is enabled by
// default, matching LINEJS.
func (s *LoginService) PasswordLogin(ctx context.Context, options PasswordLoginOptions) (*PasswordLoginResult, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("line password login: client is nil")
	}
	if !loginEmailPattern.MatchString(options.Email) {
		return nil, fmt.Errorf("line password login: invalid email")
	}
	if !validLoginPassword(options.Password) {
		return nil, fmt.Errorf("line password login: password must contain at least eight supported ASCII characters")
	}
	pin := options.PinCode
	if pin == "" {
		pin = defaultLoginPIN
	}
	if len(pin) != 6 {
		return nil, fmt.Errorf("line password login: PIN must contain six characters")
	}

	useV3 := supportsLoginV3(s.client.details.Device)
	if options.V3 != nil {
		useV3 = *options.V3
	}
	useE2EE := !options.DisableE2EE || useV3
	key, err := s.getRSAKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("line password login: get RSA key: %w", err)
	}
	encryptedCredentials, err := encryptPasswordCredentials(key, options.Email, options.Password)
	if err != nil {
		return nil, fmt.Errorf("line password login: encrypt credentials: %w", err)
	}

	var deviceKey E2EEKeyPair
	var encryptedPINKey []byte
	if useE2EE {
		deviceKey, _, err = s.client.E2EE().CreateQRSecret()
		if err != nil {
			return nil, fmt.Errorf("line password login: create E2EE key: %w", err)
		}
		pinHash := sha256.Sum256([]byte(pin))
		encryptedPINKey, err = cryptoe2ee.EncryptECB(pinHash[:], deviceKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("line password login: encrypt E2EE PIN key: %w", err)
		}
	}

	certificate, err := s.getPasswordCertificate(ctx, options.Email)
	if err != nil {
		return nil, fmt.Errorf("line password login: load certificate: %w", err)
	}
	method, path := "loginZ", loginV3Path
	if useV3 {
		method = "loginV2"
		path = loginV3Path
		if s.client.details.Device == DeviceAndroid || s.client.details.Device == DeviceAndroidSecondary {
			path = loginV4Path
		}
	}

	loginType := int32(0)
	if useE2EE {
		loginType = 2
	}
	result, err := s.passwordLoginRequest(ctx, path, method, loginType, key, encryptedCredentials, certificate, "", encryptedPINKey)
	if err != nil {
		return nil, fmt.Errorf("line password login: initial request: %w", err)
	}
	if token := passwordLoginToken(result); token.AccessToken != "" {
		token.Certificate = passwordCertificate(result, certificate)
		return s.finishPasswordLogin(ctx, options.Email, token)
	}
	if options.OnPinCode != nil {
		code := pin
		if result.PinCode != nil && *result.PinCode != "" {
			code = *result.PinCode
		}
		options.OnPinCode(code)
	}

	verifier := ""
	var restoredKey *E2EEKey
	if useE2EE {
		if result.Verifier == nil || *result.Verifier == "" {
			return nil, fmt.Errorf("line password login: server response has no E2EE verifier")
		}
		verifier = *result.Verifier
		chain, err := s.fetchE2EELoginKeyChain(ctx, verifier)
		if err != nil {
			return nil, fmt.Errorf("line password login: fetch E2EE key chain: %w", err)
		}
		restoredKey, err = s.client.E2EE().DecryptLoginKeyChain(ctx, chain, deviceKey.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("line password login: restore E2EE key chain: %w", err)
		}
		deviceSecret, err := s.client.E2EE().EncryptDeviceSecret(chain.PublicKey, deviceKey.PrivateKey, chain.EncryptedKeyChain)
		if err != nil {
			return nil, fmt.Errorf("line password login: encrypt device secret: %w", err)
		}
		verifier, err = s.confirmE2EELogin(ctx, verifier, deviceSecret)
		if err != nil {
			return nil, fmt.Errorf("line password login: confirm E2EE login: %w", err)
		}
	} else {
		if result.Verifier == nil || *result.Verifier == "" {
			return nil, fmt.Errorf("line password login: server response has no verifier")
		}
		verifier, err = s.fetchPasswordVerifier(ctx, *result.Verifier)
		if err != nil {
			return nil, fmt.Errorf("line password login: fetch verifier: %w", err)
		}
	}

	loginType = 1
	result, err = s.passwordLoginRequest(ctx, path, method, loginType, key, encryptedCredentials, certificate, verifier, encryptedPINKey)
	if err != nil {
		return nil, fmt.Errorf("line password login: verifier request: %w", err)
	}
	credentials := passwordLoginToken(result)
	if credentials.AccessToken == "" {
		return nil, fmt.Errorf("line password login: server response has no access token")
	}
	credentials.Certificate = passwordCertificate(result, certificate)
	credentials.E2EEKey = restoredKey
	return s.finishPasswordLogin(ctx, options.Email, credentials)
}

func (s *LoginService) getRSAKey(ctx context.Context) (*types.RSAKey, error) {
	args := thrift.StructValue{{ID: 1, Value: thrift.StructValue{{ID: 2, Value: thrift.I32Value(0)}}}}
	response, err := s.client.Request(ctx, RequestOptions{
		Path: loginTalkPath, Method: "getRSAKeyInfo", Protocol: thrift.ProtocolCompact,
	}, args)
	if err != nil {
		return nil, err
	}
	if err := responseException("getRSAKeyInfo", response); err != nil {
		return nil, err
	}
	fields := response.Message.Args
	if success, ok := field(fields, 0); ok {
		if nested, ok := success.(thrift.StructValue); ok {
			fields = nested
		}
	}
	var result types.RSAKey
	if err := thrift.UnmarshalStructValue(fields, &result); err != nil {
		return nil, fmt.Errorf("decode RSA key: %w", err)
	}
	if result.Keynm == nil || result.Nvalue == nil || result.Evalue == nil || result.SessionKey == nil {
		return nil, fmt.Errorf("response has incomplete RSA key data")
	}
	return &result, nil
}

func encryptPasswordCredentials(key *types.RSAKey, email, password string) (string, error) {
	modulus, err := parseRSAInteger(*key.Nvalue)
	if err != nil {
		return "", fmt.Errorf("parse modulus: %w", err)
	}
	exponent, err := parseRSAInteger(*key.Evalue)
	if err != nil {
		return "", fmt.Errorf("parse exponent: %w", err)
	}
	if exponent.Sign() <= 0 || !exponent.IsInt64() || exponent.Int64() > int64(^uint(0)>>1) {
		return "", fmt.Errorf("RSA exponent is out of range")
	}
	publicKey := &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}
	message := make([]byte, 0, len(*key.SessionKey)+len(email)+len(password)+3)
	for _, value := range []string{*key.SessionKey, email, password} {
		if len(value) > 255 {
			return "", fmt.Errorf("credential component exceeds 255 bytes")
		}
		message = append(message, byte(len(value)))
		message = append(message, value...)
	}
	block, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(block), nil
}

func parseRSAInteger(value string) (*big.Int, error) {
	text := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(value), "0x"), "0X")
	if text == "" {
		return nil, fmt.Errorf("integer is empty")
	}
	parsed, ok := new(big.Int).SetString(text, 16)
	if !ok || parsed.Sign() <= 0 {
		return nil, fmt.Errorf("invalid hexadecimal integer")
	}
	return parsed, nil
}

func (s *LoginService) passwordLoginRequest(ctx context.Context, path, method string, loginType int32, key *types.RSAKey, encryptedCredentials, certificate, verifier string, encryptedPINKey []byte) (*types.LoginResult, error) {
	fields := thrift.StructValue{
		{ID: 1, Value: thrift.I32Value(loginType)},
		{ID: 2, Value: thrift.I32Value(1)},
		{ID: 3, Value: thrift.StringValue(*key.Keynm)},
		{ID: 4, Value: thrift.StringValue(encryptedCredentials)},
		{ID: 5, Value: thrift.BoolValue(false)},
		{ID: 6, Value: thrift.StringValue("")},
		{ID: 7, Value: thrift.StringValue(string(s.client.details.Device))},
		{ID: 11, Value: thrift.BoolValue(true)},
		{ID: 12, Value: thrift.StringValue("System Product Name")},
	}
	if certificate != "" {
		fields = append(fields, thrift.Field{ID: 8, Value: thrift.StringValue(certificate)})
	}
	if verifier != "" {
		fields = append(fields, thrift.Field{ID: 9, Value: thrift.StringValue(verifier)})
	}
	if len(encryptedPINKey) > 0 {
		fields = append(fields, thrift.Field{ID: 10, Value: thrift.BinaryValue(encryptedPINKey)})
	}
	response, err := s.client.Request(ctx, RequestOptions{
		Path: path, Method: method, Protocol: thrift.ProtocolCompact,
	}, thrift.StructValue{{ID: 2, Value: fields}})
	if err != nil {
		return nil, err
	}
	if err := responseException(method, response); err != nil {
		return nil, err
	}
	resultFields := response.Message.Args
	if success, ok := field(resultFields, 0); ok {
		if nested, ok := success.(thrift.StructValue); ok {
			resultFields = nested
		}
	}
	result := new(types.LoginResult)
	if err := thrift.UnmarshalStructValue(resultFields, result); err != nil {
		return nil, fmt.Errorf("decode login result: %w", err)
	}
	return result, nil
}

func (s *LoginService) fetchE2EELoginKeyChain(ctx context.Context, verifier string) (E2EELoginKeyChain, error) {
	var response struct {
		Result struct {
			Metadata struct {
				KeyID             int32  `json:"keyId"`
				PublicKey         string `json:"publicKey"`
				EncryptedKeyChain string `json:"encryptedKeyChain"`
				E2EEVersion       int32  `json:"e2eeVersion"`
			} `json:"metadata"`
		} `json:"result"`
	}
	if err := s.getLoginJSON(ctx, loginE2EEInfoPath, verifier, &response); err != nil {
		return E2EELoginKeyChain{}, err
	}
	metadata := response.Result.Metadata
	publicKey, err := base64Decode(metadata.PublicKey)
	if err != nil {
		return E2EELoginKeyChain{}, fmt.Errorf("decode public key: %w", err)
	}
	encryptedKeyChain, err := base64Decode(metadata.EncryptedKeyChain)
	if err != nil {
		return E2EELoginKeyChain{}, fmt.Errorf("decode encrypted key chain: %w", err)
	}
	if metadata.KeyID <= 0 || len(publicKey) != 32 || len(encryptedKeyChain) == 0 {
		return E2EELoginKeyChain{}, fmt.Errorf("response has incomplete E2EE key metadata")
	}
	return E2EELoginKeyChain{KeyID: metadata.KeyID, PublicKey: publicKey, EncryptedKeyChain: encryptedKeyChain, E2EEVersion: metadata.E2EEVersion}, nil
}

func (s *LoginService) fetchPasswordVerifier(ctx context.Context, verifier string) (string, error) {
	var response struct {
		Result struct {
			Verifier string `json:"verifier"`
		} `json:"result"`
	}
	if err := s.getLoginJSON(ctx, loginV3VerifierPath, verifier, &response); err != nil {
		return "", err
	}
	if response.Result.Verifier == "" {
		return "", fmt.Errorf("response has no verifier")
	}
	return response.Result.Verifier, nil
}

func (s *LoginService) getLoginJSON(ctx context.Context, path, verifier string, output any) error {
	requestURL, err := s.client.requestURL(path)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return err
	}
	request.Host = s.client.endpoint.Host
	request.Header = s.client.Headers(http.MethodGet)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Line-Access", verifier)
	response, err := s.client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	if response == nil || response.Body == nil {
		return fmt.Errorf("GET %s: empty response", path)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("GET %s: HTTP %d", path, response.StatusCode)
	}
	reader, closeReader, err := responseReader(response)
	if err != nil {
		return fmt.Errorf("GET %s: read response: %w", path, err)
	}
	if closeReader != nil {
		defer closeReader()
	}
	data, err := io.ReadAll(io.LimitReader(reader, s.client.config.MaxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("GET %s: read response: %w", path, err)
	}
	if int64(len(data)) > s.client.config.MaxResponseBytes {
		return &ResponseTooLargeError{Limit: s.client.config.MaxResponseBytes}
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("GET %s: decode JSON: %w", path, err)
	}
	return nil
}

func (s *LoginService) confirmE2EELogin(ctx context.Context, verifier string, deviceSecret []byte) (string, error) {
	response, err := s.client.Request(ctx, RequestOptions{
		Path: registrationAuthPath(s.client.details.Device), Method: "confirmE2EELogin", Protocol: thrift.ProtocolCompact,
	}, thrift.StructValue{
		{ID: 1, Value: thrift.StringValue(verifier)},
		{ID: 2, Value: thrift.BinaryValue(deviceSecret)},
	})
	if err != nil {
		return "", err
	}
	if err := responseException("confirmE2EELogin", response); err != nil {
		return "", err
	}
	for _, id := range []int16{0, 1, 2} {
		if value, found := field(response.Message.Args, id); found {
			if result, ok := stringValue(value); ok && result != "" {
				return result, nil
			}
		}
	}
	return "", fmt.Errorf("response has no verifier")
}

func (s *LoginService) getPasswordCertificate(ctx context.Context, email string) (string, error) {
	value, found, err := s.client.storage.Get(ctx, storage.KeyCertificate+":"+email)
	if err != nil || !found {
		return "", err
	}
	certificate, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("stored certificate has type %T, want string", value)
	}
	return certificate, nil
}

func (s *LoginService) finishPasswordLogin(ctx context.Context, email string, result *PasswordLoginResult) (*PasswordLoginResult, error) {
	if result.Certificate != "" {
		if err := s.client.storage.Set(ctx, storage.KeyCertificate+":"+email, result.Certificate); err != nil {
			return nil, fmt.Errorf("persist certificate: %w", err)
		}
	}
	return result, nil
}

func passwordLoginToken(result *types.LoginResult) *PasswordLoginResult {
	credentials := new(PasswordLoginResult)
	if result == nil {
		return credentials
	}
	if result.AuthToken != nil {
		credentials.AccessToken = *result.AuthToken
	}
	if result.TokenV3IssueResult != nil {
		token := result.TokenV3IssueResult
		if token.AccessToken != nil {
			credentials.AccessToken = *token.AccessToken
		}
		if token.RefreshToken != nil {
			credentials.RefreshToken = *token.RefreshToken
		}
		if token.TokenIssueTimeEpochSec != nil && token.DurationUntilRefreshInSec != nil {
			expiry := *token.TokenIssueTimeEpochSec + *token.DurationUntilRefreshInSec
			credentials.ExpiresAt = &expiry
		}
	}
	return credentials
}

func passwordCertificate(result *types.LoginResult, existing string) string {
	if result != nil && result.Certificate != nil && *result.Certificate != "" {
		return *result.Certificate
	}
	return existing
}

func validLoginPassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	const allowed = "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?"
	for _, char := range password {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' {
			continue
		}
		if !strings.ContainsRune(allowed, char) {
			return false
		}
	}
	return true
}

func supportsLoginV3(device Device) bool {
	switch device {
	case DeviceDesktopWindows, DeviceDesktopMac, DeviceIOS, DeviceAndroid, DeviceAndroidSecondary:
		return true
	default:
		return false
	}
}

func registrationAuthPath(device Device) string {
	if device == DeviceAndroid || device == DeviceAndroidSecondary {
		return loginV4Path
	}
	return loginV3Path
}

func base64Decode(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}
