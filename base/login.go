package base

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/phongsathornpt/line-go/storage"
	"github.com/phongsathornpt/line-go/thrift"
	"github.com/phongsathornpt/line-go/types"
)

const (
	qrSessionPath       = "/acct/lgn/sq/v1"
	qrLongPollPath      = "/acct/lp/lgn/sq/v1"
	qrDefaultPollCount  = 12
	qrDefaultPollPeriod = 30 * time.Second
)

// LoginService performs the raw account Thrift calls used by QR login.
type LoginService struct {
	client *BaseClient
}

// SecureQRCode is the challenge returned by LINE's ForSecure QR endpoint.
type SecureQRCode struct {
	SessionID        string
	CallbackURL      string
	Nonce            string
	LongPollCount    int
	LongPollInterval time.Duration
}

// QRCodeLoginResult contains token and certificate data returned after a
// secure QR challenge is approved.
type QRCodeLoginResult struct {
	Certificate  string
	AccessToken  string
	RefreshToken string
	Mid          string
	ExpiresAt    *int64
	Metadata     map[string]string
	E2EEInfo     any
}

// CreateSession starts an account QR login session.
func (s *LoginService) CreateSession(ctx context.Context) (string, error) {
	response, err := s.request(ctx, qrSessionPath, "createSession", nil, 0, nil)
	if err != nil {
		return "", err
	}
	value, ok := field(response.Message.Args, 1)
	if !ok {
		return "", fmt.Errorf("line createSession: response has no session id")
	}
	sessionID, ok := stringValue(value)
	if !ok || sessionID == "" {
		return "", fmt.Errorf("line createSession: session id has type %T or is empty", value)
	}
	return sessionID, nil
}

// CreateQrCodeForSecure requests a modern QR callback URL and its nonce.
func (s *LoginService) CreateQrCodeForSecure(ctx context.Context, sessionID string) (SecureQRCode, error) {
	if sessionID == "" {
		return SecureQRCode{}, fmt.Errorf("line createQrCodeForSecure: session id is empty")
	}
	args := thrift.StructValue{{
		ID:    1,
		Value: thrift.StructValue{{ID: 1, Value: thrift.StringValue(sessionID)}},
	}}
	response, err := s.request(ctx, qrSessionPath, "createQrCodeForSecure", args, 0, nil)
	if err != nil {
		return SecureQRCode{}, err
	}
	callback, ok := stringField(response.Message.Args, 1)
	if !ok || callback == "" {
		return SecureQRCode{}, fmt.Errorf("line createQrCodeForSecure: response has no callback URL")
	}
	nonce, _ := stringField(response.Message.Args, 4)
	count := qrDefaultPollCount
	if value, found := field(response.Message.Args, 2); found {
		if parsed, ok := int32Value(value); ok && parsed > 0 {
			count = int(parsed)
		}
	}
	interval := qrDefaultPollPeriod
	if value, found := field(response.Message.Args, 3); found {
		if parsed, ok := int32Value(value); ok && parsed > 0 {
			interval = time.Duration(parsed) * time.Second
		}
	}
	return SecureQRCode{
		SessionID:        sessionID,
		CallbackURL:      callback,
		Nonce:            nonce,
		LongPollCount:    count,
		LongPollInterval: interval,
	}, nil
}

// CreateQrCode requests the legacy QR callback URL for a login session.
func (s *LoginService) CreateQrCode(ctx context.Context, sessionID string) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("line createQrCode: session id is empty")
	}
	args := thrift.StructValue{{
		ID:    1,
		Value: thrift.StructValue{{ID: 1, Value: thrift.StringValue(sessionID)}},
	}}
	response, err := s.request(ctx, qrSessionPath, "createQrCode", args, 0, nil)
	if err != nil {
		return "", err
	}
	if err := responseException("createQrCode", response); err != nil {
		return "", err
	}
	callback, ok := stringField(response.Message.Args, 1)
	if !ok || callback == "" {
		return "", fmt.Errorf("line createQrCode: response has no callback URL")
	}
	return callback, nil
}

// CheckQrCodeVerified long-polls until LINE approves the QR scan or the
// configured number of poll windows expires.
func (s *LoginService) CheckQrCodeVerified(
	ctx context.Context,
	sessionID string,
	count int,
	interval time.Duration,
) (bool, error) {
	return s.checkVerified(ctx, "checkQrCodeVerified", sessionID, count, interval)
}

// CheckPinCodeVerified long-polls until LINE approves the displayed PIN.
func (s *LoginService) CheckPinCodeVerified(
	ctx context.Context,
	sessionID string,
	count int,
	interval time.Duration,
) (bool, error) {
	return s.checkVerified(ctx, "checkPinCodeVerified", sessionID, count, interval)
}

// VerifyCertificate attempts to authorize the QR session with the saved QR
// certificate. An empty certificate is sent as an omitted optional field.
func (s *LoginService) VerifyCertificate(ctx context.Context, sessionID, certificate string) error {
	fields := thrift.StructValue{{ID: 1, Value: thrift.StringValue(sessionID)}}
	if certificate != "" {
		fields = append(fields, thrift.Field{ID: 2, Value: thrift.StringValue(certificate)})
	}
	response, err := s.request(ctx, qrSessionPath, "verifyCertificate", thrift.StructValue{{ID: 1, Value: fields}}, 0, nil)
	if err != nil {
		return err
	}
	return responseException("verifyCertificate", response)
}

// CreatePinCode requests a fallback PIN when certificate authorization fails.
func (s *LoginService) CreatePinCode(ctx context.Context, sessionID string) (string, error) {
	args := thrift.StructValue{{
		ID:    1,
		Value: thrift.StructValue{{ID: 1, Value: thrift.StringValue(sessionID)}},
	}}
	response, err := s.request(ctx, qrSessionPath, "createPinCode", args, 0, nil)
	if err != nil {
		return "", err
	}
	if err := responseException("createPinCode", response); err != nil {
		return "", err
	}
	code, ok := stringField(response.Message.Args, 1)
	if !ok || code == "" {
		return "", fmt.Errorf("line createPinCode: response has no PIN")
	}
	return code, nil
}

// QrCodeLoginV2ForSecure completes a ForSecure QR login with the nonce issued
// by CreateQrCodeForSecure.
func (s *LoginService) QrCodeLoginV2ForSecure(
	ctx context.Context,
	sessionID,
	nonce string,
) (*QRCodeLoginResult, error) {
	args := thrift.StructValue{{ID: 1, Value: thrift.StructValue{
		{ID: 1, Value: thrift.StringValue(sessionID)},
		{ID: 2, Value: thrift.StringValue("line-go")},
		{ID: 3, Value: thrift.StringValue("line-go")},
		{ID: 4, Value: thrift.BoolValue(true)},
		{ID: 5, Value: thrift.StringValue(nonce)},
	}}}
	response, err := s.request(ctx, qrSessionPath, "qrCodeLoginV2ForSecure", args, 0, nil)
	if err != nil {
		return nil, err
	}
	return decodeQRCodeLoginResult("qrCodeLoginV2ForSecure", response)
}

// QrCodeLoginV2 completes a legacy QR login challenge.
func (s *LoginService) QrCodeLoginV2(ctx context.Context, sessionID string) (*QRCodeLoginResult, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("line qrCodeLoginV2: session id is empty")
	}
	args := thrift.StructValue{{ID: 1, Value: thrift.StructValue{
		{ID: 1, Value: thrift.StringValue(sessionID)},
		{ID: 2, Value: thrift.StringValue("line-go")},
		{ID: 3, Value: thrift.StringValue("line-go")},
		{ID: 4, Value: thrift.BoolValue(true)},
	}}}
	response, err := s.request(ctx, qrSessionPath, "qrCodeLoginV2", args, 0, nil)
	if err != nil {
		return nil, err
	}
	return decodeQRCodeLoginResult("qrCodeLoginV2", response)
}

func decodeQRCodeLoginResult(method string, response Response) (*QRCodeLoginResult, error) {
	var decoded secureQRLoginResponse
	if err := thrift.UnmarshalStructValue(response.Message.Args, &decoded); err != nil {
		return nil, fmt.Errorf("line %s: decode response: %w", method, err)
	}
	accessToken := ""
	var refreshToken string
	var expiresAt *int64
	if decoded.TokenV3IssueResult != nil {
		if decoded.TokenV3IssueResult.AccessToken != nil {
			accessToken = *decoded.TokenV3IssueResult.AccessToken
		}
		if decoded.TokenV3IssueResult.RefreshToken != nil {
			refreshToken = *decoded.TokenV3IssueResult.RefreshToken
		}
		issueTime := decoded.TokenV3IssueResult.TokenIssueTimeEpochSec
		refreshDuration := decoded.TokenV3IssueResult.DurationUntilRefreshInSec
		if issueTime != nil && refreshDuration != nil {
			issued := *issueTime
			duration := *refreshDuration
			if duration > 0 && issued > int64(^uint64(0)>>1)-duration {
				return nil, fmt.Errorf("line %s: expiry overflows i64", method)
			}
			if duration < 0 && issued < (-int64(^uint64(0)>>1)-1)-duration {
				return nil, fmt.Errorf("line %s: expiry underflows i64", method)
			}
			expiry := issued + duration
			expiresAt = &expiry
		}
	}
	if accessToken == "" && decoded.AccessTokenV2 != nil {
		accessToken = *decoded.AccessTokenV2
	}
	if accessToken == "" {
		return nil, fmt.Errorf("line %s: response has no access token", method)
	}
	certificate := ""
	if decoded.Certificate != nil {
		certificate = *decoded.Certificate
	}
	mid := ""
	if decoded.Mid != nil {
		mid = *decoded.Mid
	}
	metadata := decoded.MetaData
	if metadata == nil {
		metadata = make(map[string]string)
	}
	return &QRCodeLoginResult{
		Certificate:  certificate,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Mid:          mid,
		ExpiresAt:    expiresAt,
		Metadata:     metadata,
		E2EEInfo:     decoded.E2EEInfo,
	}, nil
}

// GetQrCertificate returns the saved QR certificate, if one exists.
func (s *LoginService) GetQrCertificate(ctx context.Context) (string, bool, error) {
	value, found, err := s.client.storage.Get(ctx, storage.KeyQRCodeCertificate)
	if err != nil || !found {
		return "", found, err
	}
	certificate, ok := value.(string)
	if !ok {
		return "", true, fmt.Errorf("line QR certificate: stored value has type %T, want string", value)
	}
	return certificate, true, nil
}

// StoreQrCertificate persists a QR certificate returned after login.
func (s *LoginService) StoreQrCertificate(ctx context.Context, certificate string) error {
	if certificate == "" {
		return fmt.Errorf("line QR certificate: certificate is empty")
	}
	return s.client.storage.Set(ctx, storage.KeyQRCodeCertificate, certificate)
}

func (s *LoginService) checkVerified(
	ctx context.Context,
	method,
	sessionID string,
	count int,
	interval time.Duration,
) (bool, error) {
	if s == nil || s.client == nil {
		return false, fmt.Errorf("line %s: client is nil", method)
	}
	if sessionID == "" {
		return false, fmt.Errorf("line %s: session id is empty", method)
	}
	if count <= 0 {
		count = 1
	}
	if interval <= 0 {
		interval = qrDefaultPollPeriod
	}
	intervalMillis := interval.Milliseconds()
	if intervalMillis < 1 {
		intervalMillis = 1
	}
	args := thrift.StructValue{{
		ID:    1,
		Value: thrift.StructValue{{ID: 1, Value: thrift.StringValue(sessionID)}},
	}}
	headers := make(http.Header)
	headers.Set("X-Lst", strconv.FormatInt(intervalMillis, 10))
	headers.Set("X-Line-Access", sessionID)
	for attempt := 0; attempt < count; attempt++ {
		timeout := interval + 5*time.Second
		response, err := s.request(ctx, qrLongPollPath, method, args, timeout, headers)
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			if isLongPollPending(err) {
				continue
			}
			return false, err
		}
		if response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusGone {
			continue
		}
		if err := responseException(method, response); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func (s *LoginService) request(
	ctx context.Context,
	path,
	method string,
	args thrift.StructValue,
	timeout time.Duration,
	headers http.Header,
) (Response, error) {
	if s == nil || s.client == nil {
		return Response{}, fmt.Errorf("line %s: client is nil", method)
	}
	response, err := s.client.Request(ctx, RequestOptions{
		Path:     path,
		Method:   method,
		Protocol: thrift.ProtocolCompact,
		Timeout:  timeout,
		Headers:  headers,
	}, args)
	if err != nil {
		return Response{}, fmt.Errorf("line %s: %w", method, err)
	}
	return response, nil
}

func isLongPollPending(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	message := err.Error()
	return strings.Contains(message, "HTTP 408") || strings.Contains(message, "HTTP 410")
}

func field(fields thrift.StructValue, id int16) (thrift.Value, bool) {
	for _, item := range fields {
		if item.ID == id {
			return item.Value, true
		}
	}
	return nil, false
}

func stringField(fields thrift.StructValue, id int16) (string, bool) {
	value, found := field(fields, id)
	if !found {
		return "", false
	}
	return stringValue(value)
}

func stringValue(value thrift.Value) (string, bool) {
	switch typed := value.(type) {
	case thrift.StringValue:
		return string(typed), true
	case thrift.BinaryValue:
		return string(typed), true
	default:
		return "", false
	}
}

func int32Value(value thrift.Value) (int32, bool) {
	switch typed := value.(type) {
	case thrift.I32Value:
		return int32(typed), true
	case thrift.I16Value:
		return int32(typed), true
	default:
		return 0, false
	}
}

func responseException(method string, response Response) error {
	value, found := field(response.Message.Args, 1)
	if !found {
		return nil
	}
	fields, ok := value.(thrift.StructValue)
	if !ok {
		return nil
	}
	var code int32
	if value, found := field(fields, 1); found {
		code, _ = int32Value(value)
	}
	reason, _ := stringField(fields, 2)
	return &ServiceError{Method: method, Code: code, Reason: reason}
}

type secureQRLoginResponse struct {
	Certificate        *string                   `json:"certificate,omitempty" thrift:"1,11"`
	AccessTokenV2      *string                   `json:"accessTokenV2,omitempty" thrift:"2,11"`
	TokenV3IssueResult *types.TokenV3IssueResult `json:"tokenV3IssueResult,omitempty" thrift:"3,12"`
	Mid                *string                   `json:"mid,omitempty" thrift:"4,11"`
	LastBindTimestamp  *int64                    `json:"lastBindTimestamp,omitempty" thrift:"5,10"`
	MetaData           map[string]string         `json:"metaData,omitempty" thrift:"6,13,11,11"`
	E2EEInfo           any                       `json:"-" thrift:"10,unknown"`
}
