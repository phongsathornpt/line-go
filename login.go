package line

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// AuthTokenCredentials holds the token material accepted by the high-level
// auth-token login path.
type AuthTokenCredentials struct {
	AccessToken  string
	RefreshToken string
	Expire       *int64
}

// ParseAuthTokenInput accepts a raw access token, two newline-separated JWTs,
// or a LINEJS-compatible JSON credential object.
func ParseAuthTokenInput(input string) (AuthTokenCredentials, error) {
	value := strings.TrimSpace(input)
	if value == "" {
		return AuthTokenCredentials{}, nil
	}

	lines := nonEmptyLines(value)
	if len(lines) >= 2 && isJWT(lines[0]) && isJWT(lines[1]) {
		return AuthTokenCredentials{AccessToken: lines[0], RefreshToken: lines[1]}, nil
	}
	if !strings.HasPrefix(value, "{") {
		return AuthTokenCredentials{AccessToken: value}, nil
	}

	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return AuthTokenCredentials{}, fmt.Errorf("line auth token: decode JSON: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return AuthTokenCredentials{}, fmt.Errorf("line auth token: JSON has trailing content")
		}
		return AuthTokenCredentials{}, fmt.Errorf("line auth token: decode trailing JSON: %w", err)
	}
	nested, _ := document["tokenV3IssueResult"].(map[string]any)
	accessToken := stringField(document["accessToken"])
	if accessToken == "" {
		accessToken = stringField(document["authToken"])
	}
	if accessToken == "" {
		accessToken = stringField(nested["accessToken"])
	}
	if accessToken == "" {
		return AuthTokenCredentials{}, fmt.Errorf("line auth token: JSON must contain accessToken")
	}
	refreshToken := stringField(document["refreshToken"])
	if refreshToken == "" {
		refreshToken = stringField(nested["refreshToken"])
	}
	return AuthTokenCredentials{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expire:       numberField(document["expire"]),
	}, nil
}

// LoginWithAuthToken parses LINEJS-compatible token input, loads the token
// state, and fetches the signed-in user's profile before returning the client.
func LoginWithAuthToken(ctx context.Context, options ClientOptions, input string) (*Client, error) {
	credentials, err := ParseAuthTokenInput(input)
	if err != nil {
		return nil, err
	}
	return LoginWithCredentials(ctx, options, credentials)
}

// LoginWithCredentials creates a ready client from explicit token credentials.
func LoginWithCredentials(
	ctx context.Context,
	options ClientOptions,
	credentials AuthTokenCredentials,
) (*Client, error) {
	accessToken := strings.TrimSpace(credentials.AccessToken)
	if accessToken == "" {
		return nil, fmt.Errorf("line auth token: access token is empty")
	}
	options.AuthToken = accessToken
	options.RefreshToken = strings.TrimSpace(credentials.RefreshToken)
	client, err := NewClient(options)
	if err != nil {
		return nil, err
	}
	if credentials.Expire != nil {
		if err := client.base.Storage().Set(ctx, "expire", *credentials.Expire); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("line auth token: persist expiry: %w", err)
		}
	}
	profile, err := client.GetMyProfile(ctx)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("line auth token: initialize profile: %w", err)
	}
	client.profile = profile
	return client, nil
}

func nonEmptyLines(value string) []string {
	lines := strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	return result
}

func isJWT(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false
	}
	if _, ok := header["alg"].(string); !ok {
		return false
	}
	for _, key := range []string{"ver", "scp", "exp", "iat", "sub", "iss", "aud"} {
		if _, found := payload[key]; found {
			return true
		}
	}
	return false
}

func stringField(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func numberField(value any) *int64 {
	number, ok := value.(json.Number)
	if !ok {
		return nil
	}
	parsed, err := number.Int64()
	if err != nil {
		return nil
	}
	return &parsed
}
