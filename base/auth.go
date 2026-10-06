package base

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/phongsathornpt/line-go/thrift"
	"github.com/phongsathornpt/line-go/types"
)

var (
	ErrRefreshTokenNotFound      = errors.New("line auth: refresh token not found")
	ErrRefreshAccessTokenMissing = errors.New("line auth: refresh response has no access token")
)

// AuthService implements token refresh and refreshed-token reporting.
type AuthService struct {
	client *BaseClient
	rpc    *RPCService
}

// Refresh exchanges a refresh token for a new access-token response without
// changing client state.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*types.RefreshAccessTokenResponse, error) {
	service, err := s.client.Service(ServiceNameAccessTokenRefresh)
	if err != nil {
		return nil, err
	}
	result := new(types.RefreshResult)
	args := types.RefreshArgs{Request: &types.RefreshAccessTokenRequest{RefreshToken: stringPointer(refreshToken)}}
	if _, err := service.CallTyped(ctx, "refresh", args, result); err != nil {
		return nil, err
	}
	if result.Success == nil {
		return nil, fmt.Errorf("line auth refresh: %w", ErrMissingServiceSuccess)
	}
	return result.Success, nil
}

// TryRefreshToken loads the persisted refresh token, rotates the client's
// access token, and persists rotated refresh-token and expiry values.
func (s *AuthService) TryRefreshToken(ctx context.Context) (*types.RefreshAccessTokenResponse, error) {
	stored, found, err := s.client.storage.Get(ctx, "refreshToken")
	if err != nil {
		return nil, fmt.Errorf("line auth refresh: load refresh token: %w", err)
	}
	if !found {
		return nil, ErrRefreshTokenNotFound
	}
	refreshToken, ok := stored.(string)
	if !ok || refreshToken == "" {
		return nil, fmt.Errorf("line auth refresh: stored refresh token has type %T, want non-empty string", stored)
	}
	response, err := s.Refresh(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if response.AccessToken == nil || *response.AccessToken == "" {
		return nil, ErrRefreshAccessTokenMissing
	}
	s.client.SetAuthToken(*response.AccessToken)
	if response.RefreshToken != nil && *response.RefreshToken != "" {
		if err := s.client.storage.Set(ctx, "refreshToken", *response.RefreshToken); err != nil {
			return response, fmt.Errorf("line auth refresh: persist rotated refresh token: %w", err)
		}
	}
	if response.TokenIssueTimeEpochSec != nil && response.DurationUntilRefreshInSec != nil {
		issued := *response.TokenIssueTimeEpochSec
		duration := *response.DurationUntilRefreshInSec
		if (duration > 0 && issued > math.MaxInt64-duration) || (duration < 0 && issued < math.MinInt64-duration) {
			return response, fmt.Errorf("line auth refresh: token expiry timestamp overflows i64")
		}
		if err := s.client.storage.Set(ctx, "expire", issued+duration); err != nil {
			return response, fmt.Errorf("line auth refresh: persist expiry: %w", err)
		}
	}
	return response, nil
}

// ReportRefreshedAccessToken reports the currently refreshed token to the
// primary Auth service.
func (s *AuthService) ReportRefreshedAccessToken(ctx context.Context, accessToken string) error {
	service, err := s.client.Service(ServiceNameAuth)
	if err != nil {
		return err
	}
	result := new(types.ReportRefreshedAccessTokenResult)
	args := types.ReportRefreshedAccessTokenArgs{
		Request: &types.ReportRefreshedAccessTokenRequest{AccessToken: stringPointer(accessToken)},
	}
	_, err = service.CallTyped(ctx, "reportRefreshedAccessToken", args, result)
	if err != nil {
		return err
	}
	if result.Success == nil {
		return fmt.Errorf("line auth reportRefreshedAccessToken: %w", ErrMissingServiceSuccess)
	}
	return nil
}

// Logout sends LINEJS's special compact logoutZ request and disables this
// client after a successful response. An omitted success field means success.
func (s *AuthService) Logout(ctx context.Context) (bool, error) {
	response, err := s.client.Request(ctx, RequestOptions{
		Path:     "/RS4",
		Method:   "logoutZ",
		Protocol: thrift.ProtocolCompact,
	}, nil)
	if err != nil {
		return false, err
	}
	var success *bool
	for _, field := range response.Message.Args {
		switch field.ID {
		case 0:
			value, ok := field.Value.(thrift.BoolValue)
			if !ok {
				return false, fmt.Errorf("line logoutZ: success field has type %T, want bool", field.Value)
			}
			valueCopy := bool(value)
			success = &valueCopy
		case 1:
			exception, ok := field.Value.(thrift.StructValue)
			if !ok {
				return false, fmt.Errorf("line logoutZ: exception field has type %T, want struct", field.Value)
			}
			var remote types.TalkException
			if err := thrift.UnmarshalStructValue(exception, &remote); err != nil {
				return false, fmt.Errorf("line logoutZ: decode exception: %w", err)
			}
			return false, talkServiceError("logoutZ", &remote)
		}
	}
	result := true
	if success != nil {
		result = *success
	}
	s.client.SetAuthToken("")
	if err := s.client.Close(); err != nil {
		return false, err
	}
	return result, nil
}
