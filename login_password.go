package line

import (
	"context"
	"fmt"

	"github.com/phongsathornpt/line-go/base"
	"github.com/phongsathornpt/line-go/storage"
)

// PasswordLoginOptions configures the LINE email/password login flow.
type PasswordLoginOptions struct {
	Email       string
	Password    string
	PinCode     string
	V3          *bool
	DisableE2EE bool
	OnPinCode   func(string)
}

// LoginWithPassword authenticates with email and password and returns a client
// with its profile and login tokens loaded. E2EE key restoration is enabled by
// default, and the PIN callback receives the code to enter on the primary
// device when LINE requests device approval.
func LoginWithPassword(ctx context.Context, clientOptions ClientOptions, loginOptions PasswordLoginOptions) (*Client, error) {
	client, err := NewClient(clientOptions)
	if err != nil {
		return nil, err
	}
	credentials, err := client.base.Login().PasswordLogin(ctx, base.PasswordLoginOptions{
		Email:       loginOptions.Email,
		Password:    loginOptions.Password,
		PinCode:     loginOptions.PinCode,
		V3:          loginOptions.V3,
		DisableE2EE: loginOptions.DisableE2EE,
		OnPinCode:   loginOptions.OnPinCode,
	})
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line password login: %w", err))
	}
	client.base.SetAuthToken(credentials.AccessToken)
	if credentials.RefreshToken != "" {
		if err := client.base.Storage().Set(ctx, storage.KeyRefreshToken, credentials.RefreshToken); err != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line password login: persist refresh token: %w", err))
		}
	}
	if credentials.ExpiresAt != nil {
		if err := client.base.Storage().Set(ctx, storage.KeyExpiresAt, *credentials.ExpiresAt); err != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line password login: persist expiry: %w", err))
		}
	}
	if err := client.base.E2EE().VerifyLoginKey(ctx); err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line password login: verify E2EE key: %w", err))
	}
	profile, err := client.GetMyProfile(ctx)
	if err != nil {
		return closeAfterLoginFailure(client, fmt.Errorf("line password login: initialize profile: %w", err))
	}
	if credentials.E2EEKey != nil {
		if err := client.base.E2EE().SaveSelfKey(ctx, profile.MID, credentials.E2EEKey); err != nil {
			return closeAfterLoginFailure(client, fmt.Errorf("line password login: persist account E2EE key: %w", err))
		}
	}
	client.profile = profile
	return client, nil
}
