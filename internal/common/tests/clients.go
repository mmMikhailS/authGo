package tests

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/mmMikhailS/DeepBoard/internal/common/client/auth"
	"github.com/stretchr/testify/require"
)

func authorizationBearer(token string) func(context.Context, *http.Request) error {
	return func(ctx context.Context, req *http.Request) error {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
		return nil
	}
}

type AuthHTTPClient struct {
	client *auth.ClientWithResponses
}

func NewUserHTTPClient(t *testing.T, token string) AuthHTTPClient {
	addr := os.Getenv("AUTH_HTTP_ADDR")
	ok := WaitForPort(addr)
	require.True(t, ok, "User HTTP timed out")

	url := fmt.Sprintf("http://%v/api", addr)

	client, err := auth.NewClientWithResponses(
		url,
		auth.WithRequestEditorFn(authorizationBearer(token)),
	)
	require.NoError(t, err)

	return AuthHTTPClient{
		client: client,
	}
}

func (c AuthHTTPClient) RegisterUser(t *testing.T, email, password string) int {
	response, err := c.client.RegisterUser(context.Background(), auth.RegisterUserJSONRequestBody{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())

	return response.StatusCode
}
