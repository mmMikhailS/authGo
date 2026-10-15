package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/mmMikhailS/DeepBoard/internal/auth/adapters/password"
	"github.com/mmMikhailS/DeepBoard/internal/auth/adapters/repositories"
	"github.com/mmMikhailS/DeepBoard/internal/auth/app/http"
	"github.com/mmMikhailS/DeepBoard/internal/auth/domain/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auth middleware tests

func TestAuth_Flow(t *testing.T) {
	ctx := context.Background()

	passwordHasher := password.NewPasswordHasher(uint32(17*1024), uint32(3), uint32(33), uint32(17), uint8(2))
	userFactoryConfig := user.NewFactoryConfig(passwordHasher)
	userFactory, err := user.NewFactory(userFactoryConfig)
	require.NoError(t, err)

	conn := repositories.NewPostgresSQLConnection()
	repo := repositories.NewPostgresSQLUserRepository(conn, userFactory)
	app := NewApplication(ctx)

	email := fmt.Sprintf("%s@gmail.com", uuid.New())
	name := "test"
	pass := "password"

	t.Run("Should register a new user", func(t *testing.T) {
		cmd := http.RegisterUserRequest{
			Email:    email,
			Name:     name,
			Password: pass,
		}

		tokens, err := app.Http.RegisterUser.Handle(ctx, cmd)
		require.NoError(t, err)
		require.NotNil(t, tokens.AccessToken)
		require.NotNil(t, tokens.RefreshToken)

		savedUser, err := repo.GetUserByEmail(ctx, email)
		require.NoError(t, err)
		assert.Equal(t, email, savedUser.Email())
	})

	t.Run("Should login a new user", func(t *testing.T) {
		cmd := http.LoginUserRequest{
			Email:    email,
			Password: pass,
		}

		tokens, err := app.Http.LoginUser.Handle(ctx, cmd)
		require.NoError(t, err)
		require.NotNil(t, tokens.AccessToken)
		require.NotNil(t, tokens.RefreshToken)

		savedUser, err := repo.GetUserByEmail(ctx, email)
		require.NoError(t, err)
		assert.Equal(t, email, savedUser.Email())
	})
}
