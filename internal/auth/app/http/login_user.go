package http

import (
	"context"

	"github.com/google/uuid"
	"github.com/mmMikhailS/DeepBoard/internal/auth/domain/user"
	"github.com/mmMikhailS/DeepBoard/internal/common/decorator"
	"github.com/mmMikhailS/DeepBoard/internal/common/errors"
	"github.com/sirupsen/logrus"
)

type LoginUserRequest struct {
	Email    string
	Password string
}

type LoginUserResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Name         string `json:"name"`
}

type LoginUserHandler decorator.HttpHandler[LoginUserRequest, LoginUserResponse]

type loginUserHandler struct {
	userRepository user.Repository
	passwordHasher user.PasswordHasher
	tokenService   TokenService
	factory        Factory
}

func NewLoginUserHandler(
	userRepository user.Repository,
	passwordHasher user.PasswordHasher,
	tokenService TokenService,
	factory Factory,
	logger *logrus.Entry,
	metricsClient decorator.MetricsClient,
) LoginUserHandler {
	if userRepository == nil {
		panic("nil userRepository")
	}

	if passwordHasher == nil {
		panic("nil passwordHasher")
	}

	if tokenService == nil {
		panic("nil tokenService")
	}

	if factory == nil {
		panic("nil factory")
	}

	return decorator.ApplyHttpDecorators[LoginUserRequest, LoginUserResponse](
		loginUserHandler{
			userRepository: userRepository,
			passwordHasher: passwordHasher,
			tokenService:   tokenService,
			factory:        factory,
		},
		logger,
		metricsClient,
	)
}

func (h loginUserHandler) Handle(ctx context.Context, cmd LoginUserRequest) (LoginUserResponse, error) {
	u, err := h.userRepository.GetUserByEmail(ctx, cmd.Email)
	if err != nil {
		return LoginUserResponse{}, errors.NewSlugError(err.Error(), "invalid-login-data")
	}

	ok, err := h.passwordHasher.VerifyPassword(cmd.Password, u.PasswordHash())
	if err != nil {
		return LoginUserResponse{}, errors.NewSlugError(err.Error(), "invalid-login-data")
	}
	if !ok {
		return LoginUserResponse{}, errors.NewSlugError("invalid password", "invalid-login-data")
	}

	sessionID := uuid.New()
	tokenID := uuid.New()
	deviceID := uuid.New()

	userScopes := u.DefaultScopes()

	accessToken, refreshToken, err := h.tokenService.GenerateTokenPair(
		deviceID,
		sessionID,
		u.ID(),
		u.Email(),
		tokenID,
		user.ScopesToString(userScopes),
	)
	if err != nil {
		return LoginUserResponse{}, errors.NewSlugError(err.Error(), "token-generation-failed")
	}

	return LoginUserResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Name:         u.Name(),
	}, nil
}
