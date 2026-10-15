package http

import (
	"context"

	"github.com/google/uuid"
	"github.com/mmMikhailS/DeepBoard/internal/auth/domain/user"
	"github.com/mmMikhailS/DeepBoard/internal/common/decorator"
	"github.com/mmMikhailS/DeepBoard/internal/common/errors"
	"github.com/sirupsen/logrus"
)

type RegisterUserRequest struct {
	Email    string
	Password string
	Name     string
}

type RegisterUserResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RegisterUserHandler decorator.HttpHandler[RegisterUserRequest, RegisterUserResponse]

type registerUserHandler struct {
	userRepo       user.Repository
	passwordHasher user.PasswordHasher
	tokenService   TokenService
	factory        Factory
}

func NewRegisterUserHandler(
	userRepository user.Repository,
	passwordHasher user.PasswordHasher,
	tokenService TokenService,
	factory Factory,
	logger *logrus.Entry,
	metricsClient decorator.MetricsClient,
) RegisterUserHandler {
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

	return decorator.ApplyHttpDecorators[RegisterUserRequest, RegisterUserResponse](
		registerUserHandler{
			userRepo:       userRepository,
			passwordHasher: passwordHasher,
			tokenService:   tokenService,
			factory:        factory,
		},
		logger,
		metricsClient,
	)
}

func (h registerUserHandler) Handle(ctx context.Context, cmd RegisterUserRequest) (RegisterUserResponse, error) {
	u, err := h.factory.NewUser(cmd.Email, cmd.Name, cmd.Password)
	if err != nil {
		return RegisterUserResponse{}, errors.NewSlugError(err.Error(), "invalid-registration-data")
	}

	if err := h.userRepo.CreateUser(ctx, u); err != nil {
		return RegisterUserResponse{}, errors.NewSlugError(err.Error(), "registration-failed")
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
		return RegisterUserResponse{}, errors.NewSlugError(err.Error(), "token-generation-failed")
	}

	return RegisterUserResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
