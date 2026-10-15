package service

import (
	"github.com/mmMikhailS/DeepBoard/internal/auth/adapters/jwt"
	"github.com/mmMikhailS/DeepBoard/internal/auth/adapters/password"
	"github.com/mmMikhailS/DeepBoard/internal/auth/adapters/repositories"
	"github.com/mmMikhailS/DeepBoard/internal/auth/app"
	"github.com/mmMikhailS/DeepBoard/internal/auth/app/http"
	"github.com/mmMikhailS/DeepBoard/internal/auth/domain/user"
	"github.com/mmMikhailS/DeepBoard/internal/common/metrics"
	"github.com/sirupsen/logrus"
)

func NewApplication() app.Application {
	cfg := loadConfig()

	tokenService := jwt.NewToken(
		cfg.JWT.Issuer,
		cfg.JWT.CurrentAudience,
		cfg.JWT.AccessSecret,
		cfg.JWT.RefreshSecret,
		cfg.JWT.AccessTTL,
		cfg.JWT.RefreshTTL,
		cfg.JWT.Audience,
	)

	passwordHasher := password.NewPasswordHasher(
		cfg.Argon2.Memory,
		cfg.Argon2.Iterations,
		cfg.Argon2.KeyLength,
		cfg.Argon2.SaltLength,
		cfg.Argon2.Parallelism,
	)

	userFactoryConfig := user.NewFactoryConfig(passwordHasher)

	userFactory := user.MustNewFactory(userFactoryConfig)

	conn := repositories.NewPostgresSQLConnection()
	userRepository := repositories.NewPostgresSQLUserRepository(conn, userFactory)

	logger := logrus.NewEntry(logrus.StandardLogger())
	metricsClient := metrics.NoOp{}

	return app.Application{
		Http: app.Http{
			RegisterUser: http.NewRegisterUserHandler(userRepository, passwordHasher, tokenService, userFactory, logger, metricsClient),
			LoginUser:    http.NewLoginUserHandler(userRepository, passwordHasher, tokenService, userFactory, logger, metricsClient),
		},
	}
}
