package http

import (
	"github.com/google/uuid"
	"github.com/mmMikhailS/DeepBoard/internal/auth/domain/user"
)

type Factory interface {
	NewUser(email, name, password string) (*user.User, error)
}

type TokenService interface {
	GenerateTokenPair(
		deviceID uuid.UUID,
		sessionID uuid.UUID,
		userID uuid.UUID,
		email string,
		tokenID uuid.UUID,
		scopes []string,
	) (accessToken, refreshToken string, err error)
}
