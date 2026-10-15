package user

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	GetUserByEmail(_ context.Context, email string) (*User, error)
	GetUser(_ context.Context, userID uuid.UUID) (*User, error)
	CreateUser(_ context.Context, u *User) error
	UpdateUser(_ context.Context, userID uuid.UUID, updateFn func(u *User) (*User, error)) error
}
