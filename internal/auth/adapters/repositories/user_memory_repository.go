package repositories

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/mmMikhailS/DeepBoard/internal/auth/domain/user"
)

type MemoryUserRepository struct {
	lock sync.Mutex

	users  map[uuid.UUID]*user.User
	emails map[string]uuid.UUID

	UserFactory *user.Factory
}

func NewMemoryUserRepository(userFactory user.Factory) *MemoryUserRepository {
	if userFactory.IsZero() {
		panic("missing userFactory")
	}

	return &MemoryUserRepository{
		users:       make(map[uuid.UUID]*user.User),
		emails:      make(map[string]uuid.UUID),
		UserFactory: &userFactory,
	}
}

func (m *MemoryUserRepository) GetUser(_ context.Context, userID uuid.UUID) (*user.User, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	u, ok := m.users[userID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", user.ErrUserNotFound, userID)
	}

	return m.cloneUser(u), nil
}

func (m *MemoryUserRepository) GetUserByEmail(_ context.Context, email string) (*user.User, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	userID, ok := m.emails[email]
	if !ok {
		return nil, fmt.Errorf("%w: %s", user.ErrUserNotFound, email)
	}

	u, ok := m.users[userID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", user.ErrUserNotFound, userID)
	}

	return m.cloneUser(u), nil
}

func (m *MemoryUserRepository) CreateUser(_ context.Context, u *user.User) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, exists := m.emails[u.Email()]; exists {
		return user.ErrUserAlreadyExists
	}

	m.users[u.ID()] = u
	m.emails[u.Email()] = u.ID()

	return nil
}

func (m *MemoryUserRepository) UpdateUser(
	_ context.Context,
	userID uuid.UUID,
	updateFn func(u *user.User) (*user.User, error),
) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	existing, ok := m.users[userID]
	if !ok {
		return user.ErrUserNotFound
	}

	cloned := m.cloneUser(existing)
	updatedUser, err := updateFn(cloned)
	if err != nil {
		return err
	}

	if updatedUser.Email() != existing.Email() {
		if _, taken := m.emails[updatedUser.Email()]; taken {
			return user.ErrUserAlreadyExists
		}
		delete(m.emails, existing.Email())
		m.emails[updatedUser.Email()] = userID
	}

	m.users[userID] = updatedUser
	return nil
}

func (m *MemoryUserRepository) cloneUser(u *user.User) *user.User {
	tmp := *u
	return &tmp
}
