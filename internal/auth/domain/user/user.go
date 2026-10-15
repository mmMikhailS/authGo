package user

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user with this email already exists")

	ErrValueIsEmpty = errors.New("value is empty")

	ErrOldPasswordEqualsNewPassword = errors.New("old password equals new password")
	ErrPasswordMissMatch            = errors.New("password doesn't equals each other")
)

type User struct {
	id    uuid.UUID
	email string

	createdAt time.Time
	updatedAt time.Time

	name         string
	passwordHash string

	status Status
}

func (f Factory) NewUser(email, name, password string) (*User, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	password = strings.TrimSpace(password)
	name = strings.TrimSpace(name)

	if email == "" || !strings.Contains(email, "@") {
		return nil, errors.New("invalid email")
	}

	if name == "" {
		return nil, errors.New("name is required")
	}

	if password == "" {
		return nil, errors.New("password hash is required")
	}

	passwordHash, err := f.fc.passwordHasher.HashPassword(password)
	if err != nil {
		return nil, err
	}

	return &User{
		id:           uuid.New(),
		email:        email,
		name:         name,
		passwordHash: passwordHash,
		status:       StatusPending,
		createdAt:    time.Now(),
		updatedAt:    time.Now(),
	}, nil
}

func (u *User) ID() uuid.UUID {
	return u.id
}

func (u *User) CreatedAt() time.Time {
	return u.createdAt
}

func (u *User) UpdatedAt() time.Time {
	return u.updatedAt
}

func (u *User) Email() string {
	return u.email
}

func (u *User) Name() string {
	return u.name
}

func (u *User) PasswordHash() string {
	return u.passwordHash
}

func (u *User) Status() Status {
	return u.status
}

func (u *User) DefaultScopes() []Scope {
	return []Scope{ScopeDesignRead}
}

func (f Factory) Config() FactoryConfig {
	return f.fc
}

func (f Factory) IsZero() bool {
	return f == Factory{}
}

func (u *User) CanLogin() bool {
	return u.status == StatusActive
}

func (u *User) Activate() error {
	if u.status == StatusActive {
		return ErrUserAlreadyActive
	}

	u.status = StatusActive
	return nil
}

func (u *User) Block() error {
	if u.status == StatusBlocked {
		return ErrUserAlreadyBlocked
	}

	u.status = StatusBlocked
	return nil
}

func (u *User) ChangePassword(newPassword, oldPassword string, hasher PasswordHasher) error {
	if oldPassword == newPassword {
		return ErrOldPasswordEqualsNewPassword
	}

	ok, err := hasher.VerifyPassword(oldPassword, u.passwordHash)
	if err != nil {
		return err
	}
	if !ok {
		return ErrPasswordMissMatch
	}

	hashedNewPassword, err := hasher.HashPassword(newPassword)
	if err != nil {
		return err
	}

	u.passwordHash = hashedNewPassword
	return nil
}

func (u *User) UpdateName(newName string) error {
	if newName == "" {
		return ErrValueIsEmpty
	}

	u.name = newName
	return nil
}

type Factory struct {
	fc FactoryConfig
}

func NewFactory(fc FactoryConfig) (Factory, error) {
	if err := fc.Validate(); err != nil {
		return Factory{}, err
	}

	return Factory{
		fc: fc,
	}, nil
}

func MustNewFactory(fc FactoryConfig) Factory {
	f, err := NewFactory(fc)
	if err != nil {
		panic(err)
	}

	return f
}

type FactoryConfig struct {
	passwordHasher PasswordHasher
}

func NewFactoryConfig(passwordHasher PasswordHasher) FactoryConfig {
	return FactoryConfig{
		passwordHasher: passwordHasher,
	}
}

func (fc FactoryConfig) Validate() error {
	if fc.passwordHasher == nil {
		return errors.New("missing hasher in config")
	}
	return nil
}

type UserDBModel struct {
	ID           uuid.UUID
	Email        string
	Name         string
	PasswordHash string
	Status       Status
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (f Factory) UnmarshalUserFromDatabase(m UserDBModel) (*User, error) {
	if m.ID == uuid.Nil {
		return nil, ErrValueIsEmpty
	}

	if m.Email == "" || m.Name == "" || m.PasswordHash == "" {
		return nil, ErrValueIsEmpty
	}

	if m.Status.String() == "" {
		return nil, ErrValueIsEmpty
	}

	if m.CreatedAt.IsZero() || m.UpdatedAt.IsZero() {
		return nil, ErrValueIsEmpty
	}

	return &User{
		id:           m.ID,
		email:        m.Email,
		createdAt:    m.CreatedAt,
		updatedAt:    m.UpdatedAt,
		name:         m.Name,
		passwordHash: m.PasswordHash,
		status:       m.Status,
	}, nil
}
