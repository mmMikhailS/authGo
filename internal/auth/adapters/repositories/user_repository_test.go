package repositories_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mmMikhailS/DeepBoard/internal/auth/adapters/password"
	"github.com/mmMikhailS/DeepBoard/internal/auth/adapters/repositories"
	"github.com/mmMikhailS/DeepBoard/internal/auth/domain/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testUserFactory    = user.MustNewFactory(user.NewFactoryConfig(testPasswordHasher))
	testPasswordHasher = password.NewPasswordHasher(password.MinMemory+1, password.MinIterations+1, password.MinKeyLength+1, password.MinSaltLength+1, password.MinParallelism+1)

	usedUsers = sync.Map{}
)

func TestRepository(t *testing.T) {
	t.Parallel()
	rand.NewSource(time.Now().UTC().UnixNano())

	testRepositories := createRepositories()

	for i := range testRepositories {
		r := testRepositories[i]

		t.Run(r.Name, func(t *testing.T) {
			t.Parallel()

			t.Run("testUpdateUser", func(t *testing.T) {
				t.Parallel()
				testUpdateUser(t, r.Repository)
			})
			t.Run("testUpdateUser_parallel", func(t *testing.T) {
				t.Parallel()
				testUpdateUser_parallel(t, r.Repository)
			})
			t.Run("testUpdateUser_rollback", func(t *testing.T) {
				t.Parallel()
				testUpdateUser_rollback(t, r.Repository)
			})
			t.Run("testUpdateUser_existing", func(t *testing.T) {
				t.Parallel()
				testUpdateUser_existing(t, r.Repository)
			})
			t.Run("testUpdateUser_changePassword", func(t *testing.T) {
				t.Parallel()
				testUpdateUser_changePassword(t, r.Repository)
			})
		})
	}
}

type Repository struct {
	Name       string
	Repository user.Repository
}

func createRepositories() []Repository {
	return []Repository{
		{
			Name:       "memory",
			Repository: repositories.NewMemoryUserRepository(testUserFactory),
		},
		{
			Name:       "postgresSQL",
			Repository: newPostgresSQLUserRepository(testUserFactory),
		},
	}
}

func testUpdateUser(t *testing.T, repository user.Repository) {
	t.Helper()
	ctx := context.Background()

	testCases := []struct {
		Name   string
		Update func(*testing.T, *user.User)
	}{
		{
			Name: "block_user",
			Update: func(t *testing.T, u *user.User) {
				require.NoError(t, u.Block())
			},
		},
		{
			Name: "activate_user",
			Update: func(t *testing.T, u *user.User) {
				require.NoError(t, u.Activate())
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			u := newValidUser(t)
			require.NoError(t, repository.CreateUser(ctx, u))

			err := repository.UpdateUser(ctx, u.ID(), func(uFromRepo *user.User) (*user.User, error) {
				tc.Update(t, u)
				u = uFromRepo
				return uFromRepo, nil
			})
			require.NoError(t, err)
			assertUserInRepository(ctx, t, repository, u)
		})
	}
}

func testUpdateUser_parallel(t *testing.T, repository user.Repository) {
	t.Helper()
	ctx := context.Background()

	u := newValidUser(t)
	err := repository.CreateUser(ctx, u)
	require.NoError(t, err)

	err = repository.UpdateUser(ctx, u.ID(), func(u *user.User) (*user.User, error) {
		if active := u.CanLogin(); active {
			return nil, user.ErrUserAlreadyActive
		}
		return u, nil
	})
	require.NoError(t, err)

	workersCount := 20
	workersDone := sync.WaitGroup{}
	workersDone.Add(workersCount)

	startWorkers := make(chan struct{})
	usersActivated := make(chan int, workersCount)

	for worker := 0; worker < workersCount; worker++ {
		workerNum := worker

		go func() {
			defer workersDone.Done()
			<-startWorkers

			userActivated := false

			err := repository.UpdateUser(ctx, u.ID(), func(u *user.User) (*user.User, error) {
				if u.CanLogin() {
					return u, nil
				}

				if err := u.Activate(); err != nil {
					return nil, err
				}

				userActivated = true
				return u, nil
			})

			if userActivated && err == nil {
				usersActivated <- workerNum
			}
		}()
	}

	close(startWorkers)

	workersDone.Wait()
	close(usersActivated)

	var workersActivatedUsers []int

	for workerNum := range usersActivated {
		workersActivatedUsers = append(workersActivatedUsers, workerNum)
	}

	assert.Len(t, workersActivatedUsers, 1, "only one worker should activate user")
}

func testUpdateUser_rollback(t *testing.T, repository user.Repository) {
	t.Helper()
	ctx := context.Background()

	u := newValidUser(t)
	err := repository.CreateUser(ctx, u)
	require.NoError(t, err)

	err = repository.UpdateUser(ctx, u.ID(), func(u *user.User) (*user.User, error) {
		require.NoError(t, u.Activate())
		return u, nil
	})
	require.NoError(t, err)

	err = repository.UpdateUser(ctx, u.ID(), func(u *user.User) (*user.User, error) {
		assert.True(t, u.CanLogin())
		require.NoError(t, u.Block())

		return u, errors.New("something went wrong")
	})
	require.Error(t, err)

	persistedUser, err := repository.GetUser(ctx, u.ID())
	require.NoError(t, err)

	assert.True(t, persistedUser.CanLogin(), "User activated successfully, not rolled back")
}

func testUpdateUser_existing(t *testing.T, repository user.Repository) {
	t.Helper()
	ctx := context.Background()

	u := newValidUser(t)
	err := repository.CreateUser(ctx, u)
	require.NoError(t, err)

	err = repository.UpdateUser(ctx, u.ID(), func(_ *user.User) (*user.User, error) {
		return u, nil
	})
	require.NoError(t, err)
	assertUserInRepository(ctx, t, repository, u)

	expectedName := "test1"
	err = repository.UpdateUser(ctx, u.ID(), func(u *user.User) (*user.User, error) {
		if err := u.UpdateName(expectedName); err != nil {
			return nil, err
		}
		return u, nil
	})
	require.NoError(t, err)

	actualUser, err := repository.GetUser(ctx, u.ID())
	require.NoError(t, err)
	assert.Equal(t, expectedName, actualUser.Name())
}

func testUpdateUser_changePassword(t *testing.T, repository user.Repository) {
	t.Helper()
	ctx := context.Background()

	initialPassword := "oldPassword"
	u, err := testUserFactory.NewUser(fmt.Sprintf("%s@gmail.com", uuid.New()), "Test", initialPassword)
	require.NoError(t, err)
	usedUsers.LoadOrStore(u.ID(), true)

	err = repository.CreateUser(ctx, u)
	require.NoError(t, err)

	newPassword := "newPassword"
	err = repository.UpdateUser(ctx, u.ID(), func(u *user.User) (*user.User, error) {
		if err := u.ChangePassword(newPassword, initialPassword, testPasswordHasher); err != nil {
			return nil, err
		}
		return u, nil
	})
	require.NoError(t, err)

	updatedUser, err := repository.GetUser(ctx, u.ID())
	require.NoError(t, err)

	ok, err := testPasswordHasher.VerifyPassword(newPassword, updatedUser.PasswordHash())
	require.NoError(t, err)
	assert.True(t, ok)
}

func newValidUser(t *testing.T) *user.User {
	t.Helper()
	for {
		email := fmt.Sprintf("%s@gmail.com", uuid.New())
		name := "test-user"
		testPassword := "password"

		u, err := testUserFactory.NewUser(email, name, testPassword)
		require.NoError(t, err)

		_, alreadyUsed := usedUsers.LoadOrStore(u.ID(), true)
		if !alreadyUsed {
			return u
		}
	}
}

func assertUserInRepository(ctx context.Context, t *testing.T, repo user.Repository, expectedUser *user.User) {
	t.Helper()

	actualUser, err := repo.GetUser(ctx, expectedUser.ID())
	require.NoError(t, err)

	assert.Equal(t, expectedUser.ID(), actualUser.ID())
	assert.Equal(t, expectedUser.Name(), actualUser.Name())
	assert.Equal(t, expectedUser.Email(), actualUser.Email())
	assert.Equal(t, expectedUser.Status(), actualUser.Status())
	assert.WithinDuration(t, expectedUser.CreatedAt(), actualUser.CreatedAt(), time.Second)
	assert.Equal(t, expectedUser.PasswordHash(), actualUser.PasswordHash())
}

func newPostgresSQLUserRepository(userFactory user.Factory) *repositories.PostgresSQLUserRepository {
	db := repositories.NewPostgresSQLConnection()
	return repositories.NewPostgresSQLUserRepository(db, userFactory)
}
