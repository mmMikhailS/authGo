package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	"github.com/mmMikhailS/DeepBoard/internal/auth/domain/user"
	"go.uber.org/multierr"
)

const (
	pgDeadlockCode         = "40P01"
	pgSerializationFailure = "40001"
)

type postgresqlUser struct {
	ID    uuid.UUID `db:"id"`
	Email string    `db:"email"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`

	Name         string `db:"name"`
	PasswordHash string `db:"password_hash"`

	Status user.Status `db:"status"`
}

type PostgresSQLUserRepository struct {
	db          *sqlx.DB
	userFactory user.Factory
}

func NewPostgresSQLUserRepository(db *sqlx.DB, userFactory user.Factory) *PostgresSQLUserRepository {
	if db == nil {
		panic("nil db")
	}

	if userFactory.IsZero() {
		panic("nil userFactory")
	}

	return &PostgresSQLUserRepository{
		db:          db,
		userFactory: userFactory,
	}
}

type sqlContextGetter interface {
	GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
}

func (p *PostgresSQLUserRepository) GetUser(ctx context.Context, userID uuid.UUID) (*user.User, error) {
	query := `SELECT id, email, password_hash, updated_at, created_at, name, status FROM users WHERE id = $1`
	return p.getUser(ctx, query, userID)
}

func (p *PostgresSQLUserRepository) GetUserByEmail(ctx context.Context, email string) (*user.User, error) {
	query := `SELECT id, email, password_hash, updated_at, created_at, name, status FROM users WHERE email = $1`
	return p.getUser(ctx, query, email)
}

func (p *PostgresSQLUserRepository) CreateUser(ctx context.Context, u *user.User) error {
	dbUser := postgresqlUser{
		ID:           u.ID(),
		Email:        u.Email(),
		CreatedAt:    u.CreatedAt(),
		UpdatedAt:    u.UpdatedAt(),
		Name:         u.Name(),
		PasswordHash: u.PasswordHash(),
		Status:       u.Status(),
	}

	query := `
			INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
			VALUES (:id, :email, :name, :password_hash, :status, :created_at, :updated_at)`

	_, err := p.db.NamedExecContext(ctx, query, dbUser)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: %s", user.ErrUserAlreadyExists, u.Email())
		}
		return fmt.Errorf("failed to insert user into database: %w", err)
	}

	return nil
}

func (p *PostgresSQLUserRepository) UpdateUser(
	ctx context.Context,
	userID uuid.UUID,
	updateFn func(u *user.User) (*user.User, error),
) error {
	for {
		err := p.updateUser(ctx, userID, updateFn)
		if err == nil {
			return nil
		}

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgDeadlockCode || pgErr.Code == pgSerializationFailure {
				continue
			}
		}

		return err
	}
}

func (p *PostgresSQLUserRepository) updateUser(
	ctx context.Context,
	userID uuid.UUID,
	updateFn func(u *user.User) (*user.User, error),
) (err error) {
	tx, err := p.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}

	defer func() {
		err = p.finishTransaction(err, tx)
	}()

	existingUser, err := p.getUserForUpdate(ctx, tx, userID)
	if err != nil {
		return err
	}

	updatedUser, err := updateFn(existingUser)
	if err != nil {
		return err
	}

	if err := p.upsertUser(ctx, tx, updatedUser); err != nil {
		return err
	}

	return nil
}

func (p *PostgresSQLUserRepository) finishTransaction(err error, tx *sqlx.Tx) error {
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return multierr.Combine(err, rollbackErr)
		}
		return err
	}

	if commitErr := tx.Commit(); commitErr != nil {
		return fmt.Errorf("failed to commit tx: %s", commitErr)
	}

	return nil
}

func (p *PostgresSQLUserRepository) upsertUser(ctx context.Context, tx *sqlx.Tx, u *user.User) error {
	dbUser := postgresqlUser{
		ID:           u.ID(),
		Email:        u.Email(),
		CreatedAt:    u.CreatedAt(),
		UpdatedAt:    u.UpdatedAt(),
		Name:         u.Name(),
		PasswordHash: u.PasswordHash(),
		Status:       u.Status(),
	}

	query := `
		INSERT INTO users(
		                  id, email, created_at, updated_at, name, password_hash, status
		) VALUES (
		          :id, :email, :created_at, :updated_at, :name, :password_hash, :status
		)
		ON CONFLICT (id) DO UPDATE SET
		    email = excluded.email,
			updated_at = excluded.updated_at,
			name = excluded.name,
			password_hash = excluded.password_hash,
			status = excluded.status`

	_, err := tx.NamedExecContext(ctx, query, dbUser)
	if err != nil {
		return fmt.Errorf("unable to upsert user: %w", err)
	}

	return nil
}

func NewPostgresSQLConnection() *sqlx.DB {
	// TODO
	_, b, _, _ := runtime.Caller(0)
	basepath := filepath.Dir(b)

	err := godotenv.Load(filepath.Join(basepath, "../../../../.env"))

	login := os.Getenv("POSTGRES_USER")
	pass := os.Getenv("POSTGRES_PASSWORD")
	host := os.Getenv("POSTGRES_HOST")
	port := os.Getenv("POSTGRES_PORT")
	dbname := os.Getenv("POSTGRES_DB")

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", login, pass, host, port, dbname)

	db, err := sqlx.Connect("pgx", dsn)
	if err != nil {
		panic(fmt.Errorf("cannot connect to postgres: %s", err))
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db
}

func (p *PostgresSQLUserRepository) getUser(ctx context.Context, query string, userID any) (*user.User, error) {
	var u postgresqlUser
	err := p.db.GetContext(ctx, &u, query, userID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", user.ErrUserNotFound, userID)
		}
		return nil, fmt.Errorf("database error fetching user %s: %w", userID, err)
	}

	domainUser, err := p.userFactory.UnmarshalUserFromDatabase(u.toDBModel())
	if err != nil {
		return nil, err
	}

	return domainUser, nil
}

func (p *PostgresSQLUserRepository) getUserForUpdate(ctx context.Context, tx *sqlx.Tx, id uuid.UUID) (*user.User, error) {
	var u postgresqlUser
	query := `SELECT * FROM users WHERE id = $1 FOR UPDATE`
	err := tx.GetContext(ctx, &u, query, id)
	if err != nil {
		return nil, err
	}

	domainUser, err := p.userFactory.UnmarshalUserFromDatabase(u.toDBModel())
	if err != nil {
		return nil, err
	}

	return domainUser, nil
}

func (u *postgresqlUser) toDBModel() user.UserDBModel {
	return user.UserDBModel{
		ID:           u.ID,
		Email:        u.Email,
		Name:         u.Name,
		PasswordHash: u.PasswordHash,
		Status:       u.Status,
		CreatedAt:    u.CreatedAt.Truncate(time.Microsecond),
		UpdatedAt:    u.UpdatedAt.Truncate(time.Microsecond),
	}
}
