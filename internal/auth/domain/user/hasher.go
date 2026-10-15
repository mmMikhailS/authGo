package user

type PasswordHasher interface {
	HashPassword(password string) (string, error)
	VerifyPassword(rawPassword, storedHash string) (bool, error)
}
