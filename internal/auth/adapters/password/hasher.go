package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	MaxMemory = 1024 * 1024
	MinMemory = 16 * 1024

	MaxIterations = 10
	MinIterations = 1

	MaxParallelism = 32
	MinParallelism = 1

	MinSaltLength = 16
	MinKeyLength  = 32
)

var (
	ErrResourceLimitExceeded = errors.New("resource limit exceeded")
	ErrInvalidHashFormat     = errors.New("invalid password hash format")
	ErrInvalidSalt           = errors.New("invalid salt")
	ErrShortPasswordLength   = errors.New("password is too short")
)

type Hasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func NewPasswordHasher(memory, iterations, keyLength, saltLength uint32, parallelism uint8) *Hasher {
	if memory > MaxMemory {
		panic("memory too high")
	}

	if memory < MinMemory {
		panic("memory too low")
	}

	if iterations < MinIterations || iterations > MaxIterations {
		panic("iterations out of safe bounds")
	}

	if parallelism < MinParallelism || parallelism > MaxParallelism {
		panic("parallelism out of safe bounds")
	}

	if saltLength < MinSaltLength {
		panic("salt too short")
	}

	if keyLength < MinKeyLength {
		panic("key length too short")
	}

	return &Hasher{
		memory:      memory,
		iterations:  iterations,
		parallelism: parallelism,
		saltLength:  saltLength,
		keyLength:   keyLength,
	}
}

func (h *Hasher) HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", ErrShortPasswordLength
	}

	salt := make([]byte, h.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.iterations,
		h.memory,
		h.parallelism,
		h.keyLength,
	)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		h.memory,
		h.iterations,
		h.parallelism,
		encodedSalt,
		encodedHash,
	), nil
}

func (h *Hasher) VerifyPassword(rawPassword, storedHash string) (bool, error) {
	parts := strings.Split(storedHash, "$")
	if len(parts) != 5 {
		return false, ErrInvalidHashFormat
	}

	if parts[0] != "argon2id" {
		return false, ErrInvalidHashFormat
	}

	if parts[1] != "v=19" {
		return false, ErrInvalidHashFormat
	}

	params, err := parseParams(parts[2])
	if err != nil {
		return false, err
	}

	if params.iterations > MaxIterations || params.iterations < MinIterations {
		return false, ErrResourceLimitExceeded
	}

	if params.memory > MaxMemory || params.memory < MinMemory {
		return false, ErrResourceLimitExceeded
	}

	if params.parallelism > MaxParallelism || params.parallelism < MinParallelism {
		return false, ErrResourceLimitExceeded
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, ErrInvalidSalt
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHashFormat
	}

	if len(salt) < 8 {
		return false, ErrInvalidSalt
	}

	actualHash := argon2.IDKey(
		[]byte(rawPassword),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		uint32(len(expectedHash)),
	)

	if subtle.ConstantTimeCompare(actualHash, expectedHash) == 1 {
		return true, nil
	}
	return false, nil
}

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

func parseParams(s string) (argon2Params, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 3 {
		return argon2Params{}, ErrInvalidHashFormat
	}

	memory, err := parseParamUint32(parts[0], "m")
	if err != nil {
		return argon2Params{}, err
	}

	iterations, err := parseParamUint32(parts[1], "t")
	if err != nil {
		return argon2Params{}, err
	}

	parallelism, err := parseParamUint32(parts[2], "p")
	if err != nil {
		return argon2Params{}, err
	}

	if parallelism > 255 {
		return argon2Params{}, ErrInvalidHashFormat
	}

	return argon2Params{
		memory:      memory,
		iterations:  iterations,
		parallelism: uint8(parallelism),
	}, nil
}

func parseParamUint32(part, key string) (uint32, error) {
	prefix := key + "="
	if !strings.HasPrefix(part, prefix) {
		return 0, ErrInvalidHashFormat
	}

	value, err := strconv.ParseUint(strings.TrimPrefix(part, prefix), 10, 32)
	if err != nil {
		return 0, ErrInvalidHashFormat
	}

	return uint32(value), nil
}
