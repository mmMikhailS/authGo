package service

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Argon2 Argon2Config
	JWT    JWTConfig
}

type Argon2Config struct {
	Memory      uint32
	Iterations  uint32
	KeyLength   uint32
	SaltLength  uint32
	Parallelism uint8
}

type JWTConfig struct {
	Issuer          string
	CurrentAudience string
	AccessSecret    string
	RefreshSecret   string
	AccessTTL       time.Duration
	RefreshTTL      time.Duration
	Audience        []string
}

func loadConfig() Config {
	var cfg Config
	_, b, _, _ := runtime.Caller(0)
	basepath := filepath.Dir(b)

	err := godotenv.Load(filepath.Join(basepath, "../../../.env"))
	if err != nil {
		panic(err)
	}

	cfg.Argon2.Memory = getEnvUint[uint32]("ARGON2_MEMORY")
	cfg.Argon2.Iterations = getEnvUint[uint32]("ARGON2_ITERATIONS")
	cfg.Argon2.KeyLength = getEnvUint[uint32]("ARGON2_KEY_LENGTH")
	cfg.Argon2.SaltLength = getEnvUint[uint32]("ARGON2_SALT_LENGTH")
	cfg.Argon2.Parallelism = getEnvUint[uint8]("ARGON2_PARALLELISM")

	cfg.JWT.Issuer = os.Getenv("JWT_ISSUER")
	cfg.JWT.CurrentAudience = os.Getenv("JWT_CURRENT_AUDIENCE")
	cfg.JWT.AccessSecret = os.Getenv("JWT_ACCESS_SECRET")
	cfg.JWT.RefreshSecret = os.Getenv("JWT_REFRESH_SECRET")

	cfg.JWT.AccessTTL = getEnvDuration("JWT_ACCESS_TTL")
	cfg.JWT.RefreshTTL = getEnvDuration("JWT_REFRESH_TTL")
	cfg.JWT.Audience = getEnvSlice("JWT_AUDIENCE")

	return cfg
}

func getEnvUint[T UintEnvType](key string) T {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Errorf("required environment variable %s is missing", key))
	}

	val, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		panic(fmt.Errorf("env %s must be a number: %w", key, err))
	}

	res := T(val)
	if uint64(res) != val {
		panic(fmt.Errorf("env %s value %d is out of range for %T", key, val, res))
	}
	return res
}

func getEnvDuration(key string) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Errorf("required environment variable %s is missing", key))
	}

	d, err := time.ParseDuration(v)
	if err != nil {
		panic(fmt.Errorf("env %s has invalid duration: %w", key, err))
	}
	return d
}

func getEnvSlice(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return []string{}
	}

	items := strings.Split(v, ";")
	for i := range items {
		items[i] = strings.TrimSpace(items[i])
	}

	return items
}

type UintEnvType interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}
