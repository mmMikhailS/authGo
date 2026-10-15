package password_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/mmMikhailS/DeepBoard/internal/auth/adapters/password"
	"github.com/stretchr/testify/assert"
)

func newTestHasher() *password.Hasher {
	return password.NewPasswordHasher(uint32(65*1024), uint32(3), uint32(33), uint32(17), uint8(3))
}

func TestNewPasswordHasher(t *testing.T) {
	t.Run("Valid password hasher", func(t *testing.T) {
		provider := newTestHasher()
		assert.NotNil(t, provider)
	})

	t.Run("Memory too high", func(t *testing.T) {
		assert.Panics(t, func() {
			password.NewPasswordHasher(uint32(1025*1024), uint32(3), uint32(9), uint32(9), uint8(3))
		})
	})

	t.Run("Memory too low", func(t *testing.T) {
		assert.Panics(t, func() {
			password.NewPasswordHasher(uint32(1024), uint32(3), uint32(9), uint32(9), uint8(3))
		})
	})

	t.Run("iterations out of safe bounds", func(t *testing.T) {
		assert.Panics(t, func() {
			password.NewPasswordHasher(uint32(65*1024), uint32(0), uint32(9), uint32(9), uint8(3))
		})
	})

	t.Run("iterations out of safe bounds", func(t *testing.T) {
		assert.Panics(t, func() {
			password.NewPasswordHasher(uint32(65*1024), uint32(11), uint32(9), uint32(9), uint8(3))
		})
	})

	t.Run("parallelism out of safe bounds", func(t *testing.T) {
		assert.Panics(t, func() {
			password.NewPasswordHasher(uint32(65*1024), uint32(3), uint32(9), uint32(9), uint8(0))
		})
	})

	t.Run("parallelism out of safe bounds", func(t *testing.T) {
		assert.Panics(t, func() {
			password.NewPasswordHasher(uint32(65*1024), uint32(3), uint32(9), uint32(9), uint8(33))
		})
	})

	t.Run("salt too short", func(t *testing.T) {
		assert.Panics(t, func() {
			password.NewPasswordHasher(uint32(65*1024), uint32(3), uint32(9), uint32(15), uint8(33))
		})
	})

	t.Run("key length is too low", func(t *testing.T) {
		assert.Panics(t, func() {
			password.NewPasswordHasher(uint32(65*1024), uint32(3), uint32(6), uint32(9), uint8(3))
		})
	})
}

func TestHashPassword_Uniqueness(t *testing.T) {
	h := newTestHasher()
	pass := "password123"

	hash1, _ := h.HashPassword(pass)
	hash2, _ := h.HashPassword(pass)

	if hash1 == hash2 {
		t.Error("Hashing the same password twice produced the same result; salt is not random")
	}
}

func TestHashPassword_SaltLength(t *testing.T) {
	saltLen := uint32(33)
	h := password.NewPasswordHasher(uint32(65*1024), uint32(3), saltLen, uint32(17), uint8(3))
	hash, _ := h.HashPassword("password123")

	parts := strings.Split(hash, "$")

	decodedSalt, _ := base64.RawStdEncoding.DecodeString(parts[4])

	if len(decodedSalt) != int(saltLen) {
		t.Errorf("Expected salt length %d, got %d", saltLen, len(decodedSalt))
	}
}

func TestHashPassword_LengthValidation(t *testing.T) {
	h := newTestHasher()

	t.Run("password is too short", func(t *testing.T) {
		_, err := h.HashPassword("1234567")
		if !errors.Is(err, password.ErrShortPasswordLength) {
			t.Errorf("expected ErrShortPasswordLength, got %v", err)
		}
	})

	t.Run("password exactly 8", func(t *testing.T) {
		_, err := h.HashPassword("12345678")
		if err != nil {
			t.Errorf("expected no error for 8 chars, got %v", err)
		}
	})
}

func TestHashPassword_Format(t *testing.T) {
	h := password.NewPasswordHasher(65536, 3, 32, 16, 2)

	hashStr, err := h.HashPassword("password")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	parts := strings.Split(hashStr, "$")

	if len(parts) != 5 {
		t.Fatalf("expected 5 parts in hash string, got %d", len(parts))
	}

	if parts[0] != "argon2id" {
		t.Errorf("expected prefix argon2id, got %s", parts[0])
	}

	if parts[2] != "m=65536,t=3,p=2" {
		t.Errorf("expected params m=65536,t=3,p=2, got %s", parts[2])
	}
}

func TestHashPassword_InternalLengths(t *testing.T) {
	expectedSaltLen := uint32(24)
	expectedKeyLen := uint32(48)

	h := password.NewPasswordHasher(uint32(65*1024), 1, expectedKeyLen, expectedSaltLen, 1)
	hashStr, _ := h.HashPassword("password")

	parts := strings.Split(hashStr, "$")

	saltEncoded := parts[3]
	hashEncoded := parts[4]

	saltDecoded, _ := base64.RawStdEncoding.DecodeString(saltEncoded)
	hashDecoded, _ := base64.RawStdEncoding.DecodeString(hashEncoded)

	if len(saltDecoded) != int(expectedSaltLen) {
		t.Errorf("expected salt length %d, got %d", expectedSaltLen, len(saltDecoded))
	}

	if len(hashDecoded) != int(expectedKeyLen) {
		t.Errorf("expected hash length %d, got %d", expectedKeyLen, len(hashDecoded))
	}
}

func TestVerifyPassword(t *testing.T) {
	h := password.NewPasswordHasher(64*1024, 1, 32, 16, 1)
	correctPassword := "correct-password"
	wrongPassword := "wrong-password"

	storedHash, _ := h.HashPassword(correctPassword)

	t.Run("successful verification", func(t *testing.T) {
		match, err := h.VerifyPassword(correctPassword, storedHash)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !match {
			t.Error("expected password to match but it failed")
		}
	})

	t.Run("UTF-8 characters", func(t *testing.T) {
		p := "Ήλιος-Emoji-🔥"
		hash, _ := h.HashPassword(p)
		match, err := h.VerifyPassword(p, hash)
		if err != nil || !match {
			t.Errorf("failed UTF-8 verification")
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		match, err := h.VerifyPassword(wrongPassword, storedHash)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if match {
			t.Error("expected password to fail but it matched")
		}
	})

	t.Run("malformed hash string", func(t *testing.T) {
		invalidHashes := []string{
			"too-short",
			"argon2id$v=19$m=64$short$hash",
			"argon2id$v=99$m=64,t=1,p=1$salt$hash",
			"argon2id$v=19$m=abc,t=1,p=1$salt$hash",
		}

		for _, ih := range invalidHashes {
			match, err := h.VerifyPassword(correctPassword, ih)
			if err == nil {
				t.Errorf("expected error for malformed hash: %s", ih)
			}
			if match {
				t.Errorf("expected match to be false for malformed hash: %s", ih)
			}
		}
	})

	t.Run("corrupted base64", func(t *testing.T) {
		corrupted := storedHash[:len(storedHash)-1] + "?"
		match, err := h.VerifyPassword(correctPassword, corrupted)
		if err == nil {
			t.Error("expected error for corrupted base64")
		}
		if match {
			t.Error("expected match to be false for corrupted base64")
		}
	})

	t.Run("empty password", func(t *testing.T) {
		match, err := h.VerifyPassword("", storedHash)
		if err != nil {
			t.Errorf("unexpected error on empty password: %v", err)
		}
		if match {
			t.Error("empty password should not match 'password123'")
		}
	})

	t.Run("specific error types", func(t *testing.T) {
		tests := []struct {
			name     string
			hash     string
			expected error
		}{
			{"wrong prefix", "bcrypt$v=19$m=65536,t=2,p=1$s$h", password.ErrInvalidHashFormat},
			{"wrong version", "argon2id$v=18$m=65536,t=2,p=1$s$h", password.ErrInvalidHashFormat},
			{"missing params", "argon2id$v=19$salt$hash", password.ErrInvalidHashFormat},
			{"malformed salt", "argon2id$v=19$m=65536,t=2,p=1$invalid!salt$hash", password.ErrInvalidSalt},
			{"max iterations", "argon2id$v=19$m=65536,t=11,p=1$invalid!salt$hash", password.ErrResourceLimitExceeded},
			{"min iterations", "argon2id$v=19$m=65536,t=0,p=1$invalid!salt$hash", password.ErrResourceLimitExceeded},
			{"max memory", "argon2id$v=19$m=1049600,t=2,p=1$invalid!salt$hash", password.ErrResourceLimitExceeded},
			{"min memory", "argon2id$v=19$m=1024,t=2,p=1$invalid!salt$hash", password.ErrResourceLimitExceeded},
			{"max parallelism", "argon2id$v=19$m=65536,t=2,p=33$salt$hash", password.ErrResourceLimitExceeded},
			{"min parallelism", "argon2id$v=19$m=65536,t=2,p=0$salt$hash", password.ErrResourceLimitExceeded},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := h.VerifyPassword("password", tt.hash)
				if !errors.Is(err, tt.expected) {
					t.Errorf("expected error %v, got %v", tt.expected, err)
				}
			})
		}
	})

	t.Run("out of order params", func(t *testing.T) {
		outOfOrder := "argon2id$v=19$t=3,m=65536,p=2$salt$hash"
		_, err := h.VerifyPassword("password", outOfOrder)
		assert.ErrorIs(t, err, password.ErrInvalidHashFormat)
	})

	t.Run("iteration limit protection", func(t *testing.T) {
		highIterationHash := "argon2id$v=19$m=65536,t=100,p=1$c2FsdHNhbHQ$aGFzaGhhc2g"
		_, err := h.VerifyPassword("password", highIterationHash)
		if !errors.Is(err, password.ErrResourceLimitExceeded) {
			t.Errorf("expected ErrResourceLimitExceeded for high iterations, got %v", err)
		}
	})

	t.Run("empty parameter values", func(t *testing.T) {
		invalid := "argon2id$v=19$m=,t=,p=$salt$hash"
		_, err := h.VerifyPassword("password", invalid)
		assert.ErrorIs(t, err, password.ErrInvalidHashFormat)
	})

	t.Run("extremely long password", func(t *testing.T) {
		longPwd := strings.Repeat("a", 1024*1024)
		hash, _ := h.HashPassword(longPwd)
		match, err := h.VerifyPassword(longPwd, hash)
		if err != nil || !match {
			t.Error("failed extremely long password check")
		}
	})

	t.Run("resource exhaustion protection", func(t *testing.T) {
		hugeMemoryHash := "argon2id$v=19$m=4194304,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g"
		_, err := h.VerifyPassword("password", hugeMemoryHash)

		if err == nil {
			t.Error("expected error when hash exceeds safe memory limits")
		}
	})

	t.Run("zero values", func(t *testing.T) {
		zeroHash := "argon2id$v=19$m=0,t=0,p=0$salt$hash"
		_, err := h.VerifyPassword("password", zeroHash)
		if err == nil {
			t.Error("expected error for zero parameters")
		}
	})
}
