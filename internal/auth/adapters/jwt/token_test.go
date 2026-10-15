package jwt_test

import (
	"testing"
	"time"

	"github.com/mmMikhailS/DeepBoard/internal/auth/adapters/jwt"
	"github.com/stretchr/testify/assert"
)

func TestNewToken_Configuration_Validation(t *testing.T) {
	t.Run("should create valid provider", func(t *testing.T) {
		provider := jwt.NewToken("iss", "web", "acc-sec", "ref-sec", time.Hour, 25*time.Hour, []string{"web"})
		assert.NotNil(t, provider)
	})

	t.Run("should panic on empty issuer", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.NewToken("", "web", "acc-sec", "ref-sec", time.Hour, 25*time.Hour, []string{"web"})
		})
	})

	t.Run("should panic on empty current audience", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.NewToken("iss", "", "acc-sec", "ref-sec", time.Hour, 25*time.Hour, []string{"web"})
		})
	})

	t.Run("should panic on empty access secret", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.NewToken("iss", "web", "", "ref-sec", time.Hour, 25*time.Hour, []string{"web"})
		})
	})

	t.Run("should panic on empty refresh secret", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.NewToken("iss", "web", "acc-sec", "", time.Hour, 25*time.Hour, []string{"web"})
		})
	})

	t.Run("should panic on empty access ttl", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.NewToken("iss", "web", "acc-sec", "ref-sec", 0, 25*time.Hour, []string{"web"})
		})
	})

	t.Run("should panic on empty refresh ttl", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.NewToken("iss", "web", "acc-sec", "ref-sec", time.Hour, 0, []string{"web"})
		})
	})

	t.Run("should panic on empty audience", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.NewToken("iss", "web", "acc-sec", "ref-sec", time.Hour, 25*time.Hour, []string{})
		})
	})

	t.Run("should panic on short accessTTL", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.NewToken("iss", "web", "acc-sec", "ref-sec", time.Minute, 25*time.Hour, []string{"web"})
		})
	})

	t.Run("should panic on short accessTTL", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.NewToken("iss", "web", "acc-sec", "ref-sec", time.Minute, time.Hour, []string{"web"})
		})
	})

	t.Run("should panic on too high accessTTL", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.NewToken("iss", "web", "acc-sec", "ref-sec", 25*time.Hour, 25*time.Hour, []string{"web"})
		})
	})

	t.Run("should panic on too high refreshTTL", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.NewToken("iss", "web", "acc-sec", "ref-sec", time.Hour, 8*24*time.Hour, []string{"web"})
		})
	})
}
