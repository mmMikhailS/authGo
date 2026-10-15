package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidToken            = errors.New("invalid jwt")
	ErrInvalidTokenType        = errors.New("invalid jwt type")
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
	ErrGenerateToken           = errors.New("could not generate security token")
)

var (
	MaxAccessTTL  = 24 * time.Hour
	MaxRefreshTTL = 7 * 24 * time.Hour
	minRefreshTTL = 24 * time.Hour
	minAccessTTL  = 30 * time.Minute
)

type Token struct {
	issuer          string
	audience        []string
	currentAudience string
	refreshSecret   []byte
	accessSecret    []byte
	accessTTL       time.Duration
	refreshTTL      time.Duration
}

func NewToken(issuer, currentAudience, accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration, audience []string) *Token {
	if issuer == "" {
		panic("issuer name is empty")
	}

	if currentAudience == "" {
		panic("current audience name is empty")
	}

	if accessSecret == "" || refreshSecret == "" {
		panic("secret is empty")
	}

	if accessTTL == 0 || refreshTTL == 0 {
		panic("access ttl is zero")
	}

	if len(audience) < 1 {
		panic("audience length is empty")
	}

	if accessTTL < minAccessTTL {
		panic("access token lifetime must be higher than now")
	}

	if accessTTL > MaxAccessTTL {
		panic("access token lifetime must be less than now")
	}

	if refreshTTL < minRefreshTTL {
		panic("refresh token lifetime must be higher than now")
	}

	if refreshTTL > MaxRefreshTTL {
		panic("refresh token lifetime must be less than now")
	}

	return &Token{
		issuer:          issuer,
		audience:        audience,
		currentAudience: currentAudience,
		refreshSecret:   []byte(refreshSecret),
		accessSecret:    []byte(accessSecret),
		accessTTL:       accessTTL,
		refreshTTL:      refreshTTL,
	}
}

func (t *Token) GenerateTokenPair(
	deviceID uuid.UUID,
	sessionID uuid.UUID,
	userID uuid.UUID,
	email string,
	tokenID uuid.UUID,
	scopes []string,
) (accessToken, refreshToken string, err error) {
	accessToken, err = t.GenerateAccessToken(userID, sessionID, deviceID, email, scopes)
	if err != nil {
		return "", "", fmt.Errorf("%w: access token: %v", ErrGenerateToken, err)
	}

	refreshToken, err = t.GenerateRefreshToken(userID, sessionID, tokenID)
	if err != nil {
		return "", "", fmt.Errorf("%w: refresh token: %v", ErrGenerateToken, err)
	}

	return accessToken, refreshToken, nil
}
