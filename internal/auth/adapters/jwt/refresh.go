package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (t *Token) GenerateRefreshToken(userID, sessionID, deviceID uuid.UUID) (string, error) {
	if userID == uuid.Nil || sessionID == uuid.Nil || deviceID == uuid.Nil {
		return "", errors.New("invalid uuid parameters for token generation")
	}

	now := time.Now()
	tokenID := uuid.NewString()

	claims := RefreshClaims{
		TokenType: Access.String(),
		SessionID: sessionID,
		DeviceID:  deviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.issuer,
			Subject:   userID.String(),
			Audience:  t.audience,
			ExpiresAt: jwt.NewNumericDate(now.Add(t.refreshTTL)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedStr, err := token.SignedString(t.refreshSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return signedStr, nil
}

func (t *Token) ValidateRefreshToken(tokenStr string) (*RefreshClaims, error) {
	claims, err := validateToken(tokenStr, t.refreshSecret, &RefreshClaims{}, t.validRefresh)
	if err != nil {
		return nil, err
	}

	if claims.ExpiresAt.Time.After(time.Now().Add(t.refreshTTL + time.Minute)) {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func (t *Token) validRefresh(claims *RefreshClaims) error {
	if claims.TokenType != Refresh.String() {
		return ErrInvalidTokenType
	}

	if claims.SessionID == uuid.Nil ||
		claims.DeviceID == uuid.Nil {
		return ErrInvalidToken
	}

	return t.validateCommon(&claims.RegisteredClaims)
}
