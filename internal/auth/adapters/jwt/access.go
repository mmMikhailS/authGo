package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (t *Token) GenerateAccessToken(userID, sessionID, deviceID uuid.UUID, email string, scopes []string) (string, error) {
	if userID == uuid.Nil || sessionID == uuid.Nil || deviceID == uuid.Nil || email == "" || len(scopes) == 0 {
		return "", errors.New("invalid uuid parameters for token generation")
	}

	now := time.Now()
	tokenID := uuid.NewString()

	claims := AccessClaims{
		Email:     email,
		Scopes:    scopes,
		TokenType: Access.slug,
		SessionID: sessionID,
		DeviceID:  deviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.issuer,
			Subject:   userID.String(),
			Audience:  t.audience,
			ExpiresAt: jwt.NewNumericDate(now.Add(t.accessTTL)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedStr, err := token.SignedString(t.accessSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}
	return signedStr, nil
}

func (t *Token) ValidateAccessToken(tokenStr string) (*AccessClaims, error) {
	claims, err := validateToken(tokenStr, t.accessSecret, &AccessClaims{}, t.validAccess)
	if err != nil {
		return nil, err
	}

	if claims.ExpiresAt.Time.After(time.Now().Add(t.accessTTL + time.Minute)) {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func (t *Token) validAccess(claims *AccessClaims) error {
	if claims.Email == "" ||
		len(claims.Scopes) == 0 ||
		claims.DeviceID == uuid.Nil ||
		claims.SessionID == uuid.Nil {
		return ErrInvalidToken
	}

	if claims.TokenType != Access.slug {
		return ErrInvalidTokenType
	}

	maxAllowedExpiry := time.Now().Add(t.accessTTL + (5 * time.Minute))
	if claims.ExpiresAt.Time.After(maxAllowedExpiry) {
		return fmt.Errorf("%w: token lifetime exceeds security policy", ErrInvalidToken)
	}

	return t.validateCommon(&claims.RegisteredClaims)
}
