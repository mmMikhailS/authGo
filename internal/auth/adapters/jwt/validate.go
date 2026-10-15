package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type SessionClaimer interface {
	jwt.Claims
	GetSessionID() uuid.UUID
}

func validateToken[C SessionClaimer](
	tokenStr string,
	secret []byte,
	claims C,
	extraChecks func(C) error,
) (C, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				var zero C
				return zero, ErrUnexpectedSigningMethod
			}
			return secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithLeeway(30*time.Second),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		var zero C
		return zero, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		var zero C
		return zero, ErrInvalidToken
	}

	if err := extraChecks(claims); err != nil {
		var zero C
		return zero, err
	}

	iat, err := claims.GetIssuedAt()
	if err != nil {
		var zero C
		return zero, fmt.Errorf("%w: invalid time claims", ErrInvalidToken)
	}

	nbf, err := claims.GetNotBefore()
	if err != nil {
		var zero C
		return zero, fmt.Errorf("%w: invalid time claims", ErrInvalidToken)
	}

	if !iat.Equal(nbf.Time) {
		var zero C
		return zero, fmt.Errorf("%w: issuedAt != notBefore", ErrInvalidToken)
	}

	return claims, nil
}

func (t *Token) validateCommon(claims *jwt.RegisteredClaims) error {
	if claims.ID == "" || claims.Subject == "" {
		return ErrInvalidToken
	}

	if claims.Issuer == "" || claims.Issuer != t.issuer {
		return ErrInvalidToken
	}

	if claims.ExpiresAt == nil || claims.NotBefore == nil || claims.IssuedAt == nil {
		return ErrInvalidToken
	}

	if len(claims.Audience) == 0 || !t.audienceContains(claims.Audience) {
		return ErrInvalidToken
	}

	return nil
}

func (t *Token) audienceContains(claimsAudience []string) bool {
	for _, v := range claimsAudience {
		if v == t.currentAudience {
			return true
		}
	}
	return false
}
