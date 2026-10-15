package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AccessClaims struct {
	Email     string   `json:"email"`
	Scopes    []string `json:"scopes,omitempty"`
	TokenType string   `json:"token_type"`

	SessionID uuid.UUID `json:"sid,omitempty"`
	DeviceID  uuid.UUID `json:"device_id,omitempty"`

	jwt.RegisteredClaims
}

func (c *AccessClaims) GetSessionID() uuid.UUID { return c.SessionID }

type RefreshClaims struct {
	TokenType string `json:"token_type"`

	DeviceID  uuid.UUID `json:"device_id,omitempty"`
	SessionID uuid.UUID `json:"sid"`
	jwt.RegisteredClaims
}

func (c *RefreshClaims) GetSessionID() uuid.UUID { return c.SessionID }

type TokenType struct {
	slug string
}

func (t TokenType) String() string {
	return t.slug
}

var (
	Refresh = TokenType{"refreshToken"}
	Access  = TokenType{"accessToken"}
	Unknown = TokenType{"unknown"}
)
