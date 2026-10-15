package jwt_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	authJwt "github.com/mmMikhailS/DeepBoard/internal/auth/adapters/jwt"
	"github.com/stretchr/testify/assert"
)

func TestGenerateRefreshToken(t *testing.T) {
	refreshSecret := "test-refresh-secret-123456789123456789123456789"
	issuer := "canva-app"
	audience := []string{"web"}

	uID := uuid.New()
	sID := uuid.New()
	dID := uuid.New()

	tests := []struct {
		name        string
		deviceID    uuid.UUID
		sessionID   uuid.UUID
		userID      uuid.UUID
		wantErr     bool
		expectedErr string
	}{
		{
			name:      "success - valid token generation",
			deviceID:  dID,
			sessionID: sID,
			userID:    uID,
			wantErr:   false,
		},
		{
			name:        "error - nil device id",
			deviceID:    uuid.Nil,
			sessionID:   sID,
			userID:      uID,
			wantErr:     true,
			expectedErr: "invalid uuid parameters for token generation",
		},
		{
			name:        "error - nil session id",
			deviceID:    dID,
			sessionID:   uuid.Nil,
			userID:      uID,
			wantErr:     true,
			expectedErr: "invalid uuid parameters for token generation",
		},
		{
			name:        "error - nil user id",
			deviceID:    dID,
			sessionID:   sID,
			userID:      uuid.Nil,
			wantErr:     true,
			expectedErr: "invalid uuid parameters for token generation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			provider := authJwt.NewToken(
				issuer,
				"web",
				"acc-secret",
				refreshSecret,
				31*time.Minute,
				25*time.Hour,
				audience,
			)

			token, err := provider.GenerateRefreshToken(tt.userID, tt.sessionID, tt.deviceID)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)
			}
		})
	}
}

func TestValidateRefreshToken(t *testing.T) {
	issuer := "deep-board-app"
	currentAudience := "web-client"
	fullAudience := []string{"web-client", "mobile-client"}
	refreshSecret := []byte("secret-123456789012345678901234567")

	subject := uuid.New().String()
	tID := uuid.New().String()
	sID := uuid.New()
	dID := uuid.New()

	tests := []struct {
		name        string
		tokenString func() string
		wantErr     bool
		errType     error
	}{
		{
			name: "success - valid refresh token",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now()),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        tID,
					},
				})
			},
			wantErr: false,
		},
		{
			name: "error - wrong tokenType",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Unknown.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now()),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        tID,
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidTokenType,
		},
		{
			name: "error - nil DeviceID in token",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  uuid.Nil,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now()),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        tID,
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidToken,
		},
		{
			name: "error - nil SessionID in token",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: uuid.Nil,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now()),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        tID,
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidToken,
		},
		{
			name: "error - nil Issuer in token",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    "",
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now()),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        tID,
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidToken,
		},
		{
			name: "error - nil Subject in token",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   "",
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now()),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        tID,
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidToken,
		},
		{
			name: "error - nil Audience in token",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  nil,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now()),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        tID,
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidToken,
		},
		{
			name: "error - nil ID in token",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now()),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        "",
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidToken,
		},
		{
			name: "success - token expired 10s ago (Inside 30s Leeway)",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-10 * time.Second)),
						NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
						IssuedAt:  jwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
						ID:        tID,
					},
				})
			},
			wantErr: false,
		},
		{
			name: "error - token expired 1 hour ago (Outside Leeway)",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now()),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        tID,
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidToken,
		},
		{
			name: "error - eternal token max ttl protection",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * 365 * 10 * time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now().Add(time.Minute)),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        tID,
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidToken,
		},
		{
			name: "error - token issuedAt doesn't equal to notBefore",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-10 * time.Second)),
						NotBefore: jwt.NewNumericDate(time.Now().Add(-4 * time.Minute)),
						IssuedAt:  jwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
						ID:        tID,
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidToken,
		},
		{
			name: "error - nil ExpiresAt in token",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: nil,
						NotBefore: jwt.NewNumericDate(time.Now()),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        tID,
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidToken,
		},
		{
			name: "error - nil ExpiresAt in token",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
						NotBefore: nil,
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        tID,
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidToken,
		},
		{
			name: "error - nil ExpiresAt in token",
			tokenString: func() string {
				return createTestRefreshToken(refreshSecret, authJwt.RefreshClaims{
					TokenType: authJwt.Refresh.String(),
					DeviceID:  dID,
					SessionID: sID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now()),
						IssuedAt:  nil,
						ID:        tID,
					},
				})
			},
			wantErr: true,
			errType: authJwt.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			provider := authJwt.NewToken(
				issuer,
				currentAudience,
				"acc-sec",
				string(refreshSecret),
				31*time.Minute,
				25*time.Hour,
				fullAudience,
			)

			claims, err := provider.ValidateRefreshToken(tt.tokenString())

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
				assert.Nil(t, claims)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
			}
		})
	}
}

func createTestRefreshToken(secret []byte, claims authJwt.RefreshClaims) string {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := t.SignedString(secret)
	return s
}
