package jwt_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	authJwt "github.com/mmMikhailS/DeepBoard/internal/auth/adapters/jwt"
	"github.com/stretchr/testify/assert"
)

func TestGenerateAccessToken(t *testing.T) {
	accessSecret := "test-access-secret-123456789123456789123456789"
	issuer := "canva-app"
	audience := []string{"web"}

	email := "test@canva.com"
	uID := uuid.New()
	sID := uuid.New()
	dID := uuid.New()
	scopes := []string{"designs:read"}

	tests := []struct {
		name        string
		deviceID    uuid.UUID
		sessionID   uuid.UUID
		userID      uuid.UUID
		email       string
		scopes      []string
		wantErr     bool
		expectedErr string
	}{
		{
			name:      "success - valid token generation",
			deviceID:  dID,
			sessionID: sID,
			userID:    uID,
			email:     email,
			scopes:    scopes,
			wantErr:   false,
		},
		{
			name:        "error - nil device id",
			deviceID:    uuid.Nil,
			sessionID:   sID,
			userID:      uID,
			email:       email,
			scopes:      scopes,
			wantErr:     true,
			expectedErr: "invalid uuid parameters for token generation",
		},
		{
			name:        "error - nil session id",
			deviceID:    dID,
			sessionID:   uuid.Nil,
			userID:      uID,
			email:       email,
			scopes:      scopes,
			wantErr:     true,
			expectedErr: "invalid uuid parameters for token generation",
		},
		{
			name:        "error - nil user id",
			deviceID:    dID,
			sessionID:   sID,
			userID:      uuid.Nil,
			email:       email,
			scopes:      scopes,
			wantErr:     true,
			expectedErr: "invalid uuid parameters for token generation",
		},
		{
			name:        "error - empty email",
			deviceID:    dID,
			sessionID:   sID,
			userID:      uID,
			email:       "",
			scopes:      scopes,
			wantErr:     true,
			expectedErr: "invalid uuid parameters for token generation",
		},
		{
			name:        "error - empty scopes",
			deviceID:    dID,
			sessionID:   sID,
			userID:      uID,
			email:       email,
			scopes:      []string{},
			wantErr:     true,
			expectedErr: "invalid uuid parameters for token generation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			provider := authJwt.NewToken(
				issuer,
				"web",
				accessSecret,
				"ref-sec",
				31*time.Minute,
				25*time.Hour,
				audience,
			)

			token, err := provider.GenerateAccessToken(tt.userID, tt.sessionID, tt.deviceID, tt.email, tt.scopes)

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

func TestValidateAccessToken(t *testing.T) {
	issuer := "deep-board-app"
	currentAudience := "web-client"
	fullAudience := []string{"web-client", "mobile-client"}
	accessSecret := []byte("secret-12345678901234567890123456")

	tID := uuid.New().String()
	email := "test@deepBoard.com"
	scopes := []string{"designs:read"}
	subject := uuid.New().String()
	sID := uuid.New()
	dID := uuid.New()

	tests := []struct {
		name        string
		tokenString func() string
		wantErr     bool
		errType     error
	}{
		{
			name: "success - valid access token",
			tokenString: func() string {
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(31 * time.Minute)),
						NotBefore: jwt.NewNumericDate(time.Now()),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ID:        tID,
					},
				})
			},
			wantErr: false,
		},
		{
			name: "error - nil Email in token",
			tokenString: func() string {
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     "",
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(31 * time.Minute)),
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
			name: "error - nil Scopes in token",
			tokenString: func() string {
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    []string{},
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(31 * time.Minute)),
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
			name: "error - wrong TokenType in token",
			tokenString: func() string {
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Unknown.String(),
					SessionID: sID,
					DeviceID:  dID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(31 * time.Minute)),
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
			name: "error - nil SessionID in token",
			tokenString: func() string {
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: uuid.Nil,
					DeviceID:  dID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(31 * time.Minute)),
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
			name: "error - nil DeviceID in token",
			tokenString: func() string {
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  uuid.Nil,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(31 * time.Minute)),
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
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    "",
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(31 * time.Minute)),
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
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   "",
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(31 * time.Minute)),
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
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  nil,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(31 * time.Minute)),
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
			name: "error - nil tokenId in token",
			tokenString: func() string {
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  nil,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(31 * time.Minute)),
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
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
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
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
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
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
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
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
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
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
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
			name: "error - nil NotBefore in token",
			tokenString: func() string {
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(31 * time.Minute)),
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
			name: "error - nil IssuedAt in token",
			tokenString: func() string {
				return createTestAccessToken(accessSecret, authJwt.AccessClaims{
					Email:     email,
					Scopes:    scopes,
					TokenType: authJwt.Access.String(),
					SessionID: sID,
					DeviceID:  dID,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						Subject:   subject,
						Audience:  fullAudience,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(31 * time.Minute)),
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
				string(accessSecret),
				"ref-sec",
				31*time.Minute,
				25*time.Hour,
				fullAudience,
			)

			claims, err := provider.ValidateAccessToken(tt.tokenString())

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

func createTestAccessToken(secret []byte, claims authJwt.AccessClaims) string {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := t.SignedString(secret)
	return s
}
