package auth

import (
	"context"
	"net/http"
	"strings"

	commonerrors "github.com/mmMikhailS/DeepBoard/internal/common/errors"
	"github.com/mmMikhailS/DeepBoard/internal/common/genproto/auth"
	"github.com/mmMikhailS/DeepBoard/internal/common/server/httperr"
)

type HttpMiddleware struct {
	AuthClient auth.AuthServiceClient
}

func (h HttpMiddleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		bearerToken := h.tokenFromHeader(r)
		if bearerToken == "" {
			httperr.Unauthorised("empty-bearer-token", nil, w, r)
			return
		}

		response, err := h.AuthClient.ValidateToken(ctx, &auth.ValidateTokenRequest{
			AccessToken: bearerToken,
		})
		if err != nil {
			httperr.Unauthorised("invalid-token", err, w, r)
			return
		}

		user := User{
			UUID:  response.UserId,
			Email: response.Email,
		}

		ctx = context.WithValue(ctx, userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h HttpMiddleware) tokenFromHeader(r *http.Request) string {
	headerValue := r.Header.Get("Authorization")

	if len(headerValue) > 7 && strings.ToLower(headerValue[0:6]) == "bearer" {
		return headerValue[7:]
	}

	return ""
}

type User struct {
	UUID  string
	Email string
	Role  string

	DisplayName string
}

type ctxKey int

const (
	userContextKey ctxKey = iota
)

var NoUserInContextError = commonerrors.NewAuthorizationError("no user in context", "no-user-found")

func UserFromCtx(ctx context.Context) (User, error) {
	if u, ok := ctx.Value(userContextKey).(User); ok {
		return u, nil
	}
	return User{}, NoUserInContextError
}
