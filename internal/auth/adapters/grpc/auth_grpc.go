package grpc

import (
	"context"

	"github.com/mmMikhailS/DeepBoard/internal/auth/adapters/jwt"
	"github.com/mmMikhailS/DeepBoard/internal/common/genproto/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthGrpc struct {
	auth.UnimplementedAuthServiceServer
	tokenService jwt.Token
}

func NewAuthGrpc(tokenService jwt.Token) *AuthGrpc {
	return &AuthGrpc{tokenService: tokenService}
}

func (s *AuthGrpc) ValidateToken(_ context.Context, in *auth.ValidateTokenRequest) (*auth.ValidateTokenResponse, error) {
	claims, err := s.tokenService.ValidateAccessToken(in.AccessToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}

	return &auth.ValidateTokenResponse{
		Valid:  true,
		UserId: claims.ID,
		Email:  claims.Email,
	}, nil
}
