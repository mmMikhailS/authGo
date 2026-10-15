package client

import (
	"context"
	"strings"

	"google.golang.org/grpc/credentials"
)

type metadataServerToken struct {
	serviceURL string
}

func newMetadataServerToken(grpcAddr string) credentials.PerRPCCredentials {
	serviceURL := "https://" + strings.Split(grpcAddr, ":")[0]

	return metadataServerToken{serviceURL}
}

// TODO
//func (t metadataServerToken) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
//
//
//	return map[string]string{
//		"authorization": "Bearer " + idToken,
//	}, nil
//}

func (metadataServerToken) RequireTransportSecurity() bool {
	return true
}
