package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/mmMikhailS/DeepBoard/internal/common/genproto/auth"
	"github.com/mmMikhailS/DeepBoard/internal/common/genproto/twofa"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func NewAuthClient() (client auth.AuthServiceClient, close func() error, err error) {
	grpcAddr := os.Getenv("AUTH_GRPC_ADDR")
	if grpcAddr == "" {
		return nil, func() error { return nil }, errors.New("empty env AUTH_GRPC_ADDR")
	}

	opts, err := grpcDialOpts()
	if err != nil {
		return nil, func() error { return nil }, err
	}

	conn, err := grpc.Dial(grpcAddr, opts...)
	if err != nil {
		return nil, func() error { return nil }, err
	}

	return auth.NewAuthServiceClient(conn), conn.Close, nil
}

func WaitForAuthService(timeout time.Duration) bool {
	return waitForPort(os.Getenv("AUTH_GRPC_ADDR"), timeout)
}

func NewTwoFAClient() (client twofa.TwofaServiceClient, close func() error, err error) {
	grpcAddr := os.Getenv("TWOFA_GRPC_ADDR")
	if grpcAddr == "" {
		return nil, func() error { return nil }, errors.New("empty env TWOFA_GRPC_ADDR")
	}

	opts, err := grpcDialOpts()
	if err != nil {
		return nil, func() error { return nil }, err
	}

	conn, err := grpc.Dial(grpcAddr, opts...)
	if err != nil {
		return nil, func() error { return nil }, err
	}

	return twofa.NewTwofaServiceClient(conn), conn.Close, nil
}

func WaitForTwoFAService(timeout time.Duration) bool {
	return waitForPort(os.Getenv("TWOFA_GRPC_ADDR"), timeout)
}

func grpcDialOpts() ([]grpc.DialOption, error) {
	if noTLS, _ := strconv.ParseBool(os.Getenv("GRPC_NO_TLS")); noTLS {
		return []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}, nil
	}

	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("cannot load root CA cert: %w", err)
	}
	creds := credentials.NewTLS(&tls.Config{
		RootCAs:    systemRoots,
		MinVersion: tls.VersionTLS12,
	})

	return []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		/*grpc.WithPerRPCCredentials(newMetadataServerToken(grpcAddr)),*/
	}, nil
}
