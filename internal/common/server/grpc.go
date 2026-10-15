package server

import (
	"fmt"
	"net"
	"os"

	"github.com/mmMikhailS/DeepBoard/internal/common/logs"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	grpcLogrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpcCtxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
)

func init() {
	logger := logrus.New()
	logs.SetFormatter(logger)
	logger.SetLevel(logrus.WarnLevel)

	grpcLogrus.ReplaceGrpcLogger(logrus.NewEntry(logger))
}

func RunGRPCServer(registerServer func(server *grpc.Server)) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := fmt.Sprintf(":%s", port)
	RunGRPCServerOnAddr(addr, registerServer)
}

func RunGRPCServerOnAddr(addr string, registerServer func(server *grpc.Server)) {
	logrusEntry := logrus.NewEntry(logrus.StandardLogger())

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpcCtxtags.UnaryServerInterceptor(
				grpcCtxtags.WithFieldExtractor(grpcCtxtags.CodeGenRequestFieldExtractor),
			),
			grpcLogrus.UnaryServerInterceptor(logrusEntry),
		),
		grpc.ChainStreamInterceptor(
			grpcCtxtags.StreamServerInterceptor(
				grpcCtxtags.WithFieldExtractor(grpcCtxtags.CodeGenRequestFieldExtractor),
			),
			grpcLogrus.StreamServerInterceptor(logrusEntry),
		),
	)
	registerServer(grpcServer)

	listen, err := net.Listen("tcp", addr)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.WithField("grpcEndpoint", addr).Info("Starting: gRPC Listener")
	logrus.Fatal(grpcServer.Serve(listen))
}
