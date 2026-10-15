package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	//grpcServer "github.com/mmMikhailS/DeepBoard/internal/auth/adapters/grpc"
	"github.com/mmMikhailS/DeepBoard/internal/auth/ports"
	"github.com/mmMikhailS/DeepBoard/internal/auth/service"
	//"github.com/mmMikhailS/DeepBoard/internal/common/genproto/auth"
	"github.com/mmMikhailS/DeepBoard/internal/common/logs"
	"github.com/mmMikhailS/DeepBoard/internal/common/server"
	//"google.golang.org/grpc"
)

func main() {
	logs.Init()

	app := service.NewApplication()

	// TODO:
	//go server.RunGRPCServer(func(s *grpc.Server) {
	//	svc := grpcServer.NewAuthGrpc(app.TokenService)
	//	auth.RegisterAuthServiceServer(s, svc)
	//})

	server.RunHTTPServer(func(router chi.Router) http.Handler {
		return ports.HandlerFromMux(ports.NewHttpServer(app), router)
	})
}
