package app

import "github.com/mmMikhailS/DeepBoard/internal/auth/app/http"

type Application struct {
	Http Http
}

type Http struct {
	RegisterUser http.RegisterUserHandler
	LoginUser    http.LoginUserHandler
}
