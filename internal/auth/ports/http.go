package ports

import (
	"net/http"

	"github.com/go-chi/render"
	"github.com/mmMikhailS/DeepBoard/internal/auth/adapters/jwt"
	"github.com/mmMikhailS/DeepBoard/internal/auth/app"
	appHttp "github.com/mmMikhailS/DeepBoard/internal/auth/app/http"
	"github.com/mmMikhailS/DeepBoard/internal/common/server/httperr"
)

type HttpServer struct {
	app app.Application
}

func NewHttpServer(application app.Application) HttpServer {
	return HttpServer{
		app: application,
	}
}

func (h HttpServer) RegisterUser(w http.ResponseWriter, r *http.Request) {
	request := &RegisterUserRequest{}
	if err := render.Decode(r, request); err != nil {
		httperr.RespondWithSlugError(err, w, r)
		return
	}

	response, err := h.app.Http.RegisterUser.Handle(r.Context(), appHttp.RegisterUserRequest{
		Email:    request.Email,
		Password: request.Password,
		Name:     request.Name,
	})
	if err != nil {
		httperr.RespondWithSlugError(err, w, r)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-refresh_token",
		Value:    response.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(jwt.MaxAccessTTL),
	})

	render.Status(r, http.StatusOK)
	render.JSON(w, r, LoginUserResponse{
		AccessToken: response.AccessToken,
		Email:       request.Email,
		Name:        request.Name,
	})
}

func (h HttpServer) LoginUser(w http.ResponseWriter, r *http.Request) {
	request := &LoginUserRequest{}
	if err := render.Decode(r, request); err != nil {
		httperr.RespondWithSlugError(err, w, r)
		return
	}

	response, err := h.app.Http.LoginUser.Handle(r.Context(), appHttp.LoginUserRequest{
		Email:    request.Email,
		Password: request.Password,
	})
	if err != nil {
		httperr.RespondWithSlugError(err, w, r)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-refresh_token",
		Value:    response.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(jwt.MaxAccessTTL),
	})

	render.Status(r, http.StatusOK)
	render.JSON(w, r, LoginUserResponse{
		AccessToken: response.AccessToken,
		Email:       request.Email,
		Name:        response.Name,
	})
}
