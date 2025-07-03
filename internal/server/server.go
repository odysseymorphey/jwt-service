package server

import (
	"github.com/gofiber/fiber/v3"
	"jwt-service/internal/router"
	jwt_generator "jwt-service/internal/services/jwt-generator"
)

type Server struct {
	app *fiber.App
}

func New(service jwt_generator.JWTGenerator) *Server {
	app := &fiber.App{}

	router.RegisterRoutes(app, service)
	return &Server{
		app: app,
	}
}

func Run()
