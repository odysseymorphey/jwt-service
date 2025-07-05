package router

import (
	"github.com/gofiber/fiber/v3"
	"jwt-service/internal/config"
	"jwt-service/internal/handlers"
	"jwt-service/internal/middleware"
	"jwt-service/internal/repository"
	"jwt-service/internal/services/jwt-generator"
)

func RegisterRoutes(app *fiber.App, service jwt_generator.JWTGenerator, repo repository.JWTRepository, cfg *config.Config) {
	api := app.Group("/api/v1")

	{
		tokenPair := api.Group("/tokens")

		tokenPair.Post("/generate", handlers.GenerateTokenPair(service))
		tokenPair.Post("/refresh", handlers.RefreshTokenPair(service))
	}

	{
		auth := api.Group("/", middleware.AuthMiddleware(repo, cfg))

		auth.Get("/whoami", handlers.Whoami)
		auth.Post("/logout", handlers.Logout(repo))
	}
}
