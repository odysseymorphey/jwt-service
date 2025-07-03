package router

import (
	"github.com/gofiber/fiber/v3"
	"jwt-service/internal/handlers"
	jwt_generator "jwt-service/internal/services/jwt-generator"
)

func RegisterRoutes(app *fiber.App, service jwt_generator.JWTGenerator) {
	api := app.Group("/api/v1")

	{
		tokenPair := api.Group("/tokens/")

		tokenPair.Post("/generate", handlers.GenerateTokenPair(service))
		tokenPair.Post("/refresh", handlers.RefreshTokenPair(service))
	}
}
