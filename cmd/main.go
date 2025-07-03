package main

import (
	"github.com/gofiber/fiber/v3"
	"jwt-service/internal/router"
	jwt_generator "jwt-service/internal/services/jwt-generator"
	"jwt-service/pkg/storage/postgres"
	"log"
)

func main() {
	db, err := postgres.New()
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	service := jwt_generator.New(db)
	app := fiber.New()
	router.RegisterRoutes(app, service)

	if err = app.Listen(":8081"); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
