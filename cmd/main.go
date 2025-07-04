package main

import (
	"fmt"
	"github.com/gofiber/fiber/v3"
	"jwt-service/internal/router"
	jwt_generator "jwt-service/internal/services/jwt-generator"
	"jwt-service/pkg/storage/postgres"
	"log"
	"os"
)

func main() {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_PORT"),
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_DB"))

	db, err := postgres.New(connStr)
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	service := jwt_generator.New(db)
	app := fiber.New()
	router.RegisterRoutes(app, service, db)

	if err = app.Listen(":8081"); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
