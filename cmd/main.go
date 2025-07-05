package main

import (
	"fmt"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"jwt-service/internal/config"
	"jwt-service/internal/router"
	jwt_generator "jwt-service/internal/services/jwt-generator"
	"jwt-service/pkg/storage/postgres"
	"os"
	"os/signal"
	"syscall"

	"github.com/dev-timaracov/swagger-fiber-v3"

	_ "jwt-service/docs"
)

// @title Auth Service API
// @version 1.0
// @description Authentication service with access/refresh tokens
// @host localhost:8181
// @BasePath /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	cfg := config.Load()

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.PgHost,
		cfg.PgPort,
		cfg.PgUser,
		cfg.PgPass,
		cfg.PgDB)

	db, err := postgres.New(connStr)
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	service := jwt_generator.New(db, cfg)
	app := fiber.New()
	router.RegisterRoutes(app, service, db, cfg)
	app.Get("/swagger/*", swagger.HandlerDefault)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err = app.Listen(":8181"); err != nil {
			log.Fatalf("failed to start server: %v", err)
		}
	}()

	<-sig
	log.Info("Shutting down server...")
	db.Close()

	log.Info("Server stopped gracefully")
}
