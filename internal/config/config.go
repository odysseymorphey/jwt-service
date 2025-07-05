package config

import (
	"github.com/gofiber/fiber/v3/log"
	"github.com/joho/godotenv"
	"os"
)

type Config struct {
	ServerPort string
	JWTSecret  string
	WebhookURL string

	PgHost string
	PgPort string
	PgUser string
	PgPass string
	PgDB   string
}

func Load() *Config {
	if err := godotenv.Load(".env"); err != nil {
		log.Info("config: .env file not found, reading environment")
	}

	c := &Config{
		ServerPort: getEnv("SERVER_PORT", "8080"),
		JWTSecret:  mustGetEnv("JWT_SECRET", ""),
		WebhookURL: getEnv("WEBHOOK_URL", ""),
		PgHost:     mustGetEnv("POSTGRES_HOST", "localhost"),
		PgPort:     getEnv("POSTGRES_PORT", "5432"),
		PgUser:     getEnv("POSTGRES_USER", "postgres"),
		PgPass:     getEnv("POSTGRES_PASSWORD", "mysecretpassword"),
		PgDB:       getEnv("POSTGRES_DB", "postgres"),
	}

	if c.JWTSecret == "" {
		log.Fatal("config: JWT_SECRET must be set")
	}

	return c
}

func getEnv(key, defaultVal string) string {
	if v, ok := os.LookupEnv(key); !ok {
		return v
	}

	return defaultVal
}

func mustGetEnv(key, defaultVal string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	if defaultVal != "" {
		return defaultVal
	}
	log.Fatalf("config: required environment variable %s is not set", key)

	return ""
}
