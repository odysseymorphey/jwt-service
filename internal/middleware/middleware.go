package middleware

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"github.com/golang-jwt/jwt/v5"
	"jwt-service/internal/config"
	errors2 "jwt-service/internal/errors"
	"jwt-service/internal/repository"
)

func AuthMiddleware(repo repository.JWTRepository, cfg *config.Config) fiber.Handler {
	return func(c fiber.Ctx) error {
		auth := c.Get("Authorization")
		if auth == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": errors2.ErrMissingAuthToken,
			})
		}

		tokenStr := auth[len("Bearer "):]
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS512 {
				return nil, errors2.ErrUnexpectedHashMethod
			}
			return cfg.JWTSecret, nil
		})
		if err != nil || !token.Valid {
			return errors2.ErrInvalidToken
		}
		claims := token.Claims.(jwt.MapClaims)
		jti := claims["jti"].(string)

		exist, err := repo.IsJWTBlacklisted(jti)
		if err != nil || exist {
			log.Errorf("err: %v; exist: %v", err, exist)

			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "token revoked",
			})
		}

		c.Locals("user", claims["sub"].(string))

		return c.Next()
	}
}
