package middleware

import (
	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	errors2 "jwt-service/internal/errors"
	"jwt-service/internal/repository"
	"os"
)

var (
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
)

func AuthMiddleware(db repository.JWTRepository) fiber.Handler {
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
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			return errors2.ErrInvalidToken
		}
		claims := token.Claims.(jwt.MapClaims)
		jti := claims["jti"].(string)

		exist, err := db.IsJWTBlacklisted(jti)
		if err != nil || !exist {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "token revoked",
			})
		}

		c.Locals("user", claims["sub"].(string))

		return c.Next()
	}
}
