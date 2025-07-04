package handlers

import (
	""
	"errors"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"github.com/golang-jwt/jwt/v5"
	errors2 "jwt-service/internal/errors"
	"jwt-service/internal/models"
	"jwt-service/internal/repository"
	jwt_generator "jwt-service/internal/services/jwt-generator"
	"os"
)

var (
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
)

func GenerateTokenPair(service jwt_generator.JWTGenerator) fiber.Handler {
	return func(c fiber.Ctx) error {
		userID := c.Query("user_id")
		userAgent := c.Get("User-Agent")
		userInfo := &models.UserInfo{
			ID:    userID,
			Agent: userAgent,
		}

		tokenPair, err := service.GenerateTokenPair(userInfo)
		if err != nil {
			log.Errorf("Failed to generate token pair: userID: %v, userAgent: %v, error: %v",
				userID, userAgent, err)

			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": errors2.ErrInternalServerError,
			})
		}

		return c.JSON(tokenPair)
	}
}

func RefreshTokenPair(service jwt_generator.JWTGenerator) fiber.Handler {
	return func(c fiber.Ctx) error {
		oldTokenPair := models.TokenPair{}
		if err := c.Bind().JSON(oldTokenPair); err != nil {
			log.Errorf("Failed to read request body: %v", err)

			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": errors2.ErrInvalidPayload,
			})
		}

		userInfo := models.UserInfo{
			Agent: c.Get("User-Agent"),
			IP:    c.IP(),
		}

		newTokenPair, err := service.RefreshTokenPair(c.Context(), &oldTokenPair, &userInfo)

		switch {
		case errors.Is(err, errors2.ErrInvalidRefreshToken):
			return c.Status(fiber.StatusBadRequest).JSON(
				fiber.Map{
					"error": errors2.ErrInvalidRefreshToken,
				})
		}
		if err != nil {
			log.Errorf("Failed to refresh token pair: %v", err)

			return c.Status(fiber.StatusBadRequest).JSON(
				fiber.Map{
					"error": errors2.ErrInternalServerError,
				})
		}

		return c.JSON(newTokenPair)
	}
}

func Whoami(c fiber.Ctx) error {
	user := c.Locals("user").(string)
	return c.JSON(fiber.Map{
		"user_id": user,
	})
}

func Logout(repo repository.JWTRepository) fiber.Handler {
	return func(c fiber.Ctx) error {
		auth := c.Get("Authorization")
		tokenStr := auth[len("Bearer "):]
		token, _ := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		claims := token.Claims.(jwt.MapClaims)
		jti := claims["jti"].(string)

		err := repo.BlacklistJWT(jti)
		if err != nil {
			log.Errorf("Failed to add JWT at blacklist: %v", err)

			return c.Status(fiber.StatusInternalServerError).JSON(
				fiber.Map{
					"error": errors2.ErrInternalServerError,
				})
		}

		err = repo.RevokeAllRefresh(jti)
		if err != nil {
			log.Errorf("Failed to revoke all refreshs: %v", err)

			return c.Status(fiber.StatusInternalServerError).JSON(
				fiber.Map{
					"error": errors2.ErrInternalServerError,
				})
		}

		return c.SendStatus(fiber.StatusNoContent)
	}
}
