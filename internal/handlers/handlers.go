package handlers

import (
	"github.com/gofiber/fiber/v3"
	errors2 "jwt-service/internal/errors"
	"jwt-service/internal/models"
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
			return c.Status(fiber.StatusInternalServerError).SendString(errors2.ErrInternalServerError.Error())
		}

		return c.JSON(tokenPair)
	}
}

func RefreshTokenPair(service jwt_generator.JWTGenerator) fiber.Handler {
	return func(c fiber.Ctx) error {
		oldTokenPair := models.TokenPair{}
		if err := c.Bind().JSON(oldTokenPair); err != nil {
			return c.Status(fiber.StatusBadRequest).SendString(errors2.ErrInvalidPayload.Error())
		}

		userInfo := models.UserInfo{
			Agent: c.Get("User-Agent"),
			IP:    c.IP(),
		}

		newTokenPair, err := service.RefreshTokenPair(c.Context(), &oldTokenPair, &userInfo)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).SendString(err.Error())
		}

		return c.JSON(newTokenPair)
	}
}
