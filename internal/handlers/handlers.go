package handlers

import (
	"context"
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

// GenerateTokenPair
// @Summary     Generate access & refresh tokens
// @Description Issues a new pair of tokens for the given user GUID
// @Tags        Auth
// @Accept      json
// @Produce     json
// @Param       user_id query string true "User GUID"
// @Success     200 {object} models.TokenPair
// @Failure     400 {object} models.ErrorResponse
// @Failure     500 {object} models.ErrorResponse
// @Router      /tokens/generate [post]
func GenerateTokenPair(service jwt_generator.JWTGenerator) fiber.Handler {
	return func(c fiber.Ctx) error {
		log.Infof("Auth: %v", c.Get("Authorization"))
		log.Infof("userID: %v", c.Query("user_id"))

		userID := c.Query("user_id")
		if userID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Empty user id",
			})
		}
		userAgent := c.Get("User-Agent")
		userInfo := &models.UserInfo{
			ID:    userID,
			Agent: userAgent,
			IP:    c.IP(),
		}

		tokenPair, err := service.GenerateTokenPair(userInfo)
		if err != nil {
			log.Errorf("Failed to generate token pair: userID: %v, userAgent: %v, error: %v",
				userID, userAgent, err)

			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": errors2.ErrInternalServerError.Error(),
			})
		}

		return c.JSON(tokenPair)
	}
}

// RefreshTokenPair
// @Summary     Refresh access & refresh tokens
// @Description Rotates tokens using the provided old pair
// @Tags        Auth
// @Accept      json
// @Produce     json
// @Param       request body models.TokenPair true "Old token pair"
// @Success     200 {object} models.TokenPair
// @Failure     400 {object} models.ErrorResponse
// @Failure     500 {object} models.ErrorResponse
// @Router      /tokens/refresh [post]
func RefreshTokenPair(service jwt_generator.JWTGenerator) fiber.Handler {
	return func(c fiber.Ctx) error {
		oldTokenPair := models.TokenPair{}
		if err := c.Bind().JSON(&oldTokenPair); err != nil {
			log.Errorf("Failed to read request body: %v", err)

			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": errors2.ErrInvalidPayload.Error(),
			})
		}

		userInfo := models.UserInfo{
			Agent: c.Get("User-Agent"),
			IP:    c.IP(),
		}

		newTokenPair, err := service.RefreshTokenPair(c.Context(), &oldTokenPair, &userInfo)
		if err != nil {
			log.Errorf("Failed to refresh token pair: %v", err)

			switch {
			case errors.Is(err, errors2.ErrInternalServerError):
				return c.Status(fiber.StatusInternalServerError).JSON(
					fiber.Map{
						"error": errors2.ErrInternalServerError.Error(),
					})
			default:
				return c.Status(fiber.StatusBadRequest).JSON(
					fiber.Map{
						"error": err.Error(),
					})

			}
		}

		return c.JSON(newTokenPair)
	}
}

// Whoami
// @Summary     Get current user GUID
// @Description Returns the user_id extracted from a valid Bearer token
// @Tags        Whoami
// @Produce     json
// @Security    BearerAuth
// @Success     200 {object} models.UserResponse
// @Failure     401 {object} models.ErrorResponse
// @Router      /whoami [get]
func Whoami(c fiber.Ctx) error {
	user := c.Locals("user").(string)
	return c.JSON(fiber.Map{
		"user_id": user,
	})
}

// Logout
// @Summary     Logout user and revoke tokens
// @Description Adds the current access token to blacklist and revokes all refresh tokens
// @Tags        Logout
// @Security    BearerAuth
// @Produce     json
// @Success     204
// @Failure     500 {object} models.ErrorResponse
// @Router      /logout [post]
func Logout(repo repository.JWTRepository) fiber.Handler {
	return func(c fiber.Ctx) error {
		auth := c.Get("Authorization")
		tokenStr := auth[len("Bearer "):]
		token, _ := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		claims := token.Claims.(jwt.MapClaims)
		jti := claims["jti"].(string)
		userID := claims["sub"].(string)

		tx, err := repo.BeginTx()
		if err != nil {
			log.Errorf("failed to start tx")
			return err
		}
		defer tx.Rollback(context.Background())

		err = repo.BlacklistJWTTx(tx, jti)
		if err != nil {
			log.Errorf("Failed to add JWT at blacklist: %v", err)

			return c.Status(fiber.StatusInternalServerError).JSON(
				fiber.Map{
					"error": errors2.ErrInternalServerError.Error(),
				})
		}

		err = repo.RevokeAllRefreshTx(tx, userID)
		if err != nil {
			log.Errorf("Failed to revoke all refreshs: %v", err)

			return c.Status(fiber.StatusInternalServerError).JSON(
				fiber.Map{
					"error": errors2.ErrInternalServerError.Error(),
				})
		}

		if err = tx.Commit(context.Background()); err != nil {
			log.Errorf("Tx commit failed: %v", err)

			return err
		}

		return c.SendStatus(fiber.StatusNoContent)
	}
}
