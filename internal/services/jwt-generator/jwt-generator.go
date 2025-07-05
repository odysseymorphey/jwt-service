package jwt_generator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v3/log"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	errors2 "jwt-service/internal/errors"
	"jwt-service/internal/models"
	"jwt-service/internal/repository"
	"net/http"
	"os"
	"time"
)

var (
	jwtSecret  = []byte(os.Getenv("JWT_SECRET"))
	webhookUrl = os.Getenv("WEBHOOK_URL")
)

type JWTGenerator interface {
	GenerateTokenPair(*models.UserInfo) (*models.TokenPair, error)
	RefreshTokenPair(ctx context.Context,
		tokenPair *models.TokenPair, info *models.UserInfo) (*models.TokenPair, error)
}

type JWTGeneratorImpl struct {
	repo repository.JWTRepository
}

func New(repo repository.JWTRepository) *JWTGeneratorImpl {
	return &JWTGeneratorImpl{
		repo: repo,
	}
}

func (j *JWTGeneratorImpl) GenerateTokenPair(userInfo *models.UserInfo) (*models.TokenPair, error) {
	token := jwt.New(jwt.SigningMethodHS512)

	jti := fmt.Sprintf("%d", time.Now().UnixNano())
	token.Claims = jwt.MapClaims{
		"sub": userInfo.ID,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"jti": jti,
	}

	accessToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return nil, err
	}

	raw := fmt.Sprintf("%s:%d", userInfo.ID, time.Now().UnixNano())
	refreshToken := base64.StdEncoding.EncodeToString([]byte(raw))
	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	err = j.repo.SaveRefresh(models.RefreshData{
		UserID:    userInfo.ID,
		Hash:      string(hash),
		UserAgent: userInfo.Agent,
		IP:        userInfo.IP,
		IssuedAt:  time.Now(),
	})
	if err != nil {
		return nil, err
	}

	return &models.TokenPair{
		Access:  accessToken,
		Refresh: refreshToken,
	}, nil
}

func (j *JWTGeneratorImpl) RefreshTokenPair(ctx context.Context, tokenPair *models.TokenPair, userInfo *models.UserInfo) (*models.TokenPair, error) {
	access, err := jwt.Parse(tokenPair.Access, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS512 {
			return nil, errors2.ErrUnexpectedHashMethod
		}

		return jwtSecret, nil
	})
	if err != nil || !access.Valid {
		return nil, errors2.ErrInvalidAccessToken
	}
	claims := access.Claims.(jwt.MapClaims)
	jti := claims["jti"].(string)

	refreshData, err := j.repo.GetRefreshData(jti)
	if err != nil || refreshData.Revoked {
		return nil, errors2.ErrRefreshNotFoundOrRevoked
	}

	if userInfo.Agent != refreshData.UserAgent {
		if err := j.repo.RevokeRefresh(jti); err != nil {
			log.Errorf("Failed to revoke refresh: %v", err)
		}

		return nil, errors2.ErrUserAgentChanged
	}

	err = bcrypt.CompareHashAndPassword([]byte(refreshData.Hash), []byte(tokenPair.Refresh))
	if err != nil {
		return nil, errors2.ErrInvalidRefreshToken
	}

	if userInfo.IP != refreshData.IP {
		go j.notifyWebhook(refreshData.UserID, userInfo.IP)
	}

	err = j.repo.RevokeRefresh(jti)
	if err != nil {
		log.Errorf("Failed to revoke refresh: %v", err)

		return nil, errors2.ErrInternalServerError
	}

	newTokenPair, err := j.GenerateTokenPair(userInfo)
	if err != nil {
		return nil, errors2.ErrInternalServerError
	}

	return newTokenPair, nil
}

func (j *JWTGeneratorImpl) notifyWebhook(userID string, userIP string) {
	payload, _ := json.Marshal(map[string]string{
		"user_id": userID,
		"ip":      userIP,
	})

	resp, err := http.Post(webhookUrl, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Errorf("Failet to notify webhook: %v", err)

		return
	}

	log.Infof("Notify success. Status: %v, Code: %v", resp.Status, resp.StatusCode)
}
