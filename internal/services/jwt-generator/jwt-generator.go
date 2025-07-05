package jwt_generator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v3/log"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"jwt-service/internal/config"
	errors2 "jwt-service/internal/errors"
	"jwt-service/internal/models"
	"jwt-service/internal/repository"
	"net/http"
	"time"
)

type JWTGenerator interface {
	GenerateTokenPair(*models.UserInfo) (*models.TokenPair, error)
	RefreshTokenPair(ctx context.Context,
		tokenPair *models.TokenPair, info *models.UserInfo) (*models.TokenPair, error)
}

type JWTGeneratorImpl struct {
	repo       repository.JWTRepository
	jwtSecret  []byte
	webhookUrl string
}

func New(repo repository.JWTRepository, cfg *config.Config) *JWTGeneratorImpl {
	return &JWTGeneratorImpl{
		repo:       repo,
		jwtSecret:  []byte(cfg.JWTSecret),
		webhookUrl: cfg.WebhookURL,
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

	accessToken, err := token.SignedString(j.jwtSecret)
	if err != nil {
		log.Errorf("failed to get signed string: %v", err)
		return nil, err
	}

	raw := fmt.Sprintf("%s:%d", userInfo.ID, time.Now().UnixNano())
	refreshToken := base64.StdEncoding.EncodeToString([]byte(raw))

	sha := sha256.Sum256([]byte(refreshToken))
	short := hex.EncodeToString(sha[:])

	hash, err := bcrypt.GenerateFromPassword([]byte(short), bcrypt.DefaultCost)
	if err != nil {
		log.Errorf("failed to generate bcrytp: %v", err)
		return nil, fmt.Errorf("failed to generate bcrypt: %v", err)
	}

	tx, err := j.repo.BeginTx()
	if err != nil {
		log.Errorf("failed to start tx")
		return nil, err
	}
	defer tx.Rollback(context.Background())

	refreshData := models.RefreshData{
		JTI:       jti,
		UserID:    userInfo.ID,
		Hash:      string(hash),
		UserAgent: userInfo.Agent,
		IP:        userInfo.IP,
		IssuedAt:  time.Now(),
	}

	log.Infof("Refresh data: %v", refreshData)

	err = j.repo.SaveRefreshTx(tx, refreshData)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(context.Background()); err != nil {
		log.Errorf("Tx commit failed: %v", err)

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

		return j.jwtSecret, nil
	})
	if err != nil || !access.Valid {
		return nil, errors2.ErrInvalidAccessToken
	}
	claims := access.Claims.(jwt.MapClaims)
	jti := claims["jti"].(string)
	userInfo.ID = claims["sub"].(string)

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

	sha := sha256.Sum256([]byte(tokenPair.Refresh))
	hashed := hex.EncodeToString(sha[:])
	err = bcrypt.CompareHashAndPassword([]byte(refreshData.Hash), []byte(hashed))
	if err != nil {
		return nil, errors2.ErrInvalidRefreshToken
	}

	if userInfo.IP != refreshData.IP {
		go j.notifyWebhook(refreshData.UserID, userInfo.IP)
	}

	tx, err := j.repo.BeginTx()
	if err != nil {
		log.Errorf("failed to start tx")
		return nil, err
	}
	defer tx.Rollback(context.Background())

	err = j.repo.RevokeRefreshTx(tx, jti)
	if err != nil {
		log.Errorf("Failed to revoke refresh: %v", err)

		return nil, errors2.ErrInternalServerError
	}

	newTokenPair, err := j.GenerateTokenPair(userInfo)
	if err != nil {
		log.Errorf("Failed to generate new token pair: %v", err)

		return nil, errors2.ErrInternalServerError
	}

	if err = tx.Commit(context.Background()); err != nil {
		log.Errorf("Tx commit failed: %v", err)

		return nil, err
	}

	return newTokenPair, nil
}

func (j *JWTGeneratorImpl) notifyWebhook(userID string, userIP string) {
	payload, _ := json.Marshal(map[string]string{
		"user_id": userID,
		"ip":      userIP,
	})

	resp, err := http.Post(j.webhookUrl, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Errorf("Failet to notify webhook: %v", err)

		return
	}

	log.Infof("Notify success. Status: %v, Code: %v", resp.Status, resp.StatusCode)
}
