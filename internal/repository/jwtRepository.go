package repository

import "jwt-service/internal/models"

type JWTRepository interface {
	SaveRefresh(data models.RefreshData) error
	GetRefreshData(jti string) (*models.RefreshData, error)
	RevokeRefresh(jti string) error
	RevokeAllRefresh(userID string) error
	IsJWTBlacklisted(jti string) (bool, error)
	BlacklistJWT(jti string) error
	Close()
}
