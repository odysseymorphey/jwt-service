package repository

import "jwt-service/internal/models"

type JWTRepository interface {
	Insert(info *models.UserInfo, hash, jti string) error
	GetRefreshData(jti string) (*models.RefreshData, error)
	SetRevokedTrue(jti string)
	Update() error
}
