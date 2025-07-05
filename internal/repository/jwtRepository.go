package repository

import (
	"github.com/jackc/pgx/v5"
	"jwt-service/internal/models"
)

type JWTRepository interface {
	GetRefreshData(jti string) (*models.RefreshData, error)
	RevokeRefresh(jti string) error
	IsJWTBlacklisted(jti string) (bool, error)
	Close()

	BeginTx() (pgx.Tx, error)
	SaveRefreshTx(tx pgx.Tx, data models.RefreshData) error
	RevokeRefreshTx(tx pgx.Tx, jti string) error
	RevokeAllRefreshTx(tx pgx.Tx, userID string) error
	BlacklistJWTTx(tx pgx.Tx, jti string) error
}
