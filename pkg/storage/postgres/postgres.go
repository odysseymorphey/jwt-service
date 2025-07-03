package postgres

import (
	"database/sql"
	_ "github.com/lib/pq"
	"jwt-service/internal/models"
)

type Postgres struct {
	db sql.DB
}

func New() (*Postgres, error) {
	return nil, nil
}

func (p *Postgres) Insert(info *models.UserInfo, hash, jti string) error {
	return nil
}

func (p *Postgres) GetRefreshData(jti string) (*models.RefreshData, error) {

	return nil, nil
}

func (p *Postgres) SetRevokedTrue(jti string) {

}

func (p *Postgres) Update() error {
	return nil
}
