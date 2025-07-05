package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"jwt-service/internal/models"
)

type Postgres struct {
	pool *pgxpool.Pool
}

func New(connStr string) (*Postgres, error) {
	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		return nil, err
	}

	err = pool.Ping(context.Background())
	if err != nil {
		return nil, err
	}

	return &Postgres{
		pool: pool,
	}, nil
}

func (p *Postgres) BeginTx() (pgx.Tx, error) {
	return p.pool.Begin(context.Background())
}

func (p *Postgres) Close() {
	p.pool.Close()
}

func (p *Postgres) GetRefreshData(jti string) (*models.RefreshData, error) {
	const query = `SELECT jti,user_id,hash,user_agent,ip,issued_at,revoked
         FROM refresh_tokens WHERE jti=$1`

	var d models.RefreshData
	err := p.pool.QueryRow(context.Background(), query, jti).
		Scan(&d.JTI, &d.UserID, &d.Hash, &d.UserAgent, &d.IP, &d.IssuedAt, &d.Revoked)

	return &d, err
}

func (p *Postgres) RevokeRefresh(jti string) error {
	const query = `UPDATE refresh_tokens SET revoked=true WHERE jti=$1`

	_, err := p.pool.Exec(context.Background(), query, jti)

	return err
}

func (p *Postgres) IsJWTBlacklisted(jti string) (bool, error) {
	const query = `SELECT EXISTS(SELECT 1 FROM jwt_blacklist WHERE jti=$1)`

	var exists bool
	err := p.pool.QueryRow(context.Background(), query, jti).
		Scan(&exists)

	return exists, err
}

func (p *Postgres) SaveRefreshTx(tx pgx.Tx, data models.RefreshData) error {
	const query = `INSERT INTO refresh_tokens
         (jti,user_id,hash,user_agent,ip,issued_at,revoked)
         VALUES ($1,$2,$3,$4,$5,$6,false)`

	_, err := tx.Exec(context.Background(), query,
		data.JTI, data.UserID, data.Hash, data.UserAgent, data.IP, data.IssuedAt)
	return err
}

func (p *Postgres) RevokeRefreshTx(tx pgx.Tx, jti string) error {
	const query = `UPDATE refresh_tokens SET revoked=true WHERE jti=$1`

	_, err := tx.Exec(context.Background(), query, jti)
	return err
}

func (p *Postgres) RevokeAllRefreshTx(tx pgx.Tx, userID string) error {
	const query = `UPDATE refresh_tokens SET revoked=true WHERE user_id=$1`

	_, err := tx.Exec(context.Background(), query, userID)
	return err
}

func (p *Postgres) BlacklistJWTTx(tx pgx.Tx, jti string) error {
	const query = `INSERT INTO jwt_blacklist (jti) VALUES ($1) ON CONFLICT DO NOTHING`

	_, err := tx.Exec(context.Background(), query, jti)
	return err
}
