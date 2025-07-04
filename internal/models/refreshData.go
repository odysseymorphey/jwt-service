package models

import "time"

type RefreshData struct {
	UserID    string
	UserAgent string
	IP        string
	Hash      string
	Revoked   bool
	JTI       string
	IssuedAt  time.Time
}
