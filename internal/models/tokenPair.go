package models

type TokenPair struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}
