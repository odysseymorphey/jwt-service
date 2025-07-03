package errors2

import "errors"

var (
	ErrInvalidAccessToken       = errors.New("invalid access token")
	ErrInvalidRefreshToken      = errors.New("invalid refresh token")
	ErrRefreshNotFoundOrRevoked = errors.New("refresh not found or revoked")

	ErrMissingToken     = errors.New("missing token")
	ErrInvalidToken     = errors.New("invalid token")
	ErrUserAgentChanged = errors.New("user-agent changed")

	ErrUnexpectedHashMethod = errors.New("unexpected hash method")
	ErrInvalidPayload       = errors.New("invalid payload")

	ErrInternalServerError = errors.New("internal server error")
)
