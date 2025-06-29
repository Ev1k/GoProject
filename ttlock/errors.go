package ttlock

import "errors"

var (
	ErrUsernameExists    = errors.New("username already exists")
	ErrInvalidUsername   = errors.New("invalid username format")
	ErrInvalidPassword   = errors.New("invalid password format")
	ErrTTLockUnavailable = errors.New("ttlock service unavailable")
)

func IsTTLockError(err error) bool {
	return errors.Is(err, ErrUsernameExists) ||
		errors.Is(err, ErrInvalidUsername) ||
		errors.Is(err, ErrInvalidPassword) ||
		errors.Is(err, ErrTTLockUnavailable)
}
