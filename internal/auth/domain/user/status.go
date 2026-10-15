package user

import "errors"

var (
	ErrUserAlreadyBlocked = errors.New("user is already blocked")
	ErrUserAlreadyActive  = errors.New("user is already active")
	ErrUserIsBlocked      = errors.New("cannot perform action: user is blocked")
)

type Status string

const (
	StatusPending Status = "pending"
	StatusActive  Status = "active"
	StatusBlocked Status = "blocked"
)

func (s Status) String() string {
	switch s {
	case StatusActive:
		return "active"
	case StatusPending:
		return "pending"
	case StatusBlocked:
		return "blocked"
	default:
		return "UNKNOWN"
	}
}
