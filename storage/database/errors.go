package database

import "errors"

var (
	// ErrForbidden means the principal lacks the role the operation needs.
	ErrForbidden = errors.New("forbidden")
	// ErrStaleEpoch means a grant was sealed to an older key epoch than the node's.
	ErrStaleEpoch = errors.New("stale epoch")
	// ErrUnknownPrincipal means the grantee does not exist or is revoked.
	ErrUnknownPrincipal = errors.New("unknown principal")
	// ErrCursorPurged means the cursor is older than the owner's purge horizon.
	ErrCursorPurged = errors.New("cursor purged")
	// ErrInvalidInput marks a request the server rejects before touching data.
	ErrInvalidInput = errors.New("invalid input")
)

// PurgedError carries the horizon a stale cursor fell behind.
type PurgedError struct {
	Horizon int64
}

func (err *PurgedError) Error() string { return ErrCursorPurged.Error() }
func (err *PurgedError) Unwrap() error { return ErrCursorPurged }
