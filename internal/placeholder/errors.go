package placeholder

import "errors"

var (
	// ErrProviderNotFound indicates a lookup by provider name failed.
	ErrProviderNotFound = errors.New("placeholder: provider not found")

	// ErrCollisionUnresolvable indicates the generator exhausted its retry
	// budget without finding a non-colliding candidate.
	ErrCollisionUnresolvable = errors.New("placeholder: could not resolve collision after retries")
)
