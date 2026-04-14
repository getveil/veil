//go:build testkeystore

package testutil

import "github.com/8enji/veil/internal/vault"

// NewMemKeystore returns a fresh in-memory keystore suitable for tests.
// Compiled only when the testkeystore build tag is set.
func NewMemKeystore() *vault.MemKeystore {
	return vault.NewMemKeystore()
}
