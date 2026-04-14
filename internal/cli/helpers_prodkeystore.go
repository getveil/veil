//go:build !testkeystore

package cli

import "github.com/8enji/veil/internal/vault"

// maybeTestKeystore is a no-op in production builds. The env-var branch does
// not exist in the binary.
func maybeTestKeystore() (vault.Keystore, bool) { return nil, false }
