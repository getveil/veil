package cli

import (
	"path/filepath"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/vault"
)

// resolveRoot determines the project root directory from the --path flag
// or by searching upward from the current directory.
func resolveRoot() (string, error) {
	if flagPath != "" {
		return filepath.Abs(flagPath)
	}
	return config.FindProjectRoot(".")
}

// buildKeystore returns the appropriate Keystore for the current environment.
func buildKeystore() (vault.Keystore, error) {
	if ks, ok := maybeTestKeystore(); ok {
		return ks, nil
	}
	fallbackPath, err := config.KeystoreFallbackFile()
	if err != nil {
		return nil, err
	}
	return vault.AutoKeystore(fallbackPath), nil
}

// openVault opens the vault at the given project root, using the appropriate
// keystore (mem for tests, auto for production).
func openVault(root string) (*vault.Vault, error) {
	ks, err := buildKeystore()
	if err != nil {
		return nil, err
	}
	return vault.Open(root, ks)
}

// MaybeTestKeystoreForTest is exported for tests that need to assert the
// build-tag behavior of maybeTestKeystore.
var MaybeTestKeystoreForTest = maybeTestKeystore
