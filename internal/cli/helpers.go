package cli

import (
	"os"
	"path/filepath"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/vault"
	"github.com/spf13/cobra"
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

// requireInitializedProject resolves the project root and verifies the
// project has been initialized. On success it returns the root. On failure
// it returns a cliError/cliErrorWith that has already been printed — the
// caller just propagates it. Use this in commands that operate on project
// state but don't need the vault opened (e.g. `veil skip`, `veil run`).
func requireInitializedProject(_ *cobra.Command) (string, error) {
	root, err := resolveRoot()
	if err != nil {
		return "", cliError(err.Error(), "")
	}
	stateDir := config.ProjectStateDir(root)
	if info, statErr := os.Stat(stateDir); statErr != nil || !info.IsDir() {
		return "", cliErrorWith(ErrNotInitialized, "project not initialized", "Run veil init to get started")
	}
	return root, nil
}

// withVault resolves the project root, opens the vault, and invokes fn with
// the resolved root and opened vault. Any error from the prologue is
// printed and returned as a cliError/wrapErr (exit-code classified). fn's
// error is returned unchanged so callers can decide whether to print.
// Use this in commands that need the vault (add, list, remove, status, log).
func withVault(cmd *cobra.Command, fn func(root string, v *vault.Vault) error) error {
	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}
	v, err := openVault(root)
	if err != nil {
		return wrapErr("opening vault", err)
	}
	return fn(root, v)
}

// MaybeTestKeystoreForTest is exported for tests that need to assert the
// build-tag behavior of maybeTestKeystore.
var MaybeTestKeystoreForTest = maybeTestKeystore
