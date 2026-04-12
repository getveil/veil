package cli

import (
	"os"
	"path/filepath"
	"sync"

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

var (
	testKeystoreMu   sync.Mutex
	testKeystoreInst *vault.MemKeystore
)

// testKeystore returns a process-wide singleton MemKeystore so that init and
// subsequent commands share state within the same test process.
func testKeystore() *vault.MemKeystore {
	testKeystoreMu.Lock()
	defer testKeystoreMu.Unlock()
	if testKeystoreInst == nil {
		testKeystoreInst = vault.NewMemKeystore()
	}
	return testKeystoreInst
}

// buildKeystore returns the appropriate Keystore for the current environment.
func buildKeystore() (vault.Keystore, error) {
	if os.Getenv("VEIL_TEST_KEYSTORE") == "mem" {
		return testKeystore(), nil
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
