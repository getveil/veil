//go:build testkeystore

package cli

import (
	"os"
	"sync"

	"github.com/getveil/veil/internal/envkeys"
	"github.com/getveil/veil/internal/vault"
)

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

// maybeTestKeystore returns (mem-keystore, true) when envkeys.TestKeystoreToggle
// is set to "mem" and the binary was built with -tags testkeystore. The
// !testkeystore stub (compiled into production builds) always returns (nil,
// false), so the env-var branch does not exist in production binaries.
func maybeTestKeystore() (vault.Keystore, bool) {
	if os.Getenv(envkeys.TestKeystoreToggle) == "mem" {
		return testKeystore(), true
	}
	return nil, false
}
