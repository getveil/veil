package vault

import (
	"runtime"

	"github.com/getveil/veil/internal/ui"
)

// AutoKeystore returns the best available Keystore for the current platform.
//
// On macOS it always returns a KeyringKeystore (Keychain is always available).
// On Linux (and other platforms) it probes the keyring with a test
// Set+Delete. If Set fails, it falls back to a FileKeystore at fallbackPath.
// If Set succeeds but Delete fails, it stays on the keyring but emits a
// warning so operators can observe the stray probe key.
func AutoKeystore(fallbackPath string) Keystore {
	if runtime.GOOS == "darwin" {
		return NewKeyringKeystoreForTest()
	}

	kr := NewKeyringKeystoreForTest()
	if err := kr.Set("__veil_probe__", [32]byte{}); err != nil {
		return NewFileKeystore(fallbackPath)
	}
	if err := kr.Delete("__veil_probe__"); err != nil {
		ui.Warnf(ProbeWarnWriter,
			"keyring cleanup failed during probe: %v; continuing with system keyring",
			err)
	}
	return kr
}
