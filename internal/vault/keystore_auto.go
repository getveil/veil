package vault

import "runtime"

// AutoKeystore returns the best available Keystore for the current platform.
//
// On macOS, it always returns a KeyringKeystore (macOS always has Keychain).
// On Linux, it probes the keyring with a test write+delete; if the D-Bus
// Secret Service is unavailable, it falls back to a FileKeystore at
// fallbackPath.
func AutoKeystore(fallbackPath string) Keystore {
	if runtime.GOOS == "darwin" {
		return NewKeyringKeystore()
	}

	// On Linux (and other platforms), probe whether the keyring works.
	kr := NewKeyringKeystore()
	if err := kr.Set("__veil_probe__", [32]byte{}); err != nil {
		return NewFileKeystore(fallbackPath)
	}
	_ = kr.Delete("__veil_probe__")
	return kr
}
