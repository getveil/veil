package vault

import "errors"

var (
	// ErrKeystoreUnavailable indicates the system keystore (keyring, file)
	// could not be reached.
	ErrKeystoreUnavailable = errors.New("keystore: unavailable")

	// ErrKeystoreWrite indicates a write or chmod on the keystore backing
	// store failed.
	ErrKeystoreWrite = errors.New("keystore: write failed")
)
