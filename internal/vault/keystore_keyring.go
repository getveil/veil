package vault

import (
	"encoding/hex"
	"fmt"

	"github.com/zalando/go-keyring"
)

const keyringService = "veil"

// KeyringKeystore stores master keys in the OS keychain (macOS Keychain,
// Linux Secret Service) via go-keyring.
type KeyringKeystore struct{}

// NewKeyringKeystore returns a KeyringKeystore that delegates to the OS
// credential store.
func NewKeyringKeystore() *KeyringKeystore {
	return &KeyringKeystore{}
}

func (k *KeyringKeystore) Get(projectID string) ([32]byte, error) {
	account := KeystoreAccount(projectID)
	val, err := keyring.Get(keyringService, account)
	if err != nil {
		return [32]byte{}, fmt.Errorf("keyring: get %q: %w", account, err)
	}

	b, err := hex.DecodeString(val)
	if err != nil {
		return [32]byte{}, fmt.Errorf("keyring: decode key for %q: %w", account, err)
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("keyring: key for %q has length %d, want 32", account, len(b))
	}

	var key [32]byte
	copy(key[:], b)
	return key, nil
}

func (k *KeyringKeystore) Set(projectID string, key [32]byte) error {
	account := KeystoreAccount(projectID)
	encoded := hex.EncodeToString(key[:])
	if err := keyring.Set(keyringService, account, encoded); err != nil {
		return fmt.Errorf("keyring: set %q: %w", account, err)
	}
	return nil
}

func (k *KeyringKeystore) Delete(projectID string) error {
	account := KeystoreAccount(projectID)
	err := keyring.Delete(keyringService, account)
	if err != nil && err != keyring.ErrNotFound {
		return fmt.Errorf("keyring: delete %q: %w", account, err)
	}
	// Not-found is not an error (idempotent delete).
	return nil
}
