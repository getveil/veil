package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	magicLen   = 4
	versionLen = 1
	nonceLen   = 12
	headerLen  = magicLen + versionLen + nonceLen // 17
)

var (
	magic = [4]byte{'V', 'E', 'I', 'L'}
	aad   = []byte("veil-vault-v1")
)

// Seal encrypts plaintext with AES-256-GCM under the given key and returns
// the binary vault blob (magic + version + nonce + ciphertext+tag).
func Seal(key [32]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("vault: aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: gcm init: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: nonce generation: %w", err)
	}

	ct := gcm.Seal(nil, nonce, plaintext, aad)

	blob := make([]byte, 0, headerLen+len(ct))
	blob = append(blob, magic[:]...)
	blob = append(blob, 0x01) // version
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	return blob, nil
}

// Unseal decrypts a vault blob produced by Seal. It validates the magic bytes
// and version before attempting decryption. On any integrity failure it
// returns a descriptive error.
func Unseal(key [32]byte, data []byte) ([]byte, error) {
	if len(data) < headerLen {
		return nil, errors.New("vault: data too short to be a valid vault")
	}
	if data[0] != magic[0] || data[1] != magic[1] || data[2] != magic[2] || data[3] != magic[3] {
		return nil, errors.New("vault: invalid magic bytes (not a vault file)")
	}
	if data[4] != 0x01 {
		return nil, fmt.Errorf("vault: unsupported version %d", data[4])
	}

	nonce := data[magicLen+versionLen : headerLen]
	ct := data[headerLen:]

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("vault: aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: gcm init: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("vault: integrity check failed (corrupted or wrong key)")
	}
	return plaintext, nil
}
