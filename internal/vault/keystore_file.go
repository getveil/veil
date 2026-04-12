package vault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
)

// FileKeystore stores master keys in an age-encrypted JSON file, protected by
// a passphrase sourced from the VEIL_PASSPHRASE environment variable.
type FileKeystore struct {
	path       string // e.g. ~/.local/state/veil/master.key.age
	workFactor int    // scrypt log2(N); 0 means use age default (~18)
}

// NewFileKeystore returns a FileKeystore that reads/writes the given path.
func NewFileKeystore(path string) *FileKeystore {
	return &FileKeystore{path: path}
}

// SetWorkFactor overrides the scrypt work factor (log2 N) for encryption.
// A low value (e.g. 1) makes tests fast; production callers should leave
// the default (0) which lets age choose a secure cost.
func (f *FileKeystore) SetWorkFactor(logN int) {
	f.workFactor = logN
}

// passphrase returns the encryption passphrase or an error if unset.
func passphrase() (string, error) {
	p := os.Getenv("VEIL_PASSPHRASE")
	if p == "" {
		return "", errors.New("file keystore: VEIL_PASSPHRASE is not set (required for age-encrypted key file)")
	}
	return p, nil
}

// loadMap decrypts and unmarshals the key map from disk. If the file does not
// exist it returns an empty map and nil error.
func (f *FileKeystore) loadMap() (map[string]string, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]string), nil
	}
	if err != nil {
		return nil, fmt.Errorf("file keystore: read %q: %w", f.path, err)
	}

	pass, err := passphrase()
	if err != nil {
		return nil, err
	}

	identity, err := age.NewScryptIdentity(pass)
	if err != nil {
		return nil, fmt.Errorf("file keystore: create identity: %w", err)
	}

	reader, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return nil, fmt.Errorf("file keystore: decrypt %q: %w", f.path, err)
	}

	plaintext, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("file keystore: read decrypted data: %w", err)
	}

	m := make(map[string]string)
	if err := json.Unmarshal(plaintext, &m); err != nil {
		return nil, fmt.Errorf("file keystore: unmarshal key map: %w", err)
	}
	return m, nil
}

// saveMap encrypts and atomically writes the key map to disk.
func (f *FileKeystore) saveMap(m map[string]string) error {
	pass, err := passphrase()
	if err != nil {
		return err
	}

	plaintext, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("file keystore: marshal key map: %w", err)
	}

	recipient, err := age.NewScryptRecipient(pass)
	if err != nil {
		return fmt.Errorf("file keystore: create recipient: %w", err)
	}
	if f.workFactor > 0 {
		recipient.SetWorkFactor(f.workFactor)
	}

	var buf bytes.Buffer
	writer, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return fmt.Errorf("file keystore: init encrypt: %w", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		return fmt.Errorf("file keystore: write plaintext: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("file keystore: finalize encrypt: %w", err)
	}

	// Ensure parent directory exists.
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("file keystore: create dir %q: %w", dir, err)
	}

	// Atomic write: temp file + rename.
	tmp, err := os.CreateTemp(dir, "veil-keys-*.tmp")
	if err != nil {
		return fmt.Errorf("file keystore: create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("file keystore: write temp file: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("file keystore: chmod temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("file keystore: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("file keystore: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, f.path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("file keystore: atomic rename: %w", err)
	}
	return nil
}

func (f *FileKeystore) Get(projectID string) ([32]byte, error) {
	m, err := f.loadMap()
	if err != nil {
		return [32]byte{}, err
	}

	account := KeystoreAccount(projectID)
	encoded, ok := m[account]
	if !ok {
		return [32]byte{}, fmt.Errorf("file keystore: no key for project %q", projectID)
	}

	b, err := hex.DecodeString(encoded)
	if err != nil {
		return [32]byte{}, fmt.Errorf("file keystore: decode key for %q: %w", account, err)
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("file keystore: key for %q has length %d, want 32", account, len(b))
	}

	var key [32]byte
	copy(key[:], b)
	return key, nil
}

func (f *FileKeystore) Set(projectID string, key [32]byte) error {
	m, err := f.loadMap()
	if err != nil {
		return err
	}

	account := KeystoreAccount(projectID)
	m[account] = hex.EncodeToString(key[:])
	return f.saveMap(m)
}

func (f *FileKeystore) Delete(projectID string) error {
	m, err := f.loadMap()
	if err != nil {
		return err
	}

	account := KeystoreAccount(projectID)
	if _, ok := m[account]; !ok {
		// Idempotent: key not present is not an error.
		return nil
	}

	delete(m, account)
	return f.saveMap(m)
}
