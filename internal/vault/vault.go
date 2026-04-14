package vault

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/placeholder"
)

// vaultMeta is the on-disk JSON written to vault.meta.
type vaultMeta struct {
	ProjectID string `json:"project_id"`
	Version   int    `json:"version"`
}

// Vault is an in-memory representation of an opened vault.
type Vault struct {
	root        string
	projectID   string
	credentials []*Credential
	keystore    Keystore
}

// Open reads and decrypts an existing vault from disk.
func Open(root string, ks Keystore) (*Vault, error) {
	metaPath := config.VaultMetaFile(root)
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read meta file: %w", ErrOpen, err)
	}

	var meta vaultMeta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return nil, fmt.Errorf("%w: invalid meta file: %w", ErrOpen, err)
	}

	vaultPath := config.VaultFile(root)
	blob, err := os.ReadFile(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read vault file: %w", ErrOpen, err)
	}

	key, err := ks.Get(meta.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMasterKey, err)
	}

	plaintext, err := Unseal(key, blob)
	if err != nil {
		return nil, fmt.Errorf("%w: corrupt or truncated vault file (unseal failed): %w", ErrCorrupt, err)
	}

	var creds []*Credential
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, fmt.Errorf("%w: corrupt credential data: %w", ErrCorrupt, err)
	}

	return &Vault{
		root:        root,
		projectID:   meta.ProjectID,
		credentials: creds,
		keystore:    ks,
	}, nil
}

// Save encrypts and atomically writes the vault to disk.
func (v *Vault) Save() error {
	data, err := json.Marshal(v.credentials)
	if err != nil {
		return fmt.Errorf("%w: marshal credentials: %w", ErrSave, err)
	}

	key, err := v.keystore.Get(v.projectID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMasterKey, err)
	}

	blob, err := Seal(key, data)
	if err != nil {
		return fmt.Errorf("%w: seal: %w", ErrSave, err)
	}

	vaultPath := config.VaultFile(v.root)
	backupPath := config.VaultBackupFile(v.root)

	// Backup current vault.bin before overwriting (best-effort).
	if _, err := os.Stat(vaultPath); err == nil {
		_ = copyFile(vaultPath, backupPath)
	}

	// Atomic write: temp file + rename.
	dir := filepath.Dir(vaultPath)
	tmp, err := os.CreateTemp(dir, "vault-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: create temp file: %w", ErrSave, err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: write temp file: %w", ErrSave, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: sync failed: %w", ErrSave, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: close temp file: %w", ErrSave, err)
	}
	if err := os.Rename(tmpName, vaultPath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: atomic rename: %w", ErrSave, err)
	}
	return nil
}

// Add appends a credential after checking for duplicate names and placeholder
// collisions. It persists the vault on success.
func (v *Vault) Add(cred *Credential) error {
	for _, c := range v.credentials {
		if c.Name == cred.Name {
			return fmt.Errorf("%w: %q", ErrDuplicateCredential, cred.Name)
		}
		if c.Placeholder == cred.Placeholder {
			return fmt.Errorf("%w: generated placeholder for %q matches credential %q. Remove the conflicting credential with veil remove", ErrPlaceholderCollision, cred.Name, c.Name)
		}
	}
	v.credentials = append(v.credentials, cred)
	return v.Save()
}

// Get finds a credential by name.
func (v *Vault) Get(name string) (*Credential, bool) {
	for _, c := range v.credentials {
		if c.Name == name {
			return c, true
		}
	}
	return nil, false
}

// List returns a copy of all credentials.
func (v *Vault) List() []*Credential {
	out := make([]*Credential, len(v.credentials))
	copy(out, v.credentials)
	return out
}

// Delete removes a credential by name and persists the vault.
// Returns (false, nil) if the credential was not found.
func (v *Vault) Delete(name string) (bool, error) {
	for i, c := range v.credentials {
		if c.Name == name {
			v.credentials = append(v.credentials[:i], v.credentials[i+1:]...)
			if err := v.Save(); err != nil {
				return true, err
			}
			return true, nil
		}
	}
	return false, nil
}

// Credentials is an alias for List.
func (v *Vault) Credentials() []*Credential {
	return v.List()
}

// PlaceholderSet returns the set of currently-used placeholder strings,
// suitable for passing to placeholder.Generate to prevent collisions.
func (v *Vault) PlaceholderSet() placeholder.Set {
	out := make(placeholder.Set, len(v.credentials))
	for _, c := range v.credentials {
		out[c.Placeholder] = struct{}{}
	}
	return out
}

// PlaceholderMap returns a map from placeholder value to credential,
// used by the injector to swap placeholders back to real secrets.
func (v *Vault) PlaceholderMap() map[string]*Credential {
	m := make(map[string]*Credential, len(v.credentials))
	for _, c := range v.credentials {
		m[c.Placeholder] = c
	}
	return m
}

// ProjectID returns the vault's project identifier.
func (v *Vault) ProjectID() string {
	return v.projectID
}

// CreateVault initialises a new vault on disk: creates .veil/, vault.meta,
// generates a master key, stores it in the keystore, and writes an empty
// encrypted vault.
func CreateVault(root string, projectID string, ks Keystore) (*Vault, error) {
	stateDir := config.ProjectStateDir(root)
	if err := config.EnsureDir(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("%w: create state dir: %w", ErrSave, err)
	}

	// Write vault.meta.
	meta := vaultMeta{ProjectID: projectID, Version: 1}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal meta: %w", ErrSave, err)
	}
	if err := os.WriteFile(config.VaultMetaFile(root), metaBytes, 0600); err != nil {
		return nil, fmt.Errorf("%w: write meta: %w", ErrSave, err)
	}

	// Generate master key.
	var key [32]byte
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, fmt.Errorf("%w: generate key: %w", ErrSave, err)
	}
	if err := ks.Set(projectID, key); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMasterKey, err)
	}

	v := &Vault{
		root:        root,
		projectID:   projectID,
		credentials: []*Credential{},
		keystore:    ks,
	}

	if err := v.Save(); err != nil {
		return nil, err
	}

	// Write .gitignore inside .veil/ so nothing is accidentally committed.
	gitignorePath := config.VaultGitignoreFile(root)
	if err := os.WriteFile(gitignorePath, []byte("*\n"), 0600); err != nil {
		return nil, fmt.Errorf("%w: write gitignore: %w", ErrSave, err)
	}

	return v, nil
}

// copyFile copies src to dst, overwriting dst if it exists.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src) // #nosec G304 -- paths are derived from config, not user input
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Clean(dst), data, 0600) //nolint:gosec // dst is derived from config paths, not user input
}
