package vault

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/8enji/veil/internal/config"
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
		return nil, fmt.Errorf("vault: cannot read meta file: %w", err)
	}

	var meta vaultMeta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return nil, fmt.Errorf("vault: invalid meta file: %w", err)
	}

	vaultPath := config.VaultFile(root)
	blob, err := os.ReadFile(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("vault: cannot read vault file: %w", err)
	}

	key, err := ks.Get(meta.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("vault: cannot retrieve master key: %w", err)
	}

	plaintext, err := Unseal(key, blob)
	if err != nil {
		return nil, err
	}

	var creds []*Credential
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, fmt.Errorf("vault: corrupt credential data: %w", err)
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
		return fmt.Errorf("vault: marshal credentials: %w", err)
	}

	key, err := v.keystore.Get(v.projectID)
	if err != nil {
		return fmt.Errorf("vault: cannot retrieve master key: %w", err)
	}

	blob, err := Seal(key, data)
	if err != nil {
		return err
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
		return fmt.Errorf("vault: create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("vault: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("vault: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, vaultPath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("vault: atomic rename: %w", err)
	}
	return nil
}

// Add appends a credential after checking for duplicate names and placeholder
// collisions. It persists the vault on success.
func (v *Vault) Add(cred *Credential) error {
	for _, c := range v.credentials {
		if c.Name == cred.Name {
			return fmt.Errorf("vault: credential %q already exists", cred.Name)
		}
		if c.Placeholder == cred.Placeholder {
			return fmt.Errorf("vault: placeholder collision for %q", cred.Placeholder)
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
// Returns false if the credential was not found.
func (v *Vault) Delete(name string) bool {
	for i, c := range v.credentials {
		if c.Name == name {
			v.credentials = append(v.credentials[:i], v.credentials[i+1:]...)
			_ = v.Save()
			return true
		}
	}
	return false
}

// Credentials is an alias for List.
func (v *Vault) Credentials() []*Credential {
	return v.List()
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
		return nil, fmt.Errorf("vault: create state dir: %w", err)
	}

	// Write vault.meta.
	meta := vaultMeta{ProjectID: projectID, Version: 1}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("vault: marshal meta: %w", err)
	}
	if err := os.WriteFile(config.VaultMetaFile(root), metaBytes, 0600); err != nil {
		return nil, fmt.Errorf("vault: write meta: %w", err)
	}

	// Generate master key.
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, fmt.Errorf("vault: generate key: %w", err)
	}
	if err := ks.Set(projectID, key); err != nil {
		return nil, fmt.Errorf("vault: store master key: %w", err)
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
		return nil, fmt.Errorf("vault: write gitignore: %w", err)
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
