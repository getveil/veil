package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/getveil/veil/internal/config"
)

// ReadProjectID reads vault.meta at the project root and returns the stored
// project ID. Does not require the keystore or master key — useful for
// commands like uninstall that need to identify the vault before tearing it
// down. Returns an error if the meta file is missing, malformed, or the
// project_id is empty.
func ReadProjectID(root string) (string, error) {
	meta, err := readMeta(root)
	if err != nil {
		return "", err
	}
	if meta.ProjectID == "" {
		return "", fmt.Errorf("vault.meta: empty project_id")
	}
	return meta.ProjectID, nil
}

// ReadVaultedFiles returns the entries recorded in vault.meta. Returns an
// empty slice if vault.meta is missing or the field was never written (older
// meta files predate the registry).
func ReadVaultedFiles(root string) ([]VaultedFile, error) {
	meta, err := readMeta(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return meta.VaultedFiles, nil
}

// AddVaultedFile appends an entry to vault.meta's vaulted-files registry if
// the path is not already present. Path is converted to an absolute path
// before storage so uninstall works regardless of the caller's cwd.
func AddVaultedFile(root, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("vault.meta: abs path: %w", err)
	}
	meta, err := readMeta(root)
	if err != nil {
		return err
	}
	for _, entry := range meta.VaultedFiles {
		if entry.Path == abs {
			return nil
		}
	}
	meta.VaultedFiles = append(meta.VaultedFiles, VaultedFile{Path: abs})
	return writeMeta(root, meta)
}

func readMeta(root string) (vaultMeta, error) {
	path := config.VaultMetaFile(root)
	data, err := ReadFileNoFollow(path)
	if err != nil {
		return vaultMeta{}, fmt.Errorf("vault.meta: %w", err)
	}
	var meta vaultMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return vaultMeta{}, fmt.Errorf("vault.meta: parse: %w", err)
	}
	return meta, nil
}

func writeMeta(root string, meta vaultMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("vault.meta: marshal: %w", err)
	}
	target := config.VaultMetaFile(root)
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".vault-meta-*.tmp")
	if err != nil {
		return fmt.Errorf("vault.meta: create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("vault.meta: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("vault.meta: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("vault.meta: close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("vault.meta: chmod: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("vault.meta: rename: %w", err)
	}
	return nil
}
