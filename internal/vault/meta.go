package vault

import (
	"encoding/json"
	"fmt"

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
