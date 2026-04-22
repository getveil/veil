package vault

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/8enji/veil/internal/config"
)

// ReadProjectID reads vault.meta at the project root and returns the stored
// project ID. Does not require the keystore or master key — useful for
// commands like uninstall that need to identify the vault before tearing it
// down. Returns an error if the meta file is missing, malformed, or the
// project_id is empty.
func ReadProjectID(root string) (string, error) {
	path := config.VaultMetaFile(root)
	data, err := os.ReadFile(path) // #nosec G304 -- path derived from project root
	if err != nil {
		return "", fmt.Errorf("reading vault.meta: %w", err)
	}
	var meta vaultMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", fmt.Errorf("parsing vault.meta: %w", err)
	}
	if meta.ProjectID == "" {
		return "", fmt.Errorf("vault.meta has empty project_id")
	}
	return meta.ProjectID, nil
}
