package vault_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/vault"
)

func TestReadProjectIDReturnsStoredValue(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	meta := map[string]any{"project_id": "proj-abc123", "version": 1}
	b, _ := json.Marshal(meta)
	if err := os.WriteFile(config.VaultMetaFile(root), b, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := vault.ReadProjectID(root)
	if err != nil {
		t.Fatalf("ReadProjectID: %v", err)
	}
	if got != "proj-abc123" {
		t.Errorf("got %q, want proj-abc123", got)
	}
}

func TestReadProjectIDErrorsWhenMetaMissing(t *testing.T) {
	root := t.TempDir()
	if _, err := vault.ReadProjectID(root); err == nil {
		t.Error("expected error when vault.meta is missing")
	}
}

func TestReadProjectIDErrorsOnInvalidJSON(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.VaultMetaFile(root), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.ReadProjectID(root); err == nil {
		t.Error("expected error on malformed vault.meta")
	}
}

func TestReadProjectIDErrorsOnEmptyProjectID(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.VaultMetaFile(root), []byte(`{"project_id":"","version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.ReadProjectID(root); err == nil {
		t.Error("expected error on empty project_id")
	}
}

// TestReadVaultedFiles_TolerantOfLegacyKindField verifies the compat
// rationale documented on vaultMeta.VaultedFiles: existing vault.meta
// files that recorded a "kind" discriminator (for the now-removed MCP
// scanning path) must still unmarshal cleanly. JSON's tolerant
// field-drop on unknown struct fields is what keeps the entry shape
// stable across the v1 launch cut; this guards against an inadvertent
// switch to []string that would break old vaults silently.
func TestReadVaultedFiles_TolerantOfLegacyKindField(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	raw := `{"project_id":"p","version":1,"vaulted_files":[` +
		`{"path":"/proj/.env","kind":"env"},` +
		`{"path":"/proj/.cursor/mcp.json","kind":"mcp"}` +
		`]}`
	if err := os.WriteFile(config.VaultMetaFile(root), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := vault.ReadVaultedFiles(root)
	if err != nil {
		t.Fatalf("ReadVaultedFiles: %v (legacy kind field must not break unmarshal)", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(entries), entries)
	}
	for _, e := range entries {
		if e.Path == "" {
			t.Errorf("entry has empty Path: %+v", e)
		}
	}
}
