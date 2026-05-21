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

// TestReadProjectID_TolerantOfLegacyVaultedFilesField verifies vault.meta
// files written by pre-v1 builds (with a `vaulted_files` registry of paths
// init had touched) still unmarshal cleanly after the launch cuts dropped
// that field. JSON's tolerant unknown-field drop on struct unmarshaling is
// what keeps old vaults loadable; this test pins that contract.
func TestReadProjectID_TolerantOfLegacyVaultedFilesField(t *testing.T) {
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
	got, err := vault.ReadProjectID(root)
	if err != nil {
		t.Fatalf("ReadProjectID: %v (legacy vaulted_files must not break unmarshal)", err)
	}
	if got != "p" {
		t.Errorf("got %q, want %q", got, "p")
	}
}
