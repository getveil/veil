package vault_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/vault"
)

// TestReadProjectIDRefusesSymlinkedMeta covers the meta-read leg of the
// symlink-consistency gap: a same-UID adversary that plants a symlink at the
// vault.meta path can otherwise feed an arbitrary attacker-chosen file's
// contents into the uninstall pipeline as the vaulted-files registry,
// driving subsequent file operations against attacker-chosen paths. The
// reader must fail with ELOOP rather than follow the link.
func TestReadProjectIDRefusesSymlinkedMeta(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix symlink semantics")
	}
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}

	victim := filepath.Join(root, "attacker.meta")
	if err := os.WriteFile(victim, []byte(`{"project_id":"attacker"}`), 0o600); err != nil {
		t.Fatalf("seed victim: %v", err)
	}

	metaPath := config.VaultMetaFile(root)
	if err := os.Symlink(victim, metaPath); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	_, err := vault.ReadProjectID(root)
	if err == nil {
		t.Fatal("ReadProjectID should refuse symlinked vault.meta, got nil error")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("expected ELOOP, got: %v", err)
	}
}
