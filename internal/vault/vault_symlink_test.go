package vault_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/vault"
)

// TestOpenRefusesSymlinkedMeta covers H1's meta leg: a same-UID adversary
// who plants a symlink at vault.meta could otherwise feed an attacker-chosen
// project_id through to the keystore lookup, steering the master-key fetch
// to a project the attacker controls. The reader must fail with ELOOP
// rather than dereference the link.
func TestOpenRefusesSymlinkedMeta(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix symlink semantics")
	}
	root := t.TempDir()
	ks := vault.NewMemKeystore()
	if _, err := vault.CreateVault(root, "real-project", ks); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	metaPath := config.VaultMetaFile(root)
	if err := os.Remove(metaPath); err != nil {
		t.Fatalf("remove real meta: %v", err)
	}
	victim := filepath.Join(root, "attacker.meta")
	if err := os.WriteFile(victim, []byte(`{"project_id":"attacker"}`), 0o600); err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	if err := os.Symlink(victim, metaPath); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	v, err := vault.Open(root, ks)
	if err == nil {
		_ = v
		t.Fatal("vault.Open should refuse symlinked vault.meta, got nil error")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("expected ELOOP-wrapped error, got: %v", err)
	}
}

// TestOpenRefusesSymlinkedVaultBin covers H1's blob leg: with a symlink at
// vault.bin pointing at attacker-chosen ciphertext, Veil could otherwise be
// coaxed into running Unseal against attacker bytes (failing closed in the
// MAC, but still exposing the master key to attacker-controlled ciphertext).
// The reader must fail with ELOOP before any decryption attempt.
func TestOpenRefusesSymlinkedVaultBin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix symlink semantics")
	}
	root := t.TempDir()
	ks := vault.NewMemKeystore()
	if _, err := vault.CreateVault(root, "real-project", ks); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	vaultPath := config.VaultFile(root)
	if err := os.Remove(vaultPath); err != nil {
		t.Fatalf("remove real vault.bin: %v", err)
	}
	victim := filepath.Join(root, "attacker.bin")
	if err := os.WriteFile(victim, []byte("attacker-chosen ciphertext"), 0o600); err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	if err := os.Symlink(victim, vaultPath); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	v, err := vault.Open(root, ks)
	if err == nil {
		_ = v
		t.Fatal("vault.Open should refuse symlinked vault.bin, got nil error")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("expected ELOOP-wrapped error, got: %v", err)
	}
}

// TestSaveBackupRefusesSymlinkedVaultBin covers H2: when Save() backs up
// the existing vault.bin to vault.bin.bak via copyFile, a pre-planted
// symlink at vault.bin would otherwise stage the link target's contents
// (e.g. ~/.ssh/id_rsa) into vault.bin.bak, broadening leak vectors via
// support bundles or cloud sync. The backup must not contain victim bytes
// — copyFile's ReadFileNoFollow refuses to follow the link, and Save()
// treats backup as best-effort so the operation proceeds.
func TestSaveBackupRefusesSymlinkedVaultBin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix symlink semantics")
	}
	root := t.TempDir()
	ks := vault.NewMemKeystore()
	v, err := vault.CreateVault(root, "backup-symlink-project", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	const victimSecret = "VICTIM-PRIVATE-KEY-MATERIAL"
	victim := filepath.Join(root, "victim.secret")
	if err := os.WriteFile(victim, []byte(victimSecret), 0o600); err != nil {
		t.Fatalf("seed victim: %v", err)
	}

	vaultPath := config.VaultFile(root)
	if err := os.Remove(vaultPath); err != nil {
		t.Fatalf("remove real vault.bin: %v", err)
	}
	if err := os.Symlink(victim, vaultPath); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	// Trigger Save() via Add(). Save's atomic-rename leg replaces the
	// vault.bin symlink with a real file (rename(2) does not follow the
	// destination link), so the Add itself succeeds.
	cred := &vault.Credential{
		ID:          vault.NewID(),
		Name:        "k",
		Real:        "s",
		Placeholder: "PH_K",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	if err := v.Add(cred); err != nil {
		t.Fatalf("Add (triggers Save): %v", err)
	}

	backupPath := config.VaultBackupFile(root)
	if data, err := os.ReadFile(backupPath); err == nil {
		if strings.Contains(string(data), victimSecret) {
			t.Errorf("vault.bin.bak leaked symlink target bytes (%d bytes); copyFile followed the link", len(data))
		}
	}
	// Either outcome is acceptable: backup absent (preferred) or backup
	// containing only legitimate ciphertext. The invariant is "no victim
	// bytes in the backup".
}

// TestCreateVaultRefusesSymlinkedStateDir covers H3: when .veil/ is a
// pre-planted symlink to an attacker-chosen directory (e.g. ~/.config),
// EnsureDir's MkdirAll is a no-op against the link target and the
// subsequent Chmod(0700) defaces the target's permissions while all
// subsequent .veil/ writes land in the attacker's chosen directory.
// CreateVault must refuse rather than enter that state.
func TestCreateVaultRefusesSymlinkedStateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix symlink semantics")
	}
	root := t.TempDir()

	victimDir := filepath.Join(root, "victim-dir")
	if err := os.MkdirAll(victimDir, 0o755); err != nil {
		t.Fatalf("seed victim dir: %v", err)
	}
	stateDir := config.ProjectStateDir(root)
	if err := os.Symlink(victimDir, stateDir); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	ks := vault.NewMemKeystore()
	v, err := vault.CreateVault(root, "symlinked-state-project", ks)
	if err == nil {
		_ = v
		t.Fatal("CreateVault should refuse symlinked .veil/, got nil error")
	}

	info, statErr := os.Lstat(victimDir)
	if statErr != nil {
		t.Fatalf("lstat victim dir: %v", statErr)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("victim dir perms tightened to %o; symlink was followed despite refusal", info.Mode().Perm())
	}
}
