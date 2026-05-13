package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/getveil/veil/internal/vault"
)

func TestBackupExistsWhenBackupPresent(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "foo.env")
	if err := os.WriteFile(src, []byte("KEY=value"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src+".veil-backup", []byte("KEY=original"), 0600); err != nil {
		t.Fatal(err)
	}
	if !backupExists(src) {
		t.Error("expected backupExists to return true")
	}
}

func TestBackupExistsWhenBackupMissing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "foo.env")
	if err := os.WriteFile(src, []byte("KEY=value"), 0600); err != nil {
		t.Fatal(err)
	}
	if backupExists(src) {
		t.Error("expected backupExists to return false")
	}
}

func TestWriteBackupCopiesContentAt0600(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "foo.env")
	original := []byte("SECRET=abc123\nOTHER=plain\n")
	if err := os.WriteFile(src, original, 0644); err != nil {
		t.Fatal(err)
	}

	if err := writeBackup(src); err != nil {
		t.Fatalf("writeBackup: %v", err)
	}

	backup := src + ".veil-backup"
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(data) != string(original) {
		t.Errorf("backup content = %q, want %q", data, original)
	}

	info, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("backup mode = %o, want 0600", mode)
	}
}

func TestWriteBackupOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "foo.env")
	if err := os.WriteFile(src, []byte("NEW=content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src+".veil-backup", []byte("STALE"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := writeBackup(src); err != nil {
		t.Fatalf("writeBackup: %v", err)
	}

	data, err := os.ReadFile(src + ".veil-backup")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "NEW=content" {
		t.Errorf("backup content = %q, want NEW=content", data)
	}
}

func TestWriteBackupErrorsWhenSourceMissing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "does-not-exist")
	if err := writeBackup(src); err == nil {
		t.Error("expected error when source file is missing")
	}
}

func TestWriteBackupOnlyCreatesBackupNoRegistration(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	// CreateVault so vault.meta exists for the registration step.
	if _, err := vault.CreateVault(root, "proj-only-backup", vault.NewMemKeystore()); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	src := filepath.Join(root, ".env")
	if err := os.WriteFile(src, []byte("X=1"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := writeBackupOnly(src); err != nil {
		t.Fatalf("writeBackupOnly: %v", err)
	}
	if !backupExists(src) {
		t.Error("expected .veil-backup to exist")
	}

	// vault.meta should NOT have an entry yet — this orphan state is what the
	// per-file refactor exploits.
	entries, err := vault.ReadVaultedFiles(root)
	if err != nil {
		t.Fatalf("ReadVaultedFiles: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no vaulted-file entries after writeBackupOnly, got %d: %+v", len(entries), entries)
	}
}

func TestRegisterVaultedFileRecordsInMeta(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if _, err := vault.CreateVault(root, "proj-register", vault.NewMemKeystore()); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	src := filepath.Join(root, ".env")
	if err := os.WriteFile(src, []byte("X=1"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := registerVaultedFile(root, src, vault.KindEnv); err != nil {
		t.Fatalf("registerVaultedFile: %v", err)
	}
	entries, err := vault.ReadVaultedFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Kind != vault.KindEnv {
		t.Errorf("expected 1 vaulted-file entry of KindEnv, got %+v", entries)
	}
	// The function records ABSOLUTE paths.
	abs, _ := filepath.Abs(src)
	if entries[0].Path != abs {
		t.Errorf("path: got %q, want %q", entries[0].Path, abs)
	}
	// And does NOT create a backup sidecar.
	if backupExists(src) {
		t.Error("registerVaultedFile should not create a backup sidecar")
	}
}

func TestWriteBackupOnlyPlusRegisterEqualsRecordVaultedBackup(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if _, err := vault.CreateVault(root, "proj-combo", vault.NewMemKeystore()); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	src := filepath.Join(root, "config.json")
	if err := os.WriteFile(src, []byte(`{"k":"v"}`), 0600); err != nil {
		t.Fatal(err)
	}

	if err := writeBackupOnly(src); err != nil {
		t.Fatalf("writeBackupOnly: %v", err)
	}
	if err := registerVaultedFile(root, src, vault.KindMCP); err != nil {
		t.Fatalf("registerVaultedFile: %v", err)
	}
	if !backupExists(src) {
		t.Error("backup missing")
	}
	entries, _ := vault.ReadVaultedFiles(root)
	if len(entries) != 1 || entries[0].Kind != vault.KindMCP {
		t.Errorf("registry: got %+v", entries)
	}
}

func TestRecordVaultedBackupWrapperUnchanged(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if _, err := vault.CreateVault(root, "proj-wrapper", vault.NewMemKeystore()); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	src := filepath.Join(root, ".env")
	if err := os.WriteFile(src, []byte("X=1"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := recordVaultedBackup(root, src, vault.KindEnv); err != nil {
		t.Fatalf("recordVaultedBackup: %v", err)
	}
	if !backupExists(src) {
		t.Error("backup missing after recordVaultedBackup")
	}
	entries, _ := vault.ReadVaultedFiles(root)
	if len(entries) != 1 {
		t.Errorf("registry: expected 1 entry, got %+v", entries)
	}
}
