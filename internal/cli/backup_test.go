package cli

import (
	"os"
	"path/filepath"
	"testing"
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
