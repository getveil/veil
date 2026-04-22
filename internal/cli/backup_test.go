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
