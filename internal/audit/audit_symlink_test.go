package audit_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/getveil/veil/internal/audit"
)

// TestOpenRefusesSymlinkedDBPath asserts that audit.Open refuses to operate
// when the destination dbPath is a pre-existing symlink. Without this gate
// SQLite would open through the link (an empty file is a valid new DB to
// SQLite) and our subsequent os.Chmod would tighten the link target's
// permissions to 0600, giving a same-UID adversary a primitive against
// arbitrary files the user owns. The victim is created as an empty file so
// SQLite happily initializes it as a DB — that's what makes the chmod step
// reach the link target.
func TestOpenRefusesSymlinkedDBPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix symlink semantics")
	}
	dir := t.TempDir()

	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, nil, 0644); err != nil {
		t.Fatalf("seed victim: %v", err)
	}

	dbPath := filepath.Join(dir, "audit.db")
	if err := os.Symlink(victim, dbPath); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	s, err := audit.Open(dbPath)
	if err == nil {
		_ = s.Close()
		t.Fatal("audit.Open should refuse symlinked dbPath, got nil error")
	}

	info, statErr := os.Lstat(victim)
	if statErr != nil {
		t.Fatalf("lstat victim: %v", statErr)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("victim perms tightened to %o; symlink was followed despite Open returning error", info.Mode().Perm())
	}
}

// TestOpenRefusesSymlinkedParent asserts that audit.Open refuses to operate
// when the parent directory of dbPath is a symlink. Same risk as the leaf
// case: os.MkdirAll + os.Chmod(parent, 0o700) both follow symlinks, so the
// chmod would tighten the link target directory rather than the intended
// audit dir.
func TestOpenRefusesSymlinkedParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix symlink semantics")
	}
	dir := t.TempDir()

	victimDir := filepath.Join(dir, "victim-dir")
	if err := os.MkdirAll(victimDir, 0755); err != nil {
		t.Fatalf("seed victim dir: %v", err)
	}

	parent := filepath.Join(dir, "audit")
	if err := os.Symlink(victimDir, parent); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	dbPath := filepath.Join(parent, "audit.db")
	s, err := audit.Open(dbPath)
	if err == nil {
		_ = s.Close()
		t.Fatal("audit.Open should refuse symlinked parent, got nil error")
	}

	info, statErr := os.Lstat(victimDir)
	if statErr != nil {
		t.Fatalf("lstat victim dir: %v", statErr)
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("victim dir perms tightened to %o; symlink was followed despite Open returning error", info.Mode().Perm())
	}
}
