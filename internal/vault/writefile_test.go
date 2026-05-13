package vault

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// TestWriteFileNoFollowRefusesSymlink covers the H1/H9 leaf-symlink hole:
// plain os.WriteFile follows symlinks, so a pre-planted link at the write
// path would dump the data through to the link's target. The helper must
// fail with ELOOP and leave the target untouched.
func TestWriteFileNoFollowRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("ORIGINAL"), 0600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	err := WriteFileNoFollow(link, []byte("ATTACKER"), 0600)
	if err == nil {
		t.Fatal("WriteFileNoFollow should refuse symlink path, got nil error")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("expected ELOOP, got: %v", err)
	}

	got, rerr := os.ReadFile(target)
	if rerr != nil {
		t.Fatalf("read target: %v", rerr)
	}
	if string(got) != "ORIGINAL" {
		t.Errorf("symlink target was overwritten: got %q, want %q", got, "ORIGINAL")
	}
}

// TestWriteFileNoFollowEnforcesModeOnExisting covers the H9 mode-enforce
// hole: os.WriteFile / OpenFile only apply the requested mode on creation,
// so a pre-existing file with widened perms (e.g. 0644 from a previous
// install or attacker) keeps those perms after a rewrite. The helper must
// fchmod to the requested mode after open.
func TestWriteFileNoFollowEnforcesModeOnExisting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix mode semantics")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "existing")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("seed chmod: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("seed perm %v, want 0644", info.Mode().Perm())
	}

	if err := WriteFileNoFollow(path, []byte("new"), 0600); err != nil {
		t.Fatalf("WriteFileNoFollow: %v", err)
	}

	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("perm = %v, want 0600 — mode not enforced on pre-existing file", info.Mode().Perm())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
}

// TestWriteFileNoFollowCreatesNewFile covers the create path: a fresh write
// to a non-existent path lands with the requested mode and bytes.
func TestWriteFileNoFollowCreatesNewFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix mode semantics")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "new")

	if err := WriteFileNoFollow(path, []byte("hello"), 0600); err != nil {
		t.Fatalf("WriteFileNoFollow: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("perm = %v, want 0600", info.Mode().Perm())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want %q", got, "hello")
	}
}

// TestWriteFileNoFollowTruncates ensures a shorter rewrite leaves no tail of
// the previous content behind.
func TestWriteFileNoFollowTruncates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("AAAAAAAAAA"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := WriteFileNoFollow(path, []byte("BB"), 0600); err != nil {
		t.Fatalf("WriteFileNoFollow: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "BB" {
		t.Errorf("content = %q, want %q (file was not truncated)", got, "BB")
	}
}
