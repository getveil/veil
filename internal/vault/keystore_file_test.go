package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// newTestFileKeystore returns a FileKeystore with a minimal scrypt work
// factor so that tests run in milliseconds instead of seconds.
func newTestFileKeystore(t *testing.T) *FileKeystore {
	t.Helper()
	t.Setenv("VEIL_PASSPHRASE", "test-passphrase-123")
	path := filepath.Join(t.TempDir(), "keys.age")
	ks := NewFileKeystore(path)
	ks.SetWorkFactor(1) // minimal cost for fast tests
	return ks
}

func TestFileKeystoreSetGet(t *testing.T) {
	ks := newTestFileKeystore(t)

	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	if err := ks.Set("proj-1", key); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := ks.Get("proj-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != key {
		t.Fatalf("Get returned wrong key: got %x, want %x", got, key)
	}
}

func TestFileKeystoreGetMissing(t *testing.T) {
	ks := newTestFileKeystore(t)

	_, err := ks.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestFileKeystoreGetMissingFromExistingFile(t *testing.T) {
	ks := newTestFileKeystore(t)

	// Write one key so the file exists.
	var key [32]byte
	key[0] = 1
	if err := ks.Set("proj-a", key); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Ask for a different project.
	_, err := ks.Get("proj-b")
	if err == nil {
		t.Fatal("expected error for missing key in existing file")
	}
}

func TestFileKeystoreDeleteAndReGet(t *testing.T) {
	ks := newTestFileKeystore(t)

	var key [32]byte
	key[0] = 42

	if err := ks.Set("proj-1", key); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := ks.Delete("proj-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := ks.Get("proj-1")
	if err == nil {
		t.Fatal("expected error after Delete")
	}
}

func TestFileKeystoreDeleteIdempotent(t *testing.T) {
	ks := newTestFileKeystore(t)

	// Delete on a file that doesn't exist yet.
	if err := ks.Delete("nonexistent"); err != nil {
		t.Fatalf("Delete nonexistent (no file): %v", err)
	}

	// Create a key, then delete a different project.
	var key [32]byte
	key[0] = 1
	if err := ks.Set("proj-a", key); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := ks.Delete("proj-b"); err != nil {
		t.Fatalf("Delete nonexistent (file exists): %v", err)
	}
}

func TestFileKeystoreMultipleKeys(t *testing.T) {
	ks := newTestFileKeystore(t)

	var keyA, keyB [32]byte
	for i := range keyA {
		keyA[i] = byte(i)
	}
	for i := range keyB {
		keyB[i] = byte(255 - i)
	}

	if err := ks.Set("proj-a", keyA); err != nil {
		t.Fatalf("Set proj-a: %v", err)
	}
	if err := ks.Set("proj-b", keyB); err != nil {
		t.Fatalf("Set proj-b: %v", err)
	}

	gotA, err := ks.Get("proj-a")
	if err != nil {
		t.Fatalf("Get proj-a: %v", err)
	}
	gotB, err := ks.Get("proj-b")
	if err != nil {
		t.Fatalf("Get proj-b: %v", err)
	}

	if gotA != keyA {
		t.Fatal("proj-a key mismatch")
	}
	if gotB != keyB {
		t.Fatal("proj-b key mismatch")
	}

	// Delete one, verify the other still works.
	if err := ks.Delete("proj-a"); err != nil {
		t.Fatalf("Delete proj-a: %v", err)
	}
	_, err = ks.Get("proj-a")
	if err == nil {
		t.Fatal("expected error for deleted proj-a")
	}
	gotB, err = ks.Get("proj-b")
	if err != nil {
		t.Fatalf("Get proj-b after delete proj-a: %v", err)
	}
	if gotB != keyB {
		t.Fatal("proj-b key mismatch after delete proj-a")
	}
}

func TestFileKeystoreCorruptedFile(t *testing.T) {
	t.Setenv("VEIL_PASSPHRASE", "test-passphrase-123")
	path := filepath.Join(t.TempDir(), "keys.age")

	// Write garbage to the file.
	if err := os.WriteFile(path, []byte("this is not valid age data"), 0600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	ks := NewFileKeystore(path)
	ks.SetWorkFactor(1)

	_, err := ks.Get("proj-1")
	if err == nil {
		t.Fatal("expected error for corrupted file")
	}
}

func TestFileKeystoreNoPassphrase(t *testing.T) {
	t.Setenv("VEIL_PASSPHRASE", "")
	path := filepath.Join(t.TempDir(), "keys.age")

	ks := NewFileKeystore(path)

	var key [32]byte
	err := ks.Set("proj-1", key)
	if err == nil {
		t.Fatal("expected error when VEIL_PASSPHRASE is empty")
	}
	// Must wrap ErrPassphraseMissing (not ErrKeystoreUnavailable) so the CLI
	// can tell "user forgot to set passphrase" apart from "wrong passphrase /
	// corrupt key file" and recommend different remediation for each.
	if !errors.Is(err, ErrPassphraseMissing) {
		t.Errorf("expected ErrPassphraseMissing, got: %v", err)
	}
}

func TestFileKeystoreOverwriteKey(t *testing.T) {
	ks := newTestFileKeystore(t)

	var key1, key2 [32]byte
	key1[0] = 1
	key2[0] = 2

	if err := ks.Set("proj-1", key1); err != nil {
		t.Fatalf("Set key1: %v", err)
	}
	if err := ks.Set("proj-1", key2); err != nil {
		t.Fatalf("Set key2: %v", err)
	}

	got, err := ks.Get("proj-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != key2 {
		t.Fatal("expected updated key")
	}
}

func TestFileKeystoreEnforcesParentMode(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "state")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(parent, "master.key.age")
	t.Setenv("VEIL_PASSPHRASE", "hunter2")

	ks := NewFileKeystore(path)
	ks.SetWorkFactor(1)

	var key [32]byte
	if err := ks.Set("proj", key); err != nil {
		t.Fatalf("set: %v", err)
	}

	info, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("parent mode %o, want 0700", info.Mode().Perm())
	}
}

// Regression test for H4b: Set should round-trip after the plaintext-zeroing
// hook in saveMap. Direct verification of the zeroed heap bytes is unreliable
// in Go; we verify the observable contract (write then read returns the same
// key).
func TestFileKeystoreSetZeroesPlaintext(t *testing.T) {
	ks := newTestFileKeystore(t)

	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := ks.Set("proj", key); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := ks.Get("proj")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != key {
		t.Fatalf("round-trip mismatch")
	}
}
