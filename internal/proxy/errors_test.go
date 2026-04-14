package proxy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadCAErrCALoad verifies that ErrCALoad is returned when LoadCA
// encounters files with invalid PEM content.
func TestLoadCAErrCALoad(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Write files with non-PEM content so pem.Decode returns nil.
	if err := os.WriteFile(certPath, []byte("not valid pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("not valid pem"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCA(certPath, keyPath)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, ErrCALoad) {
		t.Fatalf("expected ErrCALoad, got %v", err)
	}
}

// TestLoadCAInconsistentState verifies that LoadCA returns ErrCALoad when one
// of the cert/key files cannot be read (e.g. missing key file).
func TestLoadCAInconsistentState(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key") // intentionally absent

	if err := os.WriteFile(certPath, []byte("fake cert"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCA(certPath, keyPath)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, ErrCALoad) {
		t.Fatalf("expected ErrCALoad, got %v", err)
	}
}
