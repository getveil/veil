//go:build integration_keychain

package vault

import (
	"testing"
)

func TestKeyringKeystoreSetGetDelete(t *testing.T) {
	ks := NewKeyringKeystore()
	projectID := "veil-test-keyring-integration"

	// Clean up in case a previous test run left state behind.
	_ = ks.Delete(projectID)

	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	// Set
	if err := ks.Set(projectID, key); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Get
	got, err := ks.Get(projectID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != key {
		t.Fatalf("Get returned wrong key: got %x, want %x", got, key)
	}

	// Delete
	if err := ks.Delete(projectID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Get after delete should fail.
	_, err = ks.Get(projectID)
	if err == nil {
		t.Fatal("expected error after Delete")
	}
}

func TestKeyringKeystoreDeleteIdempotent(t *testing.T) {
	ks := NewKeyringKeystore()
	// Deleting a key that doesn't exist should not error.
	if err := ks.Delete("veil-test-nonexistent-project"); err != nil {
		t.Fatalf("Delete nonexistent: %v", err)
	}
}
