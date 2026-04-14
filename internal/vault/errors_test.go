package vault_test

import (
	"errors"
	"os"
	"testing"

	"github.com/8enji/veil/internal/vault"
)

func TestErrSentinels(t *testing.T) {
	// Opening a non-existent vault should return ErrOpen.
	_, err := vault.Open(t.TempDir(), vault.NewMemKeystore())
	if !errors.Is(err, vault.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
	// Underlying os.ErrNotExist must also be in the chain.
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist in chain, got %v", err)
	}
}
