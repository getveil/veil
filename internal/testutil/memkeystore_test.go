//go:build testkeystore

package testutil_test

import (
	"testing"

	"github.com/getveil/veil/internal/testutil"
)

func TestNewMemKeystore(t *testing.T) {
	ks := testutil.NewMemKeystore()
	if ks == nil {
		t.Fatal("expected non-nil mem keystore")
	}
	var key [32]byte
	if err := ks.Set("project-a", key); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := ks.Get("project-a"); err != nil {
		t.Fatalf("get: %v", err)
	}
}
