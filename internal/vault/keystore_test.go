package vault

import (
	"testing"
)

func TestMemKeystoreSetGet(t *testing.T) {
	ks := NewMemKeystore()
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
		t.Fatal("Get returned wrong key")
	}
}

func TestMemKeystoreGetMissing(t *testing.T) {
	ks := NewMemKeystore()
	_, err := ks.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestMemKeystoreDelete(t *testing.T) {
	ks := NewMemKeystore()
	var key [32]byte
	key[0] = 42

	if err := ks.Set("proj-1", key); err != nil {
		t.Fatal(err)
	}
	if err := ks.Delete("proj-1"); err != nil {
		t.Fatal(err)
	}

	_, err := ks.Get("proj-1")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}
