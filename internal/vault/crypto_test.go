package vault

import (
	"crypto/rand"
	"strings"
	"testing"
)

func randomKey(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealUnsealRoundTrip(t *testing.T) {
	key := randomKey(t)
	plaintext := []byte("hello, vault!")

	blob, err := Seal(key, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := Unseal(key, blob)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}

	if string(got) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestUnsealWrongKey(t *testing.T) {
	key1 := randomKey(t)
	key2 := randomKey(t)

	blob, err := Seal(key1, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = Unseal(key2, blob)
	if err == nil {
		t.Fatal("expected error with wrong key")
	}
	if !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnsealCorruption(t *testing.T) {
	key := randomKey(t)
	blob, err := Seal(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte in the ciphertext portion.
	corrupted := make([]byte, len(blob))
	copy(corrupted, blob)
	corrupted[headerLen+2] ^= 0xFF

	_, err = Unseal(key, corrupted)
	if err == nil {
		t.Fatal("expected error on corrupted ciphertext")
	}
	if !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnsealBadMagic(t *testing.T) {
	key := randomKey(t)
	blob, err := Seal(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	corrupted := make([]byte, len(blob))
	copy(corrupted, blob)
	corrupted[0] = 'X'

	_, err = Unseal(key, corrupted)
	if err == nil {
		t.Fatal("expected error on bad magic")
	}
	if !strings.Contains(err.Error(), "invalid magic bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnsealBadVersion(t *testing.T) {
	key := randomKey(t)
	blob, err := Seal(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	corrupted := make([]byte, len(blob))
	copy(corrupted, blob)
	corrupted[4] = 0x99

	_, err = Unseal(key, corrupted)
	if err == nil {
		t.Fatal("expected error on bad version")
	}
	if !strings.Contains(err.Error(), "unsupported version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnsealTruncated(t *testing.T) {
	key := randomKey(t)

	_, err := Unseal(key, []byte("VEIL"))
	if err == nil {
		t.Fatal("expected error on truncated data")
	}
	if !strings.Contains(err.Error(), "data too short") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSealUnsealEmptyPlaintext(t *testing.T) {
	key := randomKey(t)
	blob, err := Seal(key, []byte{})
	if err != nil {
		t.Fatalf("Seal empty: %v", err)
	}

	got, err := Unseal(key, blob)
	if err != nil {
		t.Fatalf("Unseal empty: %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(got))
	}
}
