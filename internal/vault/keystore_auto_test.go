package vault

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestAutoKeystoreDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		if os.Getenv("VEIL_TEST_KEYRING") != "1" {
			t.Skip("skipping: not darwin and VEIL_TEST_KEYRING!=1")
		}
	}

	ks := AutoKeystore("/tmp/veil-test-fallback.age")
	if _, ok := ks.(*KeyringKeystore); !ok {
		t.Fatalf("expected *KeyringKeystore on %s, got %T", runtime.GOOS, ks)
	}
}

// deleteFailKeyring satisfies Keystore by succeeding Set/Get and failing Delete.
type deleteFailKeyring struct {
	deleteErr error
}

func (k *deleteFailKeyring) Set(id string, key [32]byte) error { return nil }
func (k *deleteFailKeyring) Get(id string) ([32]byte, error)   { return [32]byte{}, nil }
func (k *deleteFailKeyring) Delete(id string) error            { return k.deleteErr }

func TestAutoKeystoreWarnsOnDeleteFailure(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("probe path only runs on non-darwin")
	}

	var buf bytes.Buffer
	ProbeWarnWriter = &buf
	t.Cleanup(func() { ProbeWarnWriter = os.Stderr })

	orig := NewKeyringKeystoreForTest
	NewKeyringKeystoreForTest = func() Keystore {
		return &deleteFailKeyring{deleteErr: errors.New("cleanup quirk")}
	}
	t.Cleanup(func() { NewKeyringKeystoreForTest = orig })

	ks := AutoKeystore("/tmp/unused")
	if _, isFile := ks.(*FileKeystore); isFile {
		t.Fatalf("expected keyring, got FileKeystore")
	}
	if !bytes.Contains(buf.Bytes(), []byte("keyring")) {
		t.Fatalf("expected keyring warning in output, got %q", buf.String())
	}
}

// setFailKeyring simulates D-Bus unavailable: Set fails.
type setFailKeyring struct {
	setErr error
}

func (k *setFailKeyring) Set(id string, key [32]byte) error { return k.setErr }
func (k *setFailKeyring) Get(id string) ([32]byte, error)   { return [32]byte{}, nil }
func (k *setFailKeyring) Delete(id string) error            { return nil }

func TestAutoKeystoreFallsBackToFileOnSetFailure(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("probe path only runs on non-darwin")
	}

	orig := NewKeyringKeystoreForTest
	NewKeyringKeystoreForTest = func() Keystore {
		return &setFailKeyring{setErr: errors.New("no dbus")}
	}
	t.Cleanup(func() { NewKeyringKeystoreForTest = orig })

	ks := AutoKeystore("/tmp/fallback")
	if _, isFile := ks.(*FileKeystore); !isFile {
		t.Fatalf("expected FileKeystore fallback, got %T", ks)
	}
}
