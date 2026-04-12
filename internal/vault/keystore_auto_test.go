package vault

import (
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
