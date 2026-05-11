//go:build realkeystore

package vault

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// uniqueProjectID returns a per-test projectID that will not collide with
// either real veil installations or concurrent test runs on the same host.
func uniqueProjectID(t *testing.T) string {
	t.Helper()
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return fmt.Sprintf("veil-it-%d-%s", time.Now().UnixNano(), hex.EncodeToString(suffix[:]))
}

// TestAutoKeystoreRoundTrip exercises the production AutoKeystore against the
// real OS keystore — macOS Keychain on darwin, the Secret Service keyring on
// linux (or the age-encrypted file fallback if no keyring is available). The
// per-test projectID isolates this from the user's real veil state.
func TestAutoKeystoreRoundTrip(t *testing.T) {
	fallback := filepath.Join(t.TempDir(), "fallback.key.age")
	ks := AutoKeystore(fallback)
	if ks == nil {
		t.Fatal("AutoKeystore returned nil")
	}

	projectID := uniqueProjectID(t)

	// Always clean up, even on assertion failure mid-test, so we never leak
	// keys into the host keystore.
	t.Cleanup(func() {
		_ = ks.Delete(projectID)
	})

	var knownKey [32]byte
	for i := range knownKey {
		knownKey[i] = byte(i * 7) // arbitrary non-zero pattern
	}

	if err := ks.Set(projectID, knownKey); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := ks.Get(projectID)
	if err != nil {
		t.Fatalf("Get after Set: %v", err)
	}
	if got != knownKey {
		t.Fatalf("Get returned wrong key:\n got  %x\n want %x", got, knownKey)
	}

	if err := ks.Delete(projectID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := ks.Get(projectID); err == nil {
		t.Fatal("Get after Delete: expected error, got nil")
	}
}

// TestAutoKeystoreReturnsRealBackend verifies AutoKeystore's platform-specific
// backend selection.
//
// On darwin the Keychain is always available, so we require *KeyringKeystore.
//
// On linux the answer depends on whether the test runner has a Secret Service
// daemon (gnome-keyring, kwallet, etc.) running and unlocked. By default we
// accept either *KeyringKeystore or *FileKeystore so the test is meaningful
// on both kinds of hosts. CI sets VEIL_REQUIRE_KEYRING=1 to escalate the
// fallback case to a failure — a silent fall-through to the file keystore in
// CI would mask Linux keyring regressions.
func TestAutoKeystoreReturnsRealBackend(t *testing.T) {
	fallback := filepath.Join(t.TempDir(), "fallback.key.age")
	ks := AutoKeystore(fallback)
	if ks == nil {
		t.Fatal("AutoKeystore returned nil")
	}

	switch runtime.GOOS {
	case "darwin":
		if _, ok := ks.(*KeyringKeystore); !ok {
			t.Fatalf("on darwin expected *KeyringKeystore, got %T", ks)
		}
	default:
		// linux and others: keyring if available, file fallback otherwise.
		// When VEIL_REQUIRE_KEYRING=1 the test REQUIRES *KeyringKeystore
		// (CI uses this to detect silent degradation to the file fallback).
		requireKeyring := os.Getenv("VEIL_REQUIRE_KEYRING") == "1"
		switch ks.(type) {
		case *KeyringKeystore:
			// ok in both modes
		case *FileKeystore:
			if requireKeyring {
				t.Fatalf("VEIL_REQUIRE_KEYRING=1 but AutoKeystore returned *FileKeystore on %s — the OS keyring is not reachable (no D-Bus session, locked keyring, or missing libsecret)",
					runtime.GOOS)
			}
		default:
			t.Fatalf("on %s expected *KeyringKeystore or *FileKeystore, got %T",
				runtime.GOOS, ks)
		}
	}
}
