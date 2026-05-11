// Package testutil contains helpers shared across test files.
package testutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/getveil/veil/internal/vault"
	"github.com/oklog/ulid/v2"
)

// MakeCred constructs a *vault.Credential for tests with sensible defaults.
// name is the credential name; real is the real secret; placeholder is the
// format-valid fake. Optional hosts populate AllowedHosts (empty → no host
// scoping). Remaining fields are populated with deterministic zero-or-
// generated values suitable for test assertions.
func MakeCred(name, real, placeholder string, hosts ...string) *vault.Credential {
	return &vault.Credential{
		ID:           ulid.Make().String(),
		Name:         name,
		Real:         real,
		Placeholder:  placeholder,
		AllowedHosts: hosts,
	}
}

// TempProjectRoot returns a t.TempDir()-rooted project directory with a
// .veil/ state directory pre-created. Cleanup is handled by testing.T.
func TempProjectRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	stateDir := filepath.Join(root, ".veil")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("create state dir: %v", err)
	}
	return root
}

// SetupVaultProject creates a temp project root with a vault and one
// test credential. Returns (root, keystore). Cleanup is via t.TempDir.
// The returned *vault.MemKeystore satisfies the vault.Keystore interface
// so it can be passed wherever vault.Keystore is expected.
func SetupVaultProject(t *testing.T) (string, *vault.MemKeystore) {
	t.Helper()
	root := t.TempDir()
	ks := vault.NewMemKeystore()

	v, err := vault.CreateVault(root, "test-project", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	cred := &vault.Credential{
		ID:          vault.NewID(),
		Name:        "TEST_SECRET",
		Real:        "real-secret-value",
		Placeholder: "VEIL_PH_test_secret",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	if err := v.Add(cred); err != nil {
		t.Fatalf("Add credential: %v", err)
	}
	return root, ks
}
