// Package testutil contains helpers shared across test files.
package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/8enji/veil/internal/vault"
	"github.com/oklog/ulid/v2"
)

// MakeCred constructs a *vault.Credential for tests with sensible defaults.
// name is the credential name; real is the real secret; placeholder is the
// format-valid fake. Remaining fields are populated with deterministic
// zero-or-generated values suitable for test assertions.
func MakeCred(name, real, placeholder string) *vault.Credential {
	return &vault.Credential{
		ID:          ulid.Make().String(),
		Name:        name,
		Real:        real,
		Placeholder: placeholder,
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
