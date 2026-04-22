package testutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/8enji/veil/internal/testutil"
	"github.com/8enji/veil/internal/vault"
)

func TestTempProjectRoot(t *testing.T) {
	root := testutil.TempProjectRoot(t)
	if root == "" {
		t.Fatal("expected non-empty root")
	}
	info, err := os.Stat(filepath.Join(root, ".veil"))
	if err != nil || !info.IsDir() {
		t.Fatalf(".veil dir missing under root: %v", err)
	}
}

func TestMakeCred(t *testing.T) {
	c := testutil.MakeCred("STRIPE_KEY", "sk_live_abc", "sk_live_fake")
	if c == nil {
		t.Fatal("MakeCred returned nil")
	}
	if c.Name != "STRIPE_KEY" || c.Real != "sk_live_abc" || c.Placeholder != "sk_live_fake" {
		t.Fatalf("unexpected credential: %+v", c)
	}
	if c.ID == "" {
		t.Fatal("expected a generated ID")
	}
	if len(c.AllowedHosts) != 0 {
		t.Fatalf("expected empty AllowedHosts, got %v", c.AllowedHosts)
	}
}

func TestMakeCredWithHosts(t *testing.T) {
	c := testutil.MakeCred("GH", "ghp_real", "ghp_fake", "api.github.com", "*.github.com")
	if len(c.AllowedHosts) != 2 {
		t.Fatalf("AllowedHosts = %v, want 2 entries", c.AllowedHosts)
	}
	if c.AllowedHosts[0] != "api.github.com" {
		t.Errorf("AllowedHosts[0] = %q", c.AllowedHosts[0])
	}
	if c.AllowedHosts[1] != "*.github.com" {
		t.Errorf("AllowedHosts[1] = %q", c.AllowedHosts[1])
	}
}

func TestSetupVaultProject(t *testing.T) {
	root, ks := testutil.SetupVaultProject(t)
	if root == "" {
		t.Fatal("expected non-empty root")
	}
	if ks == nil {
		t.Fatal("expected non-nil keystore")
	}
	// Vault file should exist under .veil/
	if _, err := os.Stat(filepath.Join(root, ".veil", "vault.bin")); err != nil {
		t.Fatalf("vault.bin missing: %v", err)
	}
	// Reopen using the same keystore and verify the credential is there.
	v, err := vault.Open(root, ks)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	creds := v.List()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Name != "TEST_SECRET" {
		t.Errorf("credential name = %q, want TEST_SECRET", creds[0].Name)
	}
}
