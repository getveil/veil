package testutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/8enji/veil/internal/testutil"
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
}
