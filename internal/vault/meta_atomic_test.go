package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/config"
)

func TestWriteMetaReplacesExisting(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}

	if err := writeMeta(root, vaultMeta{ProjectID: "first", Version: 1}); err != nil {
		t.Fatalf("first writeMeta: %v", err)
	}
	if err := writeMeta(root, vaultMeta{ProjectID: "second", Version: 2}); err != nil {
		t.Fatalf("second writeMeta: %v", err)
	}

	data, err := os.ReadFile(config.VaultMetaFile(root))
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var got vaultMeta
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	if got.ProjectID != "second" || got.Version != 2 {
		t.Errorf("meta not replaced: got %+v", got)
	}
}

func TestWriteMetaLeavesNoTempFile(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeMeta(root, vaultMeta{ProjectID: "p", Version: 1}); err != nil {
		t.Fatalf("writeMeta: %v", err)
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".tmp") || strings.HasPrefix(name, ".vault-meta-") {
			t.Errorf("unexpected temp file left behind: %s", name)
		}
	}
}

func TestWriteMetaErrorLeavesExistingFileIntact(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}

	// First, write a valid meta file.
	if err := writeMeta(root, vaultMeta{ProjectID: "original", Version: 1}); err != nil {
		t.Fatalf("first writeMeta: %v", err)
	}
	original, err := os.ReadFile(config.VaultMetaFile(root))
	if err != nil {
		t.Fatal(err)
	}

	// Now make the directory read-only so a temp-file create will fail.
	if err := os.Chmod(stateDir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer func() { _ = os.Chmod(stateDir, 0700) }()

	err = writeMeta(root, vaultMeta{ProjectID: "should-not-stick", Version: 2})
	if err == nil {
		t.Fatal("expected writeMeta to fail when dir is read-only")
	}

	// Restore so we can read & cleanup, but assert original was unchanged.
	_ = os.Chmod(stateDir, 0700)
	current, err := os.ReadFile(config.VaultMetaFile(root))
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Errorf("existing meta was clobbered: got %q, want %q", current, original)
	}

	// No temp files should be left dangling.
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) == ".tmp" {
			t.Errorf("unexpected temp file left behind on failure: %s", name)
		}
	}
}
