package mcpconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverFindsExistingConfig(t *testing.T) {
	// Create a fake Claude config directory structure.
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "Claude")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "claude_desktop_config.json")
	if err := os.WriteFile(configPath, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := discoverIn(configDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != configPath {
		t.Errorf("got %q, want %q", got, configPath)
	}
}

func TestDiscoverReturnsEmptyWhenMissing(t *testing.T) {
	tmpDir := t.TempDir()

	got, err := discoverIn(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty string for missing config, got %q", got)
	}
}
