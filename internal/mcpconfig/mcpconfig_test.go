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

func TestParseValidConfig(t *testing.T) {
	content := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_abc123"
      }
    },
    "slack": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-slack"],
      "env": {
        "SLACK_TOKEN": "xoxb-123",
        "WORKSPACE": "team"
      }
    }
  },
  "preferences": {
    "theme": "dark"
  }
}`

	tmpFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	servers := cfg.Servers()
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	gh := servers["github"]
	if gh == nil {
		t.Fatal("github server not found")
	}
	if gh.Env["GITHUB_TOKEN"] != "ghp_abc123" {
		t.Errorf("GITHUB_TOKEN = %q, want %q", gh.Env["GITHUB_TOKEN"], "ghp_abc123")
	}

	sl := servers["slack"]
	if sl == nil {
		t.Fatal("slack server not found")
	}
	if sl.Env["SLACK_TOKEN"] != "xoxb-123" {
		t.Errorf("SLACK_TOKEN = %q, want %q", sl.Env["SLACK_TOKEN"], "xoxb-123")
	}
	if sl.Env["WORKSPACE"] != "team" {
		t.Errorf("WORKSPACE = %q, want %q", sl.Env["WORKSPACE"], "team")
	}
}

func TestParseNoMCPServers(t *testing.T) {
	content := `{"preferences": {"theme": "dark"}}`
	tmpFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	servers := cfg.Servers()
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseServerWithNoEnv(t *testing.T) {
	content := `{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}`
	tmpFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	servers := cfg.Servers()
	fs := servers["filesystem"]
	if fs == nil {
		t.Fatal("filesystem server not found")
	}
	if len(fs.Env) != 0 {
		t.Errorf("expected 0 env vars, got %d", len(fs.Env))
	}
}
