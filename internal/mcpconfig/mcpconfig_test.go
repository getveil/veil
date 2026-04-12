package mcpconfig

import (
	"encoding/json"
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

func TestSetEnvValueAndBytes(t *testing.T) {
	content := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_abc123"
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

	cfg.SetEnvValue("github", "GITHUB_TOKEN", "ghp_placeholder999")

	out, err := cfg.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}

	// Re-parse the output to verify.
	tmpFile2 := filepath.Join(t.TempDir(), "config2.json")
	if err := os.WriteFile(tmpFile2, out, 0644); err != nil {
		t.Fatal(err)
	}
	cfg2, err := Parse(tmpFile2)
	if err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}

	got := cfg2.Servers()["github"].Env["GITHUB_TOKEN"]
	if got != "ghp_placeholder999" {
		t.Errorf("GITHUB_TOKEN = %q, want %q", got, "ghp_placeholder999")
	}
}

func TestBytesPreservesUnknownTopLevelKeys(t *testing.T) {
	content := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "env": {
        "TOKEN": "secret123"
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

	out, err := cfg.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}

	// Verify preferences key is present in output.
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}
	if _, ok := parsed["preferences"]; !ok {
		t.Error("preferences key was lost during round-trip")
	}
}

func TestBytesPreservesUnknownServerFields(t *testing.T) {
	content := `{
  "mcpServers": {
    "custom": {
      "command": "my-server",
      "env": {
        "KEY": "val"
      },
      "customField": "preserved"
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

	out, err := cfg.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}

	// Re-parse and check customField survived.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil {
		t.Fatal(err)
	}
	var servers map[string]map[string]json.RawMessage
	if err := json.Unmarshal(top["mcpServers"], &servers); err != nil {
		t.Fatal(err)
	}
	if _, ok := servers["custom"]["customField"]; !ok {
		t.Error("customField was lost during round-trip")
	}
}

func TestParseFixture(t *testing.T) {
	cfg, err := Parse("../../test/fixtures/mcp/claude_desktop_config.json")
	if err != nil {
		t.Fatalf("Parse fixture failed: %v", err)
	}

	servers := cfg.Servers()
	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(servers))
	}

	// github server has 1 env var.
	gh := servers["github"]
	if gh == nil {
		t.Fatal("github server missing")
	}
	if gh.Env["GITHUB_TOKEN"] != "ghp_test1234567890abcdef1234567890abcdef" {
		t.Errorf("unexpected GITHUB_TOKEN: %s", gh.Env["GITHUB_TOKEN"])
	}

	// slack server has 2 env vars.
	sl := servers["slack"]
	if sl == nil {
		t.Fatal("slack server missing")
	}
	if len(sl.Env) != 2 {
		t.Errorf("expected 2 env vars in slack, got %d", len(sl.Env))
	}

	// filesystem server has no env (or empty env).
	fs := servers["filesystem"]
	if fs == nil {
		t.Fatal("filesystem server missing")
	}
	if len(fs.Env) != 0 {
		t.Errorf("expected 0 env vars in filesystem, got %d", len(fs.Env))
	}

	// Round-trip: preferences should survive.
	out, err := cfg.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}
	if _, ok := top["preferences"]; !ok {
		t.Error("preferences lost in round-trip")
	}
}
