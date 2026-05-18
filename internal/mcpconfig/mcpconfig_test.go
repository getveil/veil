package mcpconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverFindsExistingConfig(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("VEIL_MCP_CONFIG_PATH", "")
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "")

	loc, ok := claudeDesktopUserLocation()
	if !ok {
		t.Skip("no Claude Desktop subpath on this platform")
	}
	configPath := filepath.Join(append([]string{fakeHome}, loc...)...)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Discover()
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, dc := range got {
		if dc.Client == ClaudeDesktop && dc.Path == configPath {
			return
		}
	}
	t.Errorf("Discover() did not return Claude Desktop config at %s; got %+v", configPath, got)
}

func TestDiscoverReturnsAllUserScopeHits(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("VEIL_MCP_CONFIG_PATH", "")
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "")

	claudeCodePath := filepath.Join(fakeHome, ".claude.json")
	if err := os.WriteFile(claudeCodePath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cursorDir := filepath.Join(fakeHome, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cursorPath := filepath.Join(cursorDir, "mcp.json")
	if err := os.WriteFile(cursorPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Discover()
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	seenClients := map[Client]string{}
	for _, dc := range got {
		seenClients[dc.Client] = dc.Path
	}
	if seenClients[ClaudeCode] != claudeCodePath {
		t.Errorf("Claude Code path = %q, want %q", seenClients[ClaudeCode], claudeCodePath)
	}
	if seenClients[Cursor] != cursorPath {
		t.Errorf("Cursor path = %q, want %q", seenClients[Cursor], cursorPath)
	}
}

func TestDiscoverEmptyWhenDisabled(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "1")

	if err := os.WriteFile(filepath.Join(fakeHome, ".claude.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Discover()
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Discover() returned %d configs, want 0 when VEIL_MCP_DISABLE_DISCOVERY=1", len(got))
	}
}

func TestDiscoverOverridePinsClaudeDesktopOnly(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "")

	overrideDir := t.TempDir()
	overridePath := filepath.Join(overrideDir, "claude_desktop_config.json")
	if err := os.WriteFile(overridePath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_MCP_CONFIG_PATH", overridePath)

	claudeCodePath := filepath.Join(fakeHome, ".claude.json")
	if err := os.WriteFile(claudeCodePath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Discover()
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var sawDesktop, sawCode bool
	for _, dc := range got {
		if dc.Client == ClaudeDesktop && dc.Path == overridePath {
			sawDesktop = true
		}
		if dc.Client == ClaudeCode && dc.Path == claudeCodePath {
			sawCode = true
		}
	}
	if !sawDesktop {
		t.Errorf("Claude Desktop discovery did not honor VEIL_MCP_CONFIG_PATH override")
	}
	if !sawCode {
		t.Errorf("Claude Code discovery was suppressed by Claude Desktop's override")
	}
}

func TestParentAnchorsReturnsOnePerUserLocation(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("VEIL_MCP_CONFIG_PATH", "")

	got, err := ParentAnchors()
	if err != nil {
		t.Fatalf("ParentAnchors: %v", err)
	}

	seen := map[Client]bool{}
	for _, pa := range got {
		seen[pa.Client] = true
		if pa.Anchor != fakeHome {
			t.Errorf("anchor = %q, want fakeHome %q", pa.Anchor, fakeHome)
		}
	}
	if !seen[ClaudeCode] {
		t.Errorf("ParentAnchors missing ClaudeCode")
	}
	if !seen[Cursor] {
		t.Errorf("ParentAnchors missing Cursor")
	}
}

func TestParentAnchorsSkipsOverriddenClaudeDesktop(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("VEIL_MCP_CONFIG_PATH", filepath.Join(t.TempDir(), "x.json"))

	got, err := ParentAnchors()
	if err != nil {
		t.Fatalf("ParentAnchors: %v", err)
	}
	for _, pa := range got {
		if pa.Client == ClaudeDesktop {
			t.Errorf("Claude Desktop anchor returned despite VEIL_MCP_CONFIG_PATH override")
		}
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

func TestSetArgAndBytes(t *testing.T) {
	content := `{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgres://user:pw@host/db"],
      "env": {}
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

	cfg.SetArg("postgres", 2, "postgres://user:placeholder@host/db")

	out, err := cfg.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}

	tmpFile2 := filepath.Join(t.TempDir(), "config2.json")
	if err := os.WriteFile(tmpFile2, out, 0644); err != nil {
		t.Fatal(err)
	}
	cfg2, err := Parse(tmpFile2)
	if err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}

	args := cfg2.Servers()["postgres"].Args
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d: %v", len(args), args)
	}
	if args[0] != "-y" || args[1] != "@modelcontextprotocol/server-postgres" {
		t.Errorf("unrelated args mutated: %v", args)
	}
	if args[2] != "postgres://user:placeholder@host/db" {
		t.Errorf("args[2] = %q, want %q", args[2], "postgres://user:placeholder@host/db")
	}
}

func TestSetArgOutOfBoundsIsNoOp(t *testing.T) {
	content := `{
  "mcpServers": {
    "x": {
      "command": "x",
      "args": ["a", "b"]
    }
  }
}`
	cfg, err := ParseBytes([]byte(content))
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	// Out-of-range indices and unknown server names must not panic.
	cfg.SetArg("x", -1, "ignored")
	cfg.SetArg("x", 99, "ignored")
	cfg.SetArg("missing", 0, "ignored")

	args := cfg.Servers()["x"].Args
	if len(args) != 2 || args[0] != "a" || args[1] != "b" {
		t.Errorf("args mutated unexpectedly: %v", args)
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
