# MCP Config Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `veil init` to scan Claude Desktop's MCP config, vault plaintext tokens from server `env` blocks, and replace them with format-aware placeholders.

**Architecture:** New `internal/mcpconfig` package handles discovery, parsing, and rewriting of `claude_desktop_config.json`. The `runInit()` function in `internal/cli/init.go` gains a new step after `.env` processing that calls into this package. Existing `placeholder` and `vault` packages are reused unchanged.

**Tech Stack:** Go 1.26, `encoding/json`, existing `placeholder` and `vault` packages.

---

## File Structure

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `internal/mcpconfig/mcpconfig.go` | `Discover()`, `Parse()`, `ConfigFile` type, `SetEnvValue()`, `Bytes()` |
| Create | `internal/mcpconfig/mcpconfig_test.go` | Unit tests for the mcpconfig package |
| Create | `test/fixtures/mcp/claude_desktop_config.json` | Test fixture with multiple servers |
| Modify | `internal/cli/init.go` | Add MCP config step after `.env` processing |
| Modify | `internal/cli/init_test.go` | Add tests for MCP config integration in init |

---

### Task 1: Create test fixture

**Files:**
- Create: `test/fixtures/mcp/claude_desktop_config.json`

- [ ] **Step 1: Create the fixture file**

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_test1234567890abcdef1234567890abcdef"
      }
    },
    "slack": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-slack"],
      "env": {
        "SLACK_TOKEN": "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx",
        "WORKSPACE_NAME": "my-workspace"
      }
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  },
  "preferences": {
    "theme": "dark"
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add test/fixtures/mcp/claude_desktop_config.json
git commit -m "test: add MCP config fixture for claude_desktop_config.json"
```

---

### Task 2: Implement `mcpconfig.Discover()`

**Files:**
- Create: `internal/mcpconfig/mcpconfig.go`
- Create: `internal/mcpconfig/mcpconfig_test.go`

- [ ] **Step 1: Write the failing test for Discover**

In `internal/mcpconfig/mcpconfig_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/mcpconfig/ -v -run TestDiscover`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Write minimal implementation**

In `internal/mcpconfig/mcpconfig.go`:

```go
// Package mcpconfig discovers, parses, and rewrites Claude Desktop MCP configuration files.
package mcpconfig

import (
	"os"
	"path/filepath"
	"runtime"
)

const configFileName = "claude_desktop_config.json"

// Discover returns the path to Claude Desktop's MCP config file, or "" if not found.
func Discover() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir, err := claudeConfigDir(runtime.GOOS, home)
	if err != nil {
		return "", nil // unsupported platform — not an error, just no config
	}
	return discoverIn(dir)
}

// discoverIn checks whether claude_desktop_config.json exists in dir.
// Exported for testing with controlled paths.
func discoverIn(dir string) (string, error) {
	p := filepath.Join(dir, configFileName)
	info, err := os.Stat(p)
	if err != nil {
		return "", nil // file doesn't exist
	}
	if info.IsDir() {
		return "", nil
	}
	return p, nil
}

// claudeConfigDir returns the platform-specific Claude Desktop config directory.
func claudeConfigDir(goos, home string) (string, error) {
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude"), nil
	case "linux":
		return filepath.Join(home, ".config", "Claude"), nil
	default:
		return "", nil
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/mcpconfig/ -v -run TestDiscover`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/mcpconfig/mcpconfig.go internal/mcpconfig/mcpconfig_test.go
git commit -m "feat(mcpconfig): add Discover for Claude Desktop config path"
```

---

### Task 3: Implement `Parse()` and `ConfigFile` type

**Files:**
- Modify: `internal/mcpconfig/mcpconfig.go`
- Modify: `internal/mcpconfig/mcpconfig_test.go`

- [ ] **Step 1: Write failing tests for Parse**

Append to `internal/mcpconfig/mcpconfig_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/mcpconfig/ -v -run TestParse`
Expected: FAIL — `Parse` and `Servers` are not defined.

- [ ] **Step 3: Write implementation**

Add to `internal/mcpconfig/mcpconfig.go` (after the existing `Discover` code):

```go
import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ServerConfig represents a single MCP server entry.
type ServerConfig struct {
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`

	// overflow captures unknown JSON fields for round-trip fidelity.
	overflow map[string]json.RawMessage
}

// ConfigFile represents a parsed Claude Desktop configuration file.
type ConfigFile struct {
	path    string
	servers map[string]*ServerConfig

	// topLevel preserves all top-level keys for round-trip fidelity.
	// "mcpServers" is removed from this map and stored in servers.
	topLevel map[string]json.RawMessage
}

// Parse reads and parses the Claude Desktop config file at path.
func Parse(path string) (*ConfigFile, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from Discover(), not user input
	if err != nil {
		return nil, fmt.Errorf("mcpconfig: read %s: %w", path, err)
	}

	// Parse top-level as raw messages to preserve unknown keys.
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(data, &topLevel); err != nil {
		return nil, fmt.Errorf("mcpconfig: parse %s: %w", path, err)
	}

	servers := make(map[string]*ServerConfig)

	if raw, ok := topLevel["mcpServers"]; ok {
		// Parse each server as raw message first, then decode known fields.
		var rawServers map[string]json.RawMessage
		if err := json.Unmarshal(raw, &rawServers); err != nil {
			return nil, fmt.Errorf("mcpconfig: parse mcpServers: %w", err)
		}

		for name, rawServer := range rawServers {
			sc := &ServerConfig{}
			if err := json.Unmarshal(rawServer, sc); err != nil {
				return nil, fmt.Errorf("mcpconfig: parse server %q: %w", name, err)
			}

			// Capture overflow: all fields that aren't command/args/env.
			var allFields map[string]json.RawMessage
			if err := json.Unmarshal(rawServer, &allFields); err != nil {
				return nil, fmt.Errorf("mcpconfig: parse server %q overflow: %w", name, err)
			}
			delete(allFields, "command")
			delete(allFields, "args")
			delete(allFields, "env")
			if len(allFields) > 0 {
				sc.overflow = allFields
			}

			if sc.Env == nil {
				sc.Env = make(map[string]string)
			}
			servers[name] = sc
		}
	}

	return &ConfigFile{
		path:     path,
		servers:  servers,
		topLevel: topLevel,
	}, nil
}

// Servers returns the MCP server configurations.
func (c *ConfigFile) Servers() map[string]*ServerConfig {
	return c.servers
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/mcpconfig/ -v -run TestParse`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/mcpconfig/mcpconfig.go internal/mcpconfig/mcpconfig_test.go
git commit -m "feat(mcpconfig): add Parse and ConfigFile for reading MCP configs"
```

---

### Task 4: Implement `SetEnvValue()` and `Bytes()` with round-trip fidelity

**Files:**
- Modify: `internal/mcpconfig/mcpconfig.go`
- Modify: `internal/mcpconfig/mcpconfig_test.go`

- [ ] **Step 1: Write failing tests for SetEnvValue and Bytes**

Append to `internal/mcpconfig/mcpconfig_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/mcpconfig/ -v -run "TestSetEnvValue|TestBytesPreserves"`
Expected: FAIL — `SetEnvValue` and `Bytes` are not defined.

- [ ] **Step 3: Write implementation**

Add to `internal/mcpconfig/mcpconfig.go`:

```go
// SetEnvValue replaces an env var value for a specific server.
func (c *ConfigFile) SetEnvValue(server, key, value string) {
	if s, ok := c.servers[server]; ok {
		s.Env[key] = value
	}
}

// Bytes serializes the config back to formatted JSON.
// Uses 2-space indentation to match Claude Desktop's formatting.
func (c *ConfigFile) Bytes() ([]byte, error) {
	// Rebuild the top-level map with the modified mcpServers.
	out := make(map[string]json.RawMessage, len(c.topLevel))
	for k, v := range c.topLevel {
		if k == "mcpServers" {
			continue
		}
		out[k] = v
	}

	// Serialize mcpServers with overflow fields preserved.
	if len(c.servers) > 0 {
		serversMap := make(map[string]json.RawMessage, len(c.servers))
		for name, sc := range c.servers {
			serverBytes, err := marshalServer(sc)
			if err != nil {
				return nil, fmt.Errorf("mcpconfig: marshal server %q: %w", name, err)
			}
			serversMap[name] = serverBytes
		}
		raw, err := json.Marshal(serversMap)
		if err != nil {
			return nil, fmt.Errorf("mcpconfig: marshal mcpServers: %w", err)
		}
		out["mcpServers"] = raw
	}

	// Use an encoder with HTML escaping disabled.
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return nil, fmt.Errorf("mcpconfig: encode config: %w", err)
	}
	return buf.Bytes(), nil
}

// marshalServer produces JSON for a server config, merging known fields with overflow.
func marshalServer(sc *ServerConfig) (json.RawMessage, error) {
	// Start with overflow fields.
	m := make(map[string]json.RawMessage)
	for k, v := range sc.overflow {
		m[k] = v
	}

	// Add known fields (overwriting any overflow collision, which shouldn't happen).
	raw, err := json.Marshal(sc.Command)
	if err != nil {
		return nil, err
	}
	m["command"] = raw

	if len(sc.Args) > 0 {
		raw, err = json.Marshal(sc.Args)
		if err != nil {
			return nil, err
		}
		m["args"] = raw
	}

	if len(sc.Env) > 0 {
		raw, err = json.Marshal(sc.Env)
		if err != nil {
			return nil, err
		}
		m["env"] = raw
	}

	return json.Marshal(m)
}
```

Also add `"bytes"` to the import block.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/mcpconfig/ -v -run "TestSetEnvValue|TestBytesPreserves"`
Expected: PASS

- [ ] **Step 5: Run all mcpconfig tests**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/mcpconfig/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add internal/mcpconfig/mcpconfig.go internal/mcpconfig/mcpconfig_test.go
git commit -m "feat(mcpconfig): add SetEnvValue and Bytes for config rewriting"
```

---

### Task 5: Integrate MCP config scanning into `runInit()`

**Files:**
- Modify: `internal/cli/init.go:33-179`

- [ ] **Step 1: Write failing test for MCP config integration**

Append to `internal/cli/init_test.go`:

```go
func TestInitWithMCPConfig(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create .env with a secret.
	envContent := "OPENAI_API_KEY=sk-proj-1234567890abcdef\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a fake MCP config directory and file.
	mcpDir := filepath.Join(tmpDir, "claude-config")
	if err := os.MkdirAll(mcpDir, 0755); err != nil {
		t.Fatal(err)
	}
	mcpContent := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_test1234567890abcdef1234567890abcdef"
      }
    }
  }
}`
	mcpConfigPath := filepath.Join(mcpDir, "claude_desktop_config.json")
	if err := os.WriteFile(mcpConfigPath, []byte(mcpContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Override the MCP config discovery path for testing.
	t.Setenv("VEIL_MCP_CONFIG_PATH", mcpConfigPath)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Assert summary mentions both .env and MCP config.
	outStr := out.String()
	if !strings.Contains(outStr, "MCP configs processed: 1") {
		t.Errorf("expected MCP config in summary, got: %s", outStr)
	}

	// Assert MCP config was rewritten (token replaced).
	mcpData, err := os.ReadFile(mcpConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	mcpStr := string(mcpData)
	if strings.Contains(mcpStr, "ghp_test1234567890abcdef1234567890abcdef") {
		t.Error("GITHUB_TOKEN was not replaced with a placeholder")
	}
	if !strings.Contains(mcpStr, "GITHUB_TOKEN") {
		t.Error("GITHUB_TOKEN key is missing from config")
	}

	// Assert backup was created.
	backupPath := mcpConfigPath + ".veil-backup"
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal("backup file not created")
	}
	if !strings.Contains(string(backupData), "ghp_test1234567890abcdef1234567890abcdef") {
		t.Error("backup should contain original token")
	}
}

func TestInitMCPOnlyNoEnvFiles(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// No .env files — only MCP config.
	mcpDir := filepath.Join(tmpDir, "claude-config")
	if err := os.MkdirAll(mcpDir, 0755); err != nil {
		t.Fatal(err)
	}
	mcpContent := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "env": {
        "GITHUB_TOKEN": "ghp_test1234567890abcdef1234567890abcdef"
      }
    }
  }
}`
	mcpConfigPath := filepath.Join(mcpDir, "claude_desktop_config.json")
	if err := os.WriteFile(mcpConfigPath, []byte(mcpContent), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_MCP_CONFIG_PATH", mcpConfigPath)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	outStr := out.String()
	if !strings.Contains(outStr, "Secrets vaulted: 1") {
		t.Errorf("expected 1 secret vaulted, got: %s", outStr)
	}
	if !strings.Contains(outStr, "MCP configs processed: 1") {
		t.Errorf("expected MCP config in summary, got: %s", outStr)
	}
}

func TestInitMCPDryRun(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create a .env so init doesn't bail early (before MCP support is wired).
	envContent := "HOSTNAME=myserver\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	mcpDir := filepath.Join(tmpDir, "claude-config")
	if err := os.MkdirAll(mcpDir, 0755); err != nil {
		t.Fatal(err)
	}
	originalContent := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "env": {
        "GITHUB_TOKEN": "ghp_test1234567890abcdef1234567890abcdef"
      }
    }
  }
}`
	mcpConfigPath := filepath.Join(mcpDir, "claude_desktop_config.json")
	if err := os.WriteFile(mcpConfigPath, []byte(originalContent), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_MCP_CONFIG_PATH", mcpConfigPath)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--dry-run", "--path", tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --dry-run failed: %v", err)
	}

	// MCP config should be UNCHANGED.
	mcpData, err := os.ReadFile(mcpConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(mcpData) != originalContent {
		t.Errorf("MCP config should be unchanged in dry-run, got: %q", string(mcpData))
	}

	// No backup should exist.
	backupPath := mcpConfigPath + ".veil-backup"
	if _, err := os.Stat(backupPath); err == nil {
		t.Error("backup file should not exist in dry-run mode")
	}

	// Output should mention what would be vaulted.
	outStr := out.String()
	if !strings.Contains(outStr, "would vault") {
		t.Errorf("expected dry-run output, got: %s", outStr)
	}
}
```

Also add a test for `--force` re-migration with an existing backup:

```go
func TestInitMCPForceWithExistingBackup(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	envContent := "HOSTNAME=myserver\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	mcpDir := filepath.Join(tmpDir, "claude-config")
	if err := os.MkdirAll(mcpDir, 0755); err != nil {
		t.Fatal(err)
	}
	mcpContent := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "env": {
        "GITHUB_TOKEN": "ghp_test1234567890abcdef1234567890abcdef"
      }
    }
  }
}`
	mcpConfigPath := filepath.Join(mcpDir, "claude_desktop_config.json")
	if err := os.WriteFile(mcpConfigPath, []byte(mcpContent), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_MCP_CONFIG_PATH", mcpConfigPath)

	// First init.
	cmd1 := NewRoot("test")
	cmd1.SetOut(new(bytes.Buffer))
	cmd1.SetErr(new(bytes.Buffer))
	cmd1.SetArgs([]string{"init", "--path", tmpDir})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init failed: %v", err)
	}

	// Backup should exist now.
	backupPath := mcpConfigPath + ".veil-backup"
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatal("backup should exist after first init")
	}

	// Restore original MCP config for re-migration.
	if err := os.WriteFile(mcpConfigPath, []byte(mcpContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Second init without --force should skip MCP (backup exists).
	cmd2 := NewRoot("test")
	errBuf2 := new(bytes.Buffer)
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(errBuf2)
	cmd2.SetArgs([]string{"init", "--force", "--path", tmpDir})
	// Note: without --force on the init itself this would fail with "already initialized".
	// With --force, it re-initializes AND the backup check also uses force.

	if err := cmd2.Execute(); err != nil {
		t.Fatalf("init --force failed: %v", err)
	}

	// MCP config should have been re-migrated (token replaced again).
	mcpData, err := os.ReadFile(mcpConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mcpData), "ghp_test1234567890abcdef1234567890abcdef") {
		t.Error("GITHUB_TOKEN should have been replaced on --force re-migration")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/cli/ -v -run "TestInitWithMCP|TestInitMCPOnly|TestInitMCPDryRun|TestInitMCPForce"`
Expected: FAIL — tests reference `VEIL_MCP_CONFIG_PATH` env var, no MCP logic in init yet.

- [ ] **Step 3: Add test override to Discover**

In `internal/mcpconfig/mcpconfig.go`, modify `Discover()`:

```go
// Discover returns the path to Claude Desktop's MCP config file, or "" if not found.
// If VEIL_MCP_CONFIG_PATH is set, it is used instead (for testing).
func Discover() (string, error) {
	if override := os.Getenv("VEIL_MCP_CONFIG_PATH"); override != "" {
		info, err := os.Stat(override)
		if err != nil {
			return "", nil
		}
		if info.IsDir() {
			return "", nil
		}
		return override, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir, err := claudeConfigDir(runtime.GOOS, home)
	if err != nil {
		return "", nil
	}
	return discoverIn(dir)
}
```

- [ ] **Step 4: Add MCP processing to `runInit()`**

Modify `internal/cli/init.go`. The key changes:

1. After `.env` scanning (line 57-64), add MCP config discovery.
2. Change the early-exit condition to check both `.env` and MCP.
3. After the `.env` processing loop (line 162), add MCP config processing.
4. Update the summary output.

Replace the `runInit` function with:

```go
func runInit(cmd *cobra.Command, force, dryRun bool) error {
	// 1. Resolve project root.
	root := flagPath
	if root == "" {
		r, err := config.FindProjectRoot(".")
		if err != nil {
			return exitError(err.Error())
		}
		root = r
	} else {
		abs, err := filepath.Abs(root)
		if err != nil {
			return exitError(err.Error())
		}
		root = abs
	}

	// 2. Check existing .veil/ directory.
	stateDir := config.ProjectStateDir(root)
	if info, err := os.Stat(stateDir); err == nil && info.IsDir() && !force {
		return exitError("project already initialized (use --force to reinitialize)")
	}

	// 3. Scan .env files.
	envPaths, err := scanner.Scan(root)
	if err != nil {
		return exitError(fmt.Sprintf("scanning .env files: %v", err))
	}

	// 3b. Discover MCP config.
	mcpConfigPath, err := mcpconfig.Discover()
	if err != nil {
		return exitError(fmt.Sprintf("discovering MCP config: %v", err))
	}

	// Early exit if nothing to process.
	if len(envPaths) == 0 && mcpConfigPath == "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "no .env files or MCP configs found in %s\n", root)
		return nil
	}

	// 4. Generate project ID.
	projectID := vault.NewID()

	// 5. Determine keystore.
	ks, err := buildKeystore()
	if err != nil {
		return exitError(fmt.Sprintf("keystore: %v", err))
	}

	// 6. Create vault.
	v, err := vault.CreateVault(root, projectID, ks)
	if err != nil {
		return exitError(fmt.Sprintf("creating vault: %v", err))
	}

	// 7. Ensure CA.
	ca, err := proxy.LoadOrCreateCA()
	if err != nil {
		return exitError(fmt.Sprintf("setting up CA: %v", err))
	}
	caFile, err := config.CAFile()
	if err != nil {
		return exitError(fmt.Sprintf("CA file path: %v", err))
	}
	_ = ca

	// 8. Process each .env file.
	var secretsVaulted int
	for _, envPath := range envPaths {
		envFile, err := scanner.ParseFile(envPath)
		if err != nil {
			return exitError(fmt.Sprintf("parsing %s: %v", envPath, err))
		}

		fileChanged := false
		for _, line := range envFile.Lines {
			if line.Kind != scanner.KVLine {
				continue
			}

			if strings.Contains(line.Raw, "# veil:skip") {
				if flagVerbose {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  skip (veil:skip): %s\n", line.Key)
				}
				continue
			}

			if !placeholder.IsSecretLike(line.Key, line.Value) {
				if flagVerbose {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  skip (not secret-like): %s\n", line.Key)
				}
				continue
			}

			ph, err := placeholder.Generate(line.Key, line.Value)
			if err != nil {
				return exitError(fmt.Sprintf("generating placeholder for %s: %v", line.Key, err))
			}

			cred := &vault.Credential{
				ID:          vault.NewID(),
				Name:        line.Key,
				Real:        line.Value,
				Placeholder: ph,
				Source:      "init",
				CreatedAt:   time.Now(),
			}
			if err := v.Add(cred); err != nil {
				if strings.Contains(err.Error(), "already exists") {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: duplicate key %q, skipping\n", line.Key)
					continue
				}
				return exitError(fmt.Sprintf("vaulting %s: %v", line.Key, err))
			}

			secretsVaulted++

			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  would vault: %s -> %s\n", line.Key, ph)
			} else {
				envFile.SetValue(line.Key, ph)
				fileChanged = true
			}
		}

		if !dryRun && fileChanged {
			if err := atomicWriteFile(envPath, envFile.Bytes()); err != nil {
				return exitError(fmt.Sprintf("writing %s: %v", envPath, err))
			}
		}
	}

	// 8b. Process MCP config.
	var mcpConfigsProcessed int
	if mcpConfigPath != "" {
		n, err := processMCPConfig(cmd, v, mcpConfigPath, force, dryRun)
		if err != nil {
			return err
		}
		secretsVaulted += n
		if n > 0 || dryRun {
			mcpConfigsProcessed = 1
		}
	}

	// 9. Append to project .gitignore.
	if !dryRun {
		appendGitignore(root)
	}

	// 10. Print summary.
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Veil initialized for %s\n", root)
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Secrets vaulted: %d\n", secretsVaulted)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  .env files processed: %d\n", len(envPaths))
	if mcpConfigsProcessed > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  MCP configs processed: %d\n", mcpConfigsProcessed)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  CA: %s\n", caFile)
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Run 'veil trust' to install the CA into your system trust store.")

	return nil
}

// processMCPConfig extracts secrets from an MCP config file, vaults them, and
// rewrites the config with placeholders. Returns the number of secrets vaulted.
func processMCPConfig(cmd *cobra.Command, v *vault.Vault, configPath string, force, dryRun bool) (int, error) {
	// Check for existing backup (indicates already migrated).
	backupPath := configPath + ".veil-backup"
	if _, err := os.Stat(backupPath); err == nil && !force {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s already has a backup (use --force to re-migrate)\n", configPath)
		return 0, nil
	}

	cfg, err := mcpconfig.Parse(configPath)
	if err != nil {
		return 0, exitError(fmt.Sprintf("parsing MCP config: %v", err))
	}

	var count int
	configChanged := false

	for serverName, server := range cfg.Servers() {
		for key, value := range server.Env {
			if !placeholder.IsSecretLike(key, value) {
				if flagVerbose {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  skip (not secret-like): mcp:%s:%s\n", serverName, key)
				}
				continue
			}

			ph, err := placeholder.Generate(key, value)
			if err != nil {
				return 0, exitError(fmt.Sprintf("generating placeholder for mcp:%s:%s: %v", serverName, key, err))
			}

			credName := fmt.Sprintf("mcp:%s:%s", serverName, key)
			cred := &vault.Credential{
				ID:          vault.NewID(),
				Name:        credName,
				Real:        value,
				Placeholder: ph,
				Source:      "init",
				CreatedAt:   time.Now(),
			}
			if err := v.Add(cred); err != nil {
				if strings.Contains(err.Error(), "already exists") {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: duplicate key %q, skipping\n", credName)
					continue
				}
				return 0, exitError(fmt.Sprintf("vaulting %s: %v", credName, err))
			}

			count++

			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  would vault: %s -> %s\n", credName, ph)
			} else {
				cfg.SetEnvValue(serverName, key, ph)
				configChanged = true
			}
		}
	}

	if !dryRun && configChanged {
		// Create backup of original.
		originalData, err := os.ReadFile(configPath) // #nosec G304
		if err != nil {
			return 0, exitError(fmt.Sprintf("reading MCP config for backup: %v", err))
		}
		if err := os.WriteFile(backupPath, originalData, 0600); err != nil {
			return 0, exitError(fmt.Sprintf("writing MCP config backup: %v", err))
		}

		// Write updated config.
		newData, err := cfg.Bytes()
		if err != nil {
			return 0, exitError(fmt.Sprintf("serializing MCP config: %v", err))
		}
		if err := atomicWriteFile(configPath, newData); err != nil {
			return 0, exitError(fmt.Sprintf("writing MCP config: %v", err))
		}
	}

	return count, nil
}
```

Add `"github.com/8enji/veil/internal/mcpconfig"` to the import block in `init.go`.

- [ ] **Step 5: Run the new tests**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/cli/ -v -run "TestInitWithMCP|TestInitMCPOnly|TestInitMCPDryRun|TestInitMCPForce"`
Expected: PASS

- [ ] **Step 6: Run all existing init tests to verify no regressions**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/cli/ -v -run TestInit`
Expected: All PASS (existing tests unchanged)

- [ ] **Step 7: Commit**

```bash
git add internal/cli/init.go internal/cli/init_test.go
git commit -m "feat(cli): integrate MCP config scanning into veil init"
```

---

### Task 6: Update early-exit message and test

**Files:**
- Modify: `internal/cli/init_test.go`

The existing `TestInitNoEnvFiles` test expects "no .env files found" but we changed the early-exit message to include MCP configs. Update it.

- [ ] **Step 1: Update the existing test**

In `internal/cli/init_test.go`, change `TestInitNoEnvFiles`:

```go
func TestInitNoEnvFiles(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	// Ensure no MCP config is discovered either.
	t.Setenv("VEIL_MCP_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.json"))

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init with no .env files should not error: %v", err)
	}

	outStr := out.String()
	if !strings.Contains(outStr, "no .env files or MCP configs found") {
		t.Errorf("expected no-sources message, got: %s", outStr)
	}
}
```

- [ ] **Step 2: Run the test**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/cli/ -v -run TestInitNoEnvFiles`
Expected: PASS

- [ ] **Step 3: Run full test suite**

Run: `cd /Users/ben/Workspace/Veil && go test ./...`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add internal/cli/init_test.go
git commit -m "test: update TestInitNoEnvFiles for MCP config early-exit message"
```

---

### Task 7: Test with the fixture file

**Files:**
- Modify: `internal/mcpconfig/mcpconfig_test.go`

- [ ] **Step 1: Write test using the fixture**

Append to `internal/mcpconfig/mcpconfig_test.go`:

```go
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
```

- [ ] **Step 2: Run the test**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/mcpconfig/ -v -run TestParseFixture`
Expected: PASS

- [ ] **Step 3: Run full test suite**

Run: `cd /Users/ben/Workspace/Veil && go test ./...`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add internal/mcpconfig/mcpconfig_test.go
git commit -m "test(mcpconfig): add fixture-based round-trip test"
```

---

## Verification

After all tasks are complete:

1. `go test ./...` — all tests pass
2. `go vet ./...` — no issues
3. Manual test:
   - Create a temp directory with a `.env` file containing a secret
   - Set `VEIL_MCP_CONFIG_PATH` to a test MCP config with tokens
   - Run `veil init --path <tmpdir>`
   - Verify both `.env` and MCP config have placeholders
   - Run `veil list --reveal` to see vaulted credentials with `mcp:` prefixed names
   - Verify backup file exists at `<config>.veil-backup`
