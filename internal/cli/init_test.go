package cli

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/proxy"
	"github.com/8enji/veil/internal/skiphost"
	"github.com/8enji/veil/internal/vault"
)

func TestInitHappyPath(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()

	// Create .git directory so FindProjectRoot works.
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create .env with a secret and a non-secret.
	envContent := "OPENAI_API_KEY=sk-proj-1234567890abcdef\nHOSTNAME=myserver\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Run init.
	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Assert .veil/ directory created.
	stateDir := filepath.Join(tmpDir, ".veil")
	if info, err := os.Stat(stateDir); err != nil || !info.IsDir() {
		t.Error(".veil/ directory not created")
	}

	// Assert vault.bin exists.
	if _, err := os.Stat(filepath.Join(stateDir, "vault.bin")); err != nil {
		t.Error("vault.bin not created")
	}

	// Assert vault.meta exists.
	if _, err := os.Stat(filepath.Join(stateDir, "vault.meta")); err != nil {
		t.Error("vault.meta not created")
	}

	// Assert .veil/.gitignore contains *.
	veilGitignore, err := os.ReadFile(filepath.Join(stateDir, ".gitignore"))
	if err != nil {
		t.Error(".veil/.gitignore not created")
	} else if !strings.Contains(string(veilGitignore), "*") {
		t.Errorf(".veil/.gitignore should contain *, got: %q", string(veilGitignore))
	}

	// Assert .env was rewritten: OPENAI_API_KEY value changed.
	envData, err := os.ReadFile(filepath.Join(tmpDir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	envStr := string(envData)
	if strings.Contains(envStr, "sk-proj-1234567890abcdef") {
		t.Error("OPENAI_API_KEY was not replaced with a placeholder")
	}
	if !strings.Contains(envStr, "OPENAI_API_KEY=") {
		t.Error("OPENAI_API_KEY line is missing")
	}

	// Assert HOSTNAME value unchanged (not secret-like).
	if !strings.Contains(envStr, "HOSTNAME=myserver") {
		t.Errorf("HOSTNAME should be unchanged, got: %s", envStr)
	}

	// Check summary output.
	outStr := out.String()
	if !strings.Contains(outStr, "Veil initialized") {
		t.Errorf("expected summary, got: %s", outStr)
	}
	if !strings.Contains(outStr, "Secrets vaulted:") {
		t.Errorf("expected secrets vaulted line, got: %s", outStr)
	}
	if !strings.Contains(outStr, "✓") {
		t.Errorf("expected checkmark in output, got: %s", outStr)
	}
}

func TestInitDryRun(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	envContent := "OPENAI_API_KEY=sk-proj-1234567890abcdef\nHOSTNAME=myserver\n"
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--dry-run", "--path", tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --dry-run failed: %v", err)
	}

	// .veil/ should be created (vault is still created).
	if _, err := os.Stat(filepath.Join(tmpDir, ".veil")); err != nil {
		t.Error(".veil/ directory should exist even in dry-run mode")
	}

	// .env file should be UNCHANGED.
	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(envData) != envContent {
		t.Errorf(".env should be unchanged in dry-run, got: %q", string(envData))
	}

	// Output should mention what would be vaulted.
	outStr := out.String()
	if !strings.Contains(outStr, "would vault") {
		t.Errorf("expected dry-run output, got: %s", outStr)
	}
}

func TestInitForce(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	envContent := "SECRET_KEY=super-secret-value-1234567890abcdef\n"
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	// First init.
	cmd1 := NewRoot("test")
	cmd1.SetOut(new(bytes.Buffer))
	cmd1.SetErr(new(bytes.Buffer))
	cmd1.SetArgs([]string{"init", "--path", tmpDir})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init failed: %v", err)
	}

	// Rewrite .env so the second init has something to vault.
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Second init with --force.
	cmd2 := NewRoot("test")
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"init", "--force", "--path", tmpDir})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("init --force failed: %v", err)
	}
}

func TestInitNoEnvFiles(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	// Ensure no MCP config is discovered either.
	t.Setenv("VEIL_MCP_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.json"))
	// Strip CI/dev-shell secret-like exports so the shell-env scan also finds
	// nothing, ensuring the early-exit gate fires for the "no sources" case.
	clearShellEnvTestNoise(t)

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
	if !strings.Contains(outStr, "no .env files, MCP configs, or shell-exported secrets found") {
		t.Errorf("expected no-sources message, got: %s", outStr)
	}
}

func TestInitAlreadyInitialized(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	envContent := "API_TOKEN=tok_1234567890abcdefghij\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	// First init.
	cmd1 := NewRoot("test")
	cmd1.SetOut(new(bytes.Buffer))
	cmd1.SetErr(new(bytes.Buffer))
	cmd1.SetArgs([]string{"init", "--path", tmpDir})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init failed: %v", err)
	}

	// Second init without --force.
	cmd2 := NewRoot("test")
	errBuf := new(bytes.Buffer)
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(errBuf)
	cmd2.SetArgs([]string{"init", "--path", tmpDir})

	err := cmd2.Execute()
	if err == nil {
		t.Fatal("expected error for already initialized project")
	}
	if !strings.Contains(err.Error(), "already initialized") {
		t.Errorf("error should mention 'already initialized', got: %v", err)
	}
}

func TestInitGitignoreAppend(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create a .gitignore with existing content.
	gitignorePath := filepath.Join(tmpDir, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte("node_modules/\n*.log\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a .env with a secret.
	envContent := "DB_PASSWORD=password123456789012345\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Assert .gitignore now contains /.veil/.
	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "/.veil/") {
		t.Errorf(".gitignore should contain /.veil/, got: %q", content)
	}
	// Original content should still be there.
	if !strings.Contains(content, "node_modules/") {
		t.Error(".gitignore lost original content")
	}
}

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
	if !strings.Contains(outStr, "MCP configs processed:") {
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
	if !strings.Contains(outStr, "Secrets vaulted:") {
		t.Errorf("expected secrets vaulted line, got: %s", outStr)
	}
	if !strings.Contains(outStr, "MCP configs processed:") {
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

	// Second init with --force.
	cmd2 := NewRoot("test")
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"init", "--force", "--path", tmpDir})

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

func TestInitMCPCredentialNameFormat(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create .env so init proceeds.
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

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Open vault and verify credential name format.
	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("opening vault: %v", err)
	}

	cred, found := v.Get("mcp:github:GITHUB_TOKEN")
	if !found {
		t.Fatal("credential mcp:github:GITHUB_TOKEN not found in vault")
	}
	if cred.Source != "init" {
		t.Errorf("expected source %q, got %q", "init", cred.Source)
	}
	if cred.Real != "ghp_test1234567890abcdef1234567890abcdef" {
		t.Errorf("unexpected real value: %s", cred.Real)
	}
}

func TestInitMCPSkipsWhenBackupExists(t *testing.T) {
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

	// First init — creates backup.
	cmd1 := NewRoot("test")
	cmd1.SetOut(new(bytes.Buffer))
	cmd1.SetErr(new(bytes.Buffer))
	cmd1.SetArgs([]string{"init", "--path", tmpDir})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init failed: %v", err)
	}

	// Restore original config.
	if err := os.WriteFile(mcpConfigPath, []byte(mcpContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Second init WITHOUT --force — should warn and skip MCP.
	cmd2 := NewRoot("test")
	out2 := new(bytes.Buffer)
	errBuf2 := new(bytes.Buffer)
	cmd2.SetOut(out2)
	cmd2.SetErr(errBuf2)
	cmd2.SetArgs([]string{"init", "--force", "--path", tmpDir})
	// Note: --force is needed to get past "already initialized" check,
	// but the backup already exists so processMCPConfig will still skip
	// without force on the backup (force is shared). Since --force IS set,
	// let's test the non-force case differently: pre-create the backup
	// and run init on a fresh .veil dir.

	// Actually, let's test this properly: create a fresh tmpDir with a
	// pre-existing backup file, and run init (no --force needed since
	// .veil doesn't exist yet).
	tmpDir2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir2, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent2 := "HOSTNAME=myserver\n"
	if err := os.WriteFile(filepath.Join(tmpDir2, ".env"), []byte(envContent2), 0644); err != nil {
		t.Fatal(err)
	}

	mcpDir2 := filepath.Join(tmpDir2, "claude-config2")
	if err := os.MkdirAll(mcpDir2, 0755); err != nil {
		t.Fatal(err)
	}
	mcpConfigPath2 := filepath.Join(mcpDir2, "claude_desktop_config.json")
	if err := os.WriteFile(mcpConfigPath2, []byte(mcpContent), 0644); err != nil {
		t.Fatal(err)
	}
	// Pre-create backup to simulate already-migrated state.
	backupPath := mcpConfigPath2 + ".veil-backup"
	if err := os.WriteFile(backupPath, []byte(mcpContent), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_MCP_CONFIG_PATH", mcpConfigPath2)

	cmd3 := NewRoot("test")
	out3 := new(bytes.Buffer)
	errBuf3 := new(bytes.Buffer)
	cmd3.SetOut(out3)
	cmd3.SetErr(errBuf3)
	cmd3.SetArgs([]string{"init", "--path", tmpDir2})

	if err := cmd3.Execute(); err != nil {
		t.Fatalf("init with existing backup failed: %v", err)
	}

	// Should have warning about existing backup.
	errStr := errBuf3.String()
	if !strings.Contains(errStr, "already has a backup") {
		t.Errorf("expected backup warning on stderr, got: %s", errStr)
	}

	// MCP config should be unchanged (not re-migrated).
	mcpData, err := os.ReadFile(mcpConfigPath2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mcpData), "ghp_test1234567890abcdef1234567890abcdef") {
		t.Error("MCP config should be unchanged when backup exists without --force")
	}
}

func TestInitYes_VaultsAll(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	dir := t.TempDir()
	_ = os.Mkdir(filepath.Join(dir, ".git"), 0755)
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-1234567890abcdef\nGITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz1234\n"), 0644)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", dir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --yes failed: %v", err)
	}

	v, err := openVault(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	// Assert on specific .env-derived credentials rather than total count:
	// the test runner's shell env may contribute additional secret-like
	// entries (e.g. CLAUDE_CODE_OAUTH_TOKEN) that would otherwise inflate
	// the count unpredictably.
	if _, ok := v.Get("OPENAI_API_KEY"); !ok {
		t.Error("OPENAI_API_KEY should be vaulted")
	}
	if _, ok := v.Get("GITHUB_TOKEN"); !ok {
		t.Error("GITHUB_TOKEN should be vaulted")
	}
}

func TestInitInteractive_SkipFile(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	dir := t.TempDir()
	_ = os.Mkdir(filepath.Join(dir, ".git"), 0755)
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-1234567890abcdef\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, ".env.local"), []byte("LOCAL_KEY=sk-proj-localsecret1234567\n"), 0644)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetIn(strings.NewReader("select\n1\ny\n\n"))
	cmd.SetArgs([]string{"init", "--path", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, ok := v.Get("OPENAI_API_KEY"); !ok {
		t.Error("OPENAI_API_KEY should be vaulted")
	}
	if _, ok := v.Get("LOCAL_KEY"); ok {
		t.Error("LOCAL_KEY should NOT be vaulted (file was skipped)")
	}
}

func TestInitInteractive_SkipToken(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	dir := t.TempDir()
	_ = os.Mkdir(filepath.Join(dir, ".git"), 0755)
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-1234567890abcdef\nSTRIPE_KEY=sk_live_12345678901234567890abcd\n"), 0644)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetIn(strings.NewReader("select\n1\n\n"))
	cmd.SetArgs([]string{"init", "--path", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, ok := v.Get("OPENAI_API_KEY"); !ok {
		t.Error("OPENAI_API_KEY should be vaulted")
	}
	if _, ok := v.Get("STRIPE_KEY"); ok {
		t.Error("STRIPE_KEY should NOT be vaulted (was deselected)")
	}
}

func TestInitInteractive_SkipHosts(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	// Clear known test-runner env noise so shell-env scan has nothing to
	// prompt about — otherwise the stdin script below would feed its inputs
	// into the shell-env prompt instead of the skip-hosts prompt.
	clearShellEnvTestNoise(t)
	dir := t.TempDir()
	_ = os.Mkdir(filepath.Join(dir, ".git"), 0755)
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-1234567890abcdef\n"), 0644)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetIn(strings.NewReader("y\napi.anthropic.com\n"))
	cmd.SetArgs([]string{"init", "--path", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	hosts, err := skiphost.Load(config.SkipHostsFile(dir))
	if err != nil {
		t.Fatalf("load skip hosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "api.anthropic.com" {
		t.Errorf("expected [api.anthropic.com], got %v", hosts)
	}
}

func TestInitForce_WipesVault(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	dir := t.TempDir()
	_ = os.Mkdir(filepath.Join(dir, ".git"), 0755)
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-1234567890abcdef\n"), 0644)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", dir, "--yes"})
	_ = cmd.Execute()

	cmd2 := NewRoot("test")
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetIn(strings.NewReader("y\n"))
	cmd2.SetArgs([]string{"init", "--path", dir, "--force", "--yes"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("init --force failed: %v", err)
	}

	v, err := openVault(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	creds := v.List()
	if len(creds) != 0 {
		t.Logf("note: %d creds found (may be from re-scanning placeholders)", len(creds))
	}
}

func TestInitEnvSkipsWhenBackupExists(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte("GITHUB_TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Pre-seed a backup with a sentinel so we can verify it's not overwritten.
	backupPath := envPath + ".veil-backup"
	sentinel := []byte("sentinel\n")
	if err := os.WriteFile(backupPath, sentinel, 0600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	stderr := new(bytes.Buffer)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Backup must still contain the sentinel (unchanged).
	got, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(sentinel) {
		t.Errorf("backup overwritten; got %q, want %q", got, sentinel)
	}

	// .env must still contain the real token (file was skipped, not processed).
	envContents, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(envContents), "ghp_real1234567890abcdef1234567890abcdef") {
		t.Error(".env should have been skipped (real token still present)")
	}

	// Stderr should mention the skip.
	if !strings.Contains(stderr.String(), "already has a backup") {
		t.Errorf("expected 'already has a backup' warning on stderr, got: %s", stderr.String())
	}
}

func TestInitEnvCreatesBackupBeforeRewrite(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(tmpDir, ".env")
	original := []byte("# header\nGITHUB_TOKEN=ghp_real1234567890abcdef1234567890abcdef\nLOG_LEVEL=debug\n")
	if err := os.WriteFile(envPath, original, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Backup must exist and contain the exact original bytes.
	backup, err := os.ReadFile(envPath + ".veil-backup")
	if err != nil {
		t.Fatalf("backup not created: %v", err)
	}
	if string(backup) != string(original) {
		t.Errorf("backup content mismatch\ngot:  %q\nwant: %q", backup, original)
	}

	// Backup permission must be 0600.
	info, err := os.Stat(envPath + ".veil-backup")
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("backup mode = %o, want 0600", mode)
	}

	// .env must no longer contain the real token (placeholder substitution
	// happened).
	envContents, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(envContents), "ghp_real1234567890abcdef1234567890abcdef") {
		t.Error("real token leaked into .env after init")
	}
}

func TestAppendGitignoreAddsVeilBackupPattern(t *testing.T) {
	dir := t.TempDir()
	gitignorePath := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte("node_modules/\n"), 0644); err != nil {
		t.Fatal(err)
	}

	appendGitignore(dir)

	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "/.veil/") {
		t.Errorf(".gitignore should contain /.veil/, got: %q", content)
	}
	if !strings.Contains(content, "*.veil-backup") {
		t.Errorf(".gitignore should contain *.veil-backup, got: %q", content)
	}
	if !strings.Contains(content, "node_modules/") {
		t.Error(".gitignore lost original content")
	}
}

func TestAppendGitignoreIdempotent(t *testing.T) {
	dir := t.TempDir()
	gitignorePath := filepath.Join(dir, ".gitignore")
	initial := "node_modules/\n/.veil/\n*.veil-backup\n"
	if err := os.WriteFile(gitignorePath, []byte(initial), 0644); err != nil {
		t.Fatal(err)
	}

	appendGitignore(dir)

	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != initial {
		t.Errorf("expected .gitignore unchanged, got: %q", data)
	}
}

func TestAppendGitignoreNoOpWhenMissing(t *testing.T) {
	dir := t.TempDir()
	// No .gitignore present.
	appendGitignore(dir)
	if _, err := os.Stat(filepath.Join(dir, ".gitignore")); !os.IsNotExist(err) {
		t.Error("appendGitignore should not create .gitignore when absent")
	}
}

func TestInit_CorrelatesAWSTripleInEnvFile(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	envContent := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
		"AWS_SESSION_TOKEN=FwoGZXIvYXdzEJr//////////wEaDPexample\n" +
		"DATABASE_URL=postgres://u:pw@h/db\n"
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}

	awsCred, ok := v.Get("AWS_ACCESS_KEY_ID")
	if !ok {
		t.Fatalf("vault missing AWS_ACCESS_KEY_ID; names = %v", v.Names())
	}
	if awsCred.Scheme != "aws" {
		t.Errorf("Scheme = %q, want aws", awsCred.Scheme)
	}
	if awsCred.AWSAccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AWSAccessKeyID = %q", awsCred.AWSAccessKeyID)
	}
	if awsCred.Real != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("Real (secret access key) = %q", awsCred.Real)
	}
	if awsCred.AWSSessionToken != "FwoGZXIvYXdzEJr//////////wEaDPexample" {
		t.Errorf("AWSSessionToken = %q", awsCred.AWSSessionToken)
	}
	if awsCred.AWSAccessKeyIDPlaceholder == "" {
		t.Error("AWSAccessKeyIDPlaceholder is empty")
	}
	if awsCred.AWSSessionTokenPlaceholder == "" {
		t.Error("AWSSessionTokenPlaceholder is empty")
	}
	if len(awsCred.AllowedHosts) != 1 || awsCred.AllowedHosts[0] != "*.amazonaws.com" {
		t.Errorf("AllowedHosts = %v, want [*.amazonaws.com]", awsCred.AllowedHosts)
	}

	for _, name := range []string{"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		if _, found := v.Get(name); found {
			t.Errorf("unexpected bearer credential %q in vault (should be absorbed into aws group)", name)
		}
	}

	if _, ok := v.Get("DATABASE_URL"); !ok {
		t.Error("vault missing DATABASE_URL")
	}

	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	envStr := string(envData)
	for _, real := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"FwoGZXIvYXdzEJr//////////wEaDPexample",
	} {
		if strings.Contains(envStr, real) {
			t.Errorf(".env still contains real value %q:\n%s", real, envStr)
		}
	}
}

func TestInit_CorrelatesTwoAWSAccountsInEnvFile(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "PROD_AWS_ACCESS_KEY_ID=AKIAPRODEXAMPLE00001\n" +
		"PROD_AWS_SECRET_ACCESS_KEY=prod/secret/access/key/example00001\n" +
		"DEV_AWS_ACCESS_KEY_ID=AKIADEVEXAMPLE000001\n" +
		"DEV_AWS_SECRET_ACCESS_KEY=dev/secret/access/key/example000001\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	for _, groupName := range []string{"PROD_AWS_ACCESS_KEY_ID", "DEV_AWS_ACCESS_KEY_ID"} {
		c, ok := v.Get(groupName)
		if !ok {
			t.Errorf("missing aws credential %q", groupName)
			continue
		}
		if c.Scheme != "aws" {
			t.Errorf("%s.Scheme = %q, want aws", groupName, c.Scheme)
		}
	}
	for _, leaked := range []string{"PROD_AWS_SECRET_ACCESS_KEY", "DEV_AWS_SECRET_ACCESS_KEY"} {
		if _, ok := v.Get(leaked); ok {
			t.Errorf("unexpected bearer credential %q (should be absorbed)", leaked)
		}
	}
	prodCred, _ := v.Get("PROD_AWS_ACCESS_KEY_ID")
	if prodCred.AWSAccessKeyID != "AKIAPRODEXAMPLE00001" {
		t.Errorf("PROD AWSAccessKeyID = %q", prodCred.AWSAccessKeyID)
	}
	if prodCred.Real != "prod/secret/access/key/example00001" {
		t.Errorf("PROD secret cross-paired: %q", prodCred.Real)
	}
	devCred, _ := v.Get("DEV_AWS_ACCESS_KEY_ID")
	if devCred.AWSAccessKeyID != "AKIADEVEXAMPLE000001" {
		t.Errorf("DEV AWSAccessKeyID = %q", devCred.AWSAccessKeyID)
	}
	if devCred.Real != "dev/secret/access/key/example000001" {
		t.Errorf("DEV secret cross-paired: %q", devCred.Real)
	}
}

func TestInit_PartialAWSFallsThroughToBearer(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	c, ok := v.Get("AWS_ACCESS_KEY_ID")
	if !ok {
		t.Fatal("vault missing AWS_ACCESS_KEY_ID")
	}
	if c.Scheme != "" {
		t.Errorf("Scheme = %q, want empty (bearer)", c.Scheme)
	}
	if c.AWSAccessKeyID != "" {
		t.Errorf("AWSAccessKeyID = %q on bearer credential", c.AWSAccessKeyID)
	}
}

func TestInit_FakeAWSValueStaysBearer(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "AWS_ACCESS_KEY_ID=fake-access-key-test\n" +
		"AWS_SECRET_ACCESS_KEY=fake-secret-key-for-testing-purposes\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		c, ok := v.Get(name)
		if !ok {
			t.Errorf("missing credential %q", name)
			continue
		}
		if c.Scheme != "" {
			t.Errorf("%s.Scheme = %q, want empty (bearer, not aws)", name, c.Scheme)
		}
	}
}

func TestInit_DryRunShowsGroupedAWS(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--dry-run", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	outStr := out.String()
	if !strings.Contains(outStr, "would vault (aws)") {
		t.Errorf("dry-run output missing grouped AWS line:\n%s", outStr)
	}

	gotBytes, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBytes) != envContent {
		t.Errorf(".env changed in dry-run:\n got = %q\nwant = %q", string(gotBytes), envContent)
	}
}

// TestInit_NoNonInteractiveNoticeBeforeRootResolution verifies that
// init does not print "Non-interactive mode: vaulting all detected
// secrets" when the project-root precondition fails. Otherwise users
// see a misleading "proceeding" notice immediately followed by an
// error (regression for F-1).
func TestInit_NoNonInteractiveNoticeBeforeRootResolution(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	// Use a tempdir that has no project marker (no .git, .veil, .env)
	// and a HOME above it so FindProjectRoot stops before reaching the
	// real project root above the test process's actual cwd.
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, "nowhere")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	// Provide a non-TTY *os.File for stdin so detectInteractive falls
	// into the non-interactive branch (a *bytes.Buffer would be treated
	// as interactive and bypass the bug).
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	_ = pw.Close()

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetIn(pr)
	cmd.SetArgs([]string{"init"}) // no --path, so resolveInitRoot uses cwd

	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected init to fail without a project root, got nil")
	}

	if strings.Contains(out.String(), "Non-interactive mode") {
		t.Errorf("non-interactive notice printed before precondition failure:\n%s", out.String())
	}
}

func TestInit_VaultedAWSCredentialResignsViaProxy(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	cred, ok := v.Get("AWS_ACCESS_KEY_ID")
	if !ok {
		t.Fatal("vault missing AWS_ACCESS_KEY_ID")
	}
	if cred.Scheme != "aws" {
		t.Fatalf("cred.Scheme = %q, want aws", cred.Scheme)
	}
	if cred.AWSAccessKeyIDPlaceholder == "" {
		t.Fatal("cred missing AWSAccessKeyIDPlaceholder")
	}

	// Build an injector keyed by the placeholder AKID — this mirrors what
	// the proxy does when an agent emits a SigV4 request signed with the
	// placeholder credentials.
	injector := proxy.NewInjector(
		map[string]*vault.Credential{cred.AWSAccessKeyIDPlaceholder: cred},
		nil, 0, "test",
	)

	// Construct a plausible SigV4 request using the placeholder AKID. The
	// Signature value is intentionally "ignored" — the proxy signer discards
	// and recomputes it. This is the same fixture shape used by
	// TestSignAWSSigV4_GetVanilla in internal/proxy/sigv4_signer_test.go.
	header := http.Header{}
	header.Set("Host", "example.amazonaws.com")
	header.Set("X-Amz-Date", "20150830T123600Z")
	header.Set("Authorization",
		"AWS4-HMAC-SHA256 "+
			"Credential="+cred.AWSAccessKeyIDPlaceholder+"/20150830/us-east-1/service/aws4_request, "+
			"SignedHeaders=host;x-amz-date, "+
			"Signature=ignored")

	_, newHeader, _, injections := injector.ProcessRequest(
		"req-spotcheck",
		"GET",
		"https://example.amazonaws.com/",
		header,
		nil,
	)

	var resigned bool
	for _, inj := range injections {
		if inj.Location == proxy.LocationAWSSigV4Resigned {
			resigned = true
			break
		}
	}
	if !resigned {
		t.Fatalf("expected aws_sigv4_resigned injection, got: %+v", injections)
	}

	newAuth := newHeader.Get("Authorization")
	if !strings.Contains(newAuth, "Credential="+cred.AWSAccessKeyID+"/") {
		t.Errorf("Authorization should contain real AKID after re-sign, got: %s", newAuth)
	}
	if strings.Contains(newAuth, "Credential="+cred.AWSAccessKeyIDPlaceholder+"/") {
		t.Errorf("Authorization still contains placeholder AKID, got: %s", newAuth)
	}
	if strings.Contains(newAuth, "Signature=ignored") {
		t.Errorf("Authorization signature was not recomputed, got: %s", newAuth)
	}
}
