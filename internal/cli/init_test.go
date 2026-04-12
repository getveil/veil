package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if !strings.Contains(outStr, "Secrets vaulted: 1") {
		t.Errorf("expected 1 secret vaulted, got: %s", outStr)
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
	if !strings.Contains(outStr, "no .env files found") {
		t.Errorf("expected no-env message, got: %s", outStr)
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
