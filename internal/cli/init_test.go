package cli

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/mcpconfig"
	"github.com/getveil/veil/internal/proxy"
	"github.com/getveil/veil/internal/skiphost"
	"github.com/getveil/veil/internal/vault"
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
	resetTestKeystoreForTest(t)

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
	cmd.SetArgs([]string{"init", "--dry-run", "--yes", "--path", tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --dry-run failed: %v", err)
	}

	// F-3 regression: dry-run must not write any project state.
	stateDir := filepath.Join(tmpDir, ".veil")
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Errorf(".veil/ should not exist after --dry-run, stat err: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "vault.meta")); !os.IsNotExist(err) {
		t.Errorf("vault.meta should not exist after --dry-run, stat err: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "vault.bin")); !os.IsNotExist(err) {
		t.Errorf("vault.bin should not exist after --dry-run, stat err: %v", err)
	}

	// F-3 regression: dry-run must not write to the keystore.
	if entries := snapshotTestKeystore(t); len(entries) != 0 {
		t.Errorf("keystore should be empty after --dry-run, got %d entries: %v", len(entries), entries)
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

// TestInitDryRun_SummaryQualified verifies the dry-run summary lines all carry
// a "would …" qualifier and do not claim that secrets were "stored" or that
// Veil was "initialized." Without this, a user inspecting only the summary
// would conclude that --dry-run had vaulted secrets when nothing changed.
func TestInitDryRun_SummaryQualified(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	resetTestKeystoreForTest(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "OPENAI_API_KEY=sk-proj-1234567890abcdef\n"
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--dry-run", "--yes", "--path", tmpDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --dry-run failed: %v", err)
	}

	outStr := out.String()

	// Forbidden phrases — these would mislead a user reading the summary.
	forbidden := []string{
		"secret stored in keychain",
		"secrets stored in keychain",
		"Veil initialized for",
	}
	for _, p := range forbidden {
		if strings.Contains(outStr, p) {
			t.Errorf("dry-run output must not contain %q (implies real action). Got:\n%s", p, outStr)
		}
	}

	// Required qualifier phrases — confirm the summary is honest.
	required := []string{
		"would store",
		"Dry-run preview for",
		"would be vaulted",
	}
	for _, p := range required {
		if !strings.Contains(outStr, p) {
			t.Errorf("dry-run output missing %q. Got:\n%s", p, outStr)
		}
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

// TestInitReinitDoesNotOrphanKeystoreEntries is the F-15 regression. After a
// successful init, a second init (without --force) must fail before creating
// any new keystore entry so the keystore still holds exactly one master-key
// entry for the project.
func TestInitReinitDoesNotOrphanKeystoreEntries(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	resetTestKeystoreForTest(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "SECRET_KEY=super-secret-value-1234567890abcdef\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd1 := NewRoot("test")
	cmd1.SetOut(new(bytes.Buffer))
	cmd1.SetErr(new(bytes.Buffer))
	cmd1.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init failed: %v", err)
	}
	afterFirst := snapshotTestKeystore(t)
	if len(afterFirst) != 1 {
		t.Fatalf("expected exactly 1 keystore entry after first init, got %d: %v", len(afterFirst), afterFirst)
	}

	// Second init without --force should fail (project already initialized)
	// and must not create a new keystore entry.
	cmd2 := NewRoot("test")
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd2.Execute(); err == nil {
		t.Fatal("expected second init to fail with 'already initialized'")
	}

	afterSecond := snapshotTestKeystore(t)
	if len(afterSecond) != 1 {
		t.Errorf("expected exactly 1 keystore entry after re-init attempt, got %d: %v",
			len(afterSecond), afterSecond)
	}
	if afterSecond[0] != afterFirst[0] {
		t.Errorf("keystore entry changed across re-init attempt: was %q, now %q",
			afterFirst[0], afterSecond[0])
	}
}

// TestInitForceCleansPriorKeystoreEntry verifies that an init --force run
// deletes the previous projectID's master-key entry from the keystore, so
// only the new entry remains. Without this cleanup, every --force would
// leak an orphan entry (F-15).
func TestInitForceCleansPriorKeystoreEntry(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	resetTestKeystoreForTest(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "SECRET_KEY=super-secret-value-1234567890abcdef\n"
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd1 := NewRoot("test")
	cmd1.SetOut(new(bytes.Buffer))
	cmd1.SetErr(new(bytes.Buffer))
	cmd1.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init failed: %v", err)
	}
	afterFirst := snapshotTestKeystore(t)
	if len(afterFirst) != 1 {
		t.Fatalf("expected 1 keystore entry after first init, got %d: %v", len(afterFirst), afterFirst)
	}

	// Restore .env content for the second pass to have something to vault.
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd2 := NewRoot("test")
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"init", "--force", "--path", tmpDir, "--yes"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("init --force failed: %v", err)
	}

	afterForce := snapshotTestKeystore(t)
	if len(afterForce) != 1 {
		t.Errorf("expected 1 keystore entry after --force (prior orphan cleaned), got %d: %v",
			len(afterForce), afterForce)
	}
}

// TestUninstallEmptiesKeystoreForProject is the F-15 regression for the
// uninstall path: after uninstall, the keystore must hold no master-key
// entries belonging to this project.
func TestUninstallEmptiesKeystoreForProject(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	resetTestKeystoreForTest(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "SECRET_KEY=super-secret-value-1234567890abcdef\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd1 := NewRoot("test")
	cmd1.SetOut(new(bytes.Buffer))
	cmd1.SetErr(new(bytes.Buffer))
	cmd1.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	if got := snapshotTestKeystore(t); len(got) != 1 {
		t.Fatalf("expected 1 keystore entry after init, got %d: %v", len(got), got)
	}

	cmd2 := NewRoot("test")
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"uninstall", "--path", tmpDir, "--yes"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	if got := snapshotTestKeystore(t); len(got) != 0 {
		t.Errorf("expected keystore empty after uninstall, got %d entries: %v", len(got), got)
	}
}

func TestInitNoEnvFiles(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path
	t.Setenv("HOME", t.TempDir())
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
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path
	t.Setenv("HOME", t.TempDir())

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
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path
	t.Setenv("HOME", t.TempDir())

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
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path
	t.Setenv("HOME", t.TempDir())

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
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path
	t.Setenv("HOME", t.TempDir())

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
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path
	t.Setenv("HOME", t.TempDir())

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

func TestInitMCPReclaimsOrphanedBackup(t *testing.T) {
	// F-12 regression: an orphaned .veil-backup (no entry in vault.meta) means
	// the prior Veil install was uninstalled or its state was wiped. Init must
	// treat that backup as the source of truth and re-vault from it, rather
	// than silently skipping (which would yield fewer secrets in the vault than
	// the user expected).
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path
	t.Setenv("HOME", t.TempDir())

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("HOSTNAME=myserver\n"), 0644); err != nil {
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
	// The "current" file is what a stale prior init left behind: placeholders
	// instead of real values. The backup carries the real pre-Veil bytes.
	staleCurrent := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "env": {
        "GITHUB_TOKEN": "ghp_VEIL_oldplaceholder"
      }
    }
  }
}`
	mcpConfigPath := filepath.Join(mcpDir, "claude_desktop_config.json")
	if err := os.WriteFile(mcpConfigPath, []byte(staleCurrent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mcpConfigPath+".veil-backup", []byte(originalContent), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_MCP_CONFIG_PATH", mcpConfigPath)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init with orphan backup failed: %v", err)
	}

	if !strings.Contains(errBuf.String(), "orphaned backup") {
		t.Errorf("expected 'orphaned backup' notice on stderr, got: %s", errBuf.String())
	}

	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	cred, ok := v.Get("mcp:github:GITHUB_TOKEN")
	if !ok {
		t.Fatal("GITHUB_TOKEN not vaulted; orphan reclaim should have re-vaulted from backup")
	}
	if cred.Real != "ghp_test1234567890abcdef1234567890abcdef" {
		t.Errorf("vaulted real value should come from the backup; got %q", cred.Real)
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
	envContent := []byte("OPENAI_API_KEY=sk-proj-1234567890abcdef\n")
	envPath := filepath.Join(dir, ".env")
	_ = os.WriteFile(envPath, envContent, 0644)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", dir, "--yes"})
	_ = cmd.Execute()

	// Restore the original .env so the --force re-init has the real secret
	// to re-vault. Without this, init now refuses to re-vault the placeholder-
	// laden .env to prevent the data-loss bug regressed by
	// TestInitForce_PreservesOriginalSecretsWhenEnvAlreadyVaulted.
	if err := os.WriteFile(envPath, envContent, 0644); err != nil {
		t.Fatal(err)
	}

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
	cred, ok := v.Get("OPENAI_API_KEY")
	if !ok {
		t.Fatal("OPENAI_API_KEY missing from vault after --force")
	}
	if cred.Real != "sk-proj-1234567890abcdef" {
		t.Fatalf("--force re-vault did not preserve real value: got %q", cred.Real)
	}
}

func TestInitEnvReclaimsOrphanedBackup(t *testing.T) {
	// F-12 regression: an orphaned .env.veil-backup (no entry in vault.meta)
	// means a prior Veil install was uninstalled (or its state was wiped) but
	// the backup was left behind. Init must restore from the backup and re-
	// vault rather than silently skipping (which would leave the placeholder
	// in .env unvaulted on the second pass).
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(tmpDir, ".env")
	// "Current" .env is what a stale prior init left: a placeholder, not the
	// real secret. The orphan backup carries the true pre-Veil bytes.
	if err := os.WriteFile(envPath, []byte("GITHUB_TOKEN=ghp_VEIL_oldplaceholder\n"), 0644); err != nil {
		t.Fatal(err)
	}
	original := []byte("GITHUB_TOKEN=ghp_real1234567890abcdef1234567890abcdef\n")
	if err := os.WriteFile(envPath+".veil-backup", original, 0600); err != nil {
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

	if !strings.Contains(stderr.String(), "orphaned backup") {
		t.Errorf("expected 'orphaned backup' notice on stderr, got: %s", stderr.String())
	}

	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	cred, ok := v.Get("GITHUB_TOKEN")
	if !ok {
		t.Fatal("GITHUB_TOKEN not vaulted; orphan reclaim should have re-vaulted from backup")
	}
	if cred.Real != "ghp_real1234567890abcdef1234567890abcdef" {
		t.Errorf("vaulted real value should come from the backup; got %q", cred.Real)
	}

	// New backup must contain the original (pre-Veil) bytes.
	newBackup, err := os.ReadFile(envPath + ".veil-backup")
	if err != nil {
		t.Fatalf("backup not created: %v", err)
	}
	if string(newBackup) != string(original) {
		t.Errorf("new backup should match original\ngot:  %q\nwant: %q", newBackup, original)
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

	appendGitignore(io.Discard, dir)

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

	appendGitignore(io.Discard, dir)

	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != initial {
		t.Errorf("expected .gitignore unchanged, got: %q", data)
	}
}

// When .gitignore is missing, appendGitignore must create one so the cleartext
// .env.veil-backup sidecar — written earlier in init — isn't picked up by
// `git add .` and committed.
func TestAppendGitignoreCreatesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	gitignorePath := filepath.Join(dir, ".gitignore")

	appendGitignore(io.Discard, dir)

	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatalf("appendGitignore should create .gitignore when absent: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "/.veil/") {
		t.Errorf("created .gitignore should contain /.veil/, got: %q", content)
	}
	if !strings.Contains(content, "*.veil-backup") {
		t.Errorf("created .gitignore should contain *.veil-backup, got: %q", content)
	}
	info, err := os.Lstat(gitignorePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("created .gitignore must not be a symlink")
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("created .gitignore should be 0600, got %o", perm)
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
	defer func() { _ = pr.Close() }()
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

// TestInitForce_PreservesOriginalSecretsWhenEnvAlreadyVaulted is the regression
// for the data-loss bug where `veil init --force` re-scanned a .env that already
// contained Veil placeholders, treated the placeholders as fresh secrets
// (they bear valid provider prefixes and pass length/charset/entropy checks),
// and wrote them as the new "real" values into both .env.veil-backup and the
// keystore — destroying every copy of the user's original secrets that Veil
// controlled. The fix refuses to vault values that carry the placeholder
// sentinel and surfaces an actionable error instead.
func TestInitForce_PreservesOriginalSecretsWhenEnvAlreadyVaulted(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	resetTestKeystoreForTest(t)

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	originalSecret := "ghp_5KsHJk2lQmN8pR4tWxY7zA1bC3dE5fG7hI9j"
	originalEnv := []byte("GITHUB_TOKEN=" + originalSecret + "\n")
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, originalEnv, 0644); err != nil {
		t.Fatal(err)
	}

	// First init: vaults the real secret normally.
	cmd1 := NewRoot("test")
	cmd1.SetOut(new(bytes.Buffer))
	cmd1.SetErr(new(bytes.Buffer))
	cmd1.SetArgs([]string{"init", "--path", dir, "--yes"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init failed: %v", err)
	}

	v1, err := openVault(dir)
	if err != nil {
		t.Fatalf("openVault after first init: %v", err)
	}
	cred1, ok := v1.Get("GITHUB_TOKEN")
	if !ok {
		t.Fatal("first init did not vault GITHUB_TOKEN")
	}
	if cred1.Real != originalSecret {
		t.Fatalf("first init lost real secret: got %q, want %q", cred1.Real, originalSecret)
	}
	backupPath := envPath + ".veil-backup"
	backupBefore, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("reading backup after first init: %v", err)
	}
	if string(backupBefore) != string(originalEnv) {
		t.Fatalf("first init backup mismatch:\ngot:  %q\nwant: %q", backupBefore, originalEnv)
	}
	envAfterFirst, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(envAfterFirst), originalSecret) {
		t.Fatal("first init left real secret in .env")
	}

	// Re-run with --force WITHOUT restoring the .env. The .env now contains
	// placeholder values that look real (correct prefix, correct length). The
	// pre-fix code path would re-scan these, classify them as fresh secrets,
	// overwrite the backup with the placeholder-laden .env, and store
	// placeholders as "real" values in a freshly-created vault — wiping the
	// originals from every layer Veil controls.
	cmd2 := NewRoot("test")
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"init", "--path", dir, "--force", "--yes"})
	forceErr := cmd2.Execute()
	if forceErr == nil {
		t.Fatal("expected init --force to refuse re-vaulting placeholder-laden .env, got nil error")
	}

	// The keystore must still hold the original real secret.
	v2, err := openVault(dir)
	if err != nil {
		t.Fatalf("openVault after --force: %v", err)
	}
	cred2, ok := v2.Get("GITHUB_TOKEN")
	if !ok {
		t.Fatal("vault missing GITHUB_TOKEN after --force; originals were destroyed")
	}
	if cred2.Real != originalSecret {
		t.Fatalf("--force destroyed original secret in keystore:\ngot:  %q\nwant: %q", cred2.Real, originalSecret)
	}

	// The backup must still hold the original pre-Veil .env bytes.
	backupAfter, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("reading backup after --force: %v", err)
	}
	if string(backupAfter) != string(originalEnv) {
		t.Fatalf("--force destroyed .env.veil-backup:\ngot:  %q\nwant: %q", backupAfter, originalEnv)
	}
}

// TestInitRefusesSymlinkedEnv covers the regression where a symlinked .env
// (a common defensive pattern: .env -> ~/.config/secrets) gets silently
// broken by init in a way that produces MORE exposure than not running Veil
// at all. With os.Stat in the scanner and os.Rename over the symlink, init
// would: (1) read the target's cleartext, (2) write it to <root>/.env.veil-
// backup INSIDE the project tree, (3) replace the symlink with a placeholder
// file, while (4) leaving the target file unchanged and cleartext. Veil must
// refuse the operation before any destructive step.
func TestInitRefusesSymlinkedEnv(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	// External target outside the project — the "safe" location the user
	// deliberately picked to keep secrets out of source control.
	externalDir := t.TempDir()
	target := filepath.Join(externalDir, "secrets")
	originalTarget := "OPENAI_API_KEY=sk-proj-real-secret-xxxxxxxxxxxx\n"
	if err := os.WriteFile(target, []byte(originalTarget), 0o600); err != nil {
		t.Fatal(err)
	}

	projectDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projectDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(projectDir, ".env")
	if err := os.Symlink(target, envPath); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{"init", "--path", projectDir, "--yes"})

	execErr := cmd.Execute()
	if execErr == nil {
		t.Fatal("expected init to refuse symlinked .env, got nil error")
	}

	// The error must mention the symlink so the user understands why.
	if !strings.Contains(execErr.Error(), "symbolic link") {
		t.Errorf("expected error to mention 'symbolic link', got: %v", execErr)
	}

	// .env must still be a symlink (init must not have replaced it).
	info, err := os.Lstat(envPath)
	if err != nil {
		t.Fatalf("Lstat .env: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error(".env was replaced by a regular file — init must not touch a symlinked input")
	}

	// Critical: NO cleartext backup must be materialized in the project tree.
	if _, err := os.Stat(envPath + ".veil-backup"); err == nil {
		data, _ := os.ReadFile(envPath + ".veil-backup")
		t.Errorf(".env.veil-backup must not exist after refusal; found cleartext: %q", data)
	}

	// The target file must be unchanged.
	gotTarget, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(gotTarget) != originalTarget {
		t.Errorf("target file modified after refusal\n got: %q\nwant: %q", gotTarget, originalTarget)
	}

	// No vault state must have been created (refusal precedes vault build).
	if _, err := os.Stat(filepath.Join(projectDir, ".veil")); err == nil {
		t.Error(".veil/ must not be created when init refuses the input")
	}
}

// TestInitVaultsMCPArgsToken covers H2: real MCP configs commonly pass
// credentials via positional args (e.g. `args: ["--token", "ghp_..."]`).
// Before the fix, processMCPConfig only scanned server.Env, so the token
// stayed cleartext in claude_desktop_config.json after veil init.
func TestInitVaultsMCPArgsToken(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path
	t.Setenv("HOME", t.TempDir())

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// .env so init has work to do besides the MCP config.
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("HOSTNAME=myserver\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mcpDir := filepath.Join(tmpDir, "claude-config")
	if err := os.MkdirAll(mcpDir, 0755); err != nil {
		t.Fatal(err)
	}
	originalToken := "ghp_test1234567890abcdef1234567890abcdef"
	mcpContent := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github", "--token", "` + originalToken + `"]
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
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	mcpData, err := os.ReadFile(mcpConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	mcpStr := string(mcpData)
	if strings.Contains(mcpStr, originalToken) {
		t.Errorf("token survived in args; cleartext leaked in MCP config:\n%s", mcpStr)
	}
	// The benign flanking arg must be preserved verbatim.
	if !strings.Contains(mcpStr, `"--token"`) {
		t.Errorf("--token flag arg lost during rewrite:\n%s", mcpStr)
	}

	backupData, err := os.ReadFile(mcpConfigPath + ".veil-backup")
	if err != nil {
		t.Fatalf("backup not created: %v", err)
	}
	if !strings.Contains(string(backupData), originalToken) {
		t.Error("backup should contain the original token")
	}
}

// TestInitVaultsMCPArgsDSN covers the other H2 variant: a postgres-style DSN
// embedded as a positional arg. The existing IsSecretLike already detects
// URL-with-password values, but processMCPConfig never inspected args so the
// DSN (and its embedded password) stayed cleartext after init.
func TestInitVaultsMCPArgsDSN(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path
	t.Setenv("HOME", t.TempDir())

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("HOSTNAME=myserver\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mcpDir := filepath.Join(tmpDir, "claude-config")
	if err := os.MkdirAll(mcpDir, 0755); err != nil {
		t.Fatal(err)
	}
	originalPassword := "s3cret-db-password-xyz"
	originalDSN := "postgres://app_user:" + originalPassword + "@db.internal.example.com:5432/prod"
	mcpContent := `{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres", "` + originalDSN + `"]
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
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	mcpData, err := os.ReadFile(mcpConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	mcpStr := string(mcpData)
	if strings.Contains(mcpStr, originalPassword) {
		t.Errorf("DSN password leaked in MCP config:\n%s", mcpStr)
	}
	// Structural fidelity: the placeholder DSN must still parse back as a
	// postgres URL anchored at the same host so the MCP server still routes.
	if !strings.Contains(mcpStr, "postgres://app_user:") {
		t.Errorf("DSN structure not preserved (username/scheme):\n%s", mcpStr)
	}
	if !strings.Contains(mcpStr, "@db.internal.example.com:5432/prod") {
		t.Errorf("DSN structure not preserved (host/path):\n%s", mcpStr)
	}

	backupData, err := os.ReadFile(mcpConfigPath + ".veil-backup")
	if err != nil {
		t.Fatalf("backup not created: %v", err)
	}
	if !strings.Contains(string(backupData), originalDSN) {
		t.Error("backup should contain the original DSN with the real password")
	}
}

// TestInitSkipsBenignMCPArgs covers the false-positive boundary: non-secret
// args (subcommand strings, low-entropy flag values) must not get vaulted.
// Using empty key for IsSecretLike means args are vaulted only when their
// value alone trips a provider/URL/entropy signal — flag names like
// "--port" don't drag innocent values into the vault.
func TestInitSkipsBenignMCPArgs(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path
	t.Setenv("HOME", t.TempDir())

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("HOSTNAME=myserver\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mcpDir := filepath.Join(tmpDir, "claude-config")
	if err := os.MkdirAll(mcpDir, 0755); err != nil {
		t.Fatal(err)
	}
	mcpContent := `{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/data", "--port", "3306"]
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
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// File must be byte-identical: nothing in the filesystem server's args
	// is secret-shaped, so no .veil-backup should have been written.
	mcpData, err := os.ReadFile(mcpConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(mcpData) != mcpContent {
		t.Errorf("MCP config mutated despite no secret-shaped args:\ngot:  %q\nwant: %q", mcpData, mcpContent)
	}
	if _, err := os.Stat(mcpConfigPath + ".veil-backup"); err == nil {
		t.Error("backup must not be created when there are no MCP secrets")
	}
}

// TestInitForce_RefusesPlaceholderInMCPArgs covers the --force re-vault
// scenario for args. Once init has replaced a real secret in args with a
// sentinel-bearing placeholder, a subsequent --force run must refuse rather
// than overwrite the backup and keystore with the placeholder, which would
// destroy every copy of the original secret Veil controlled.
func TestInitForce_RefusesPlaceholderInMCPArgs(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path
	t.Setenv("HOME", t.TempDir())

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// Need an .env so init proceeds to vault the MCP config; otherwise the
	// "nothing to do" short-circuit may run instead.
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("HOSTNAME=myserver\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mcpDir := filepath.Join(tmpDir, "claude-config")
	if err := os.MkdirAll(mcpDir, 0755); err != nil {
		t.Fatal(err)
	}
	originalToken := "ghp_5KsHJk2lQmN8pR4tWxY7zA1bC3dE5fG7hI9j"
	mcpContent := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github", "--token", "` + originalToken + `"]
    }
  }
}`
	mcpConfigPath := filepath.Join(mcpDir, "claude_desktop_config.json")
	if err := os.WriteFile(mcpConfigPath, []byte(mcpContent), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_MCP_CONFIG_PATH", mcpConfigPath)

	// First init: vaults the token from args.
	cmd1 := NewRoot("test")
	cmd1.SetOut(new(bytes.Buffer))
	cmd1.SetErr(new(bytes.Buffer))
	cmd1.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init failed: %v", err)
	}

	backupPath := mcpConfigPath + ".veil-backup"
	backupBefore, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("first init did not create backup: %v", err)
	}
	if !strings.Contains(string(backupBefore), originalToken) {
		t.Fatalf("first init backup missing original token: %s", backupBefore)
	}

	// Re-run with --force: refusePlaceholderInputs must catch the sentinel
	// in args and abort before the destructive rewrite.
	cmd2 := NewRoot("test")
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"init", "--path", tmpDir, "--force", "--yes"})
	if err := cmd2.Execute(); err == nil {
		t.Fatal("expected --force to refuse re-vaulting placeholder-laden MCP args, got nil error")
	}

	// Backup and the previously-vaulted token must still be intact.
	backupAfter, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("backup gone after --force: %v", err)
	}
	if !bytes.Equal(backupBefore, backupAfter) {
		t.Errorf("--force destroyed backup:\nbefore: %q\nafter:  %q", backupBefore, backupAfter)
	}
}

// TestInitRefusesPrePlantedBackupSymlink covers the regression where a
// hostile cloned repo pre-plants `.env.veil-backup` as a symlink pointing
// at e.g. ~/.ssh/authorized_keys. Prior to the writeBackup hardening,
// os.WriteFile followed the symlink and dumped the cleartext .env into
// the attacker-chosen target — the project's .gitignore (which lists
// *.veil-backup) is only updated at the END of init, so the malicious
// symlink isn't filtered out before the destructive write runs.
func TestInitRefusesPrePlantedBackupSymlink(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VEIL_MCP_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.json"))

	// Stand-in for the attacker's chosen exfiltration target (e.g. ~/.ssh/
	// authorized_keys). Pre-populate it with a known marker so we can prove
	// init did not overwrite it.
	externalDir := t.TempDir()
	exfilTarget := filepath.Join(externalDir, "victim-file")
	originalMarker := "ORIGINAL_CONTENT_MUST_NOT_BE_OVERWRITTEN\n"
	if err := os.WriteFile(exfilTarget, []byte(originalMarker), 0o600); err != nil {
		t.Fatal(err)
	}

	projectDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projectDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(projectDir, ".env")
	envContent := "OPENAI_API_KEY=sk-proj-real-secret-xxxxxxxxxxxx\n"
	if err := os.WriteFile(envPath, []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}
	// The malicious sidecar — exactly what a hostile clone could ship.
	backupPath := envPath + ".veil-backup"
	if err := os.Symlink(exfilTarget, backupPath); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	// --force so the orphan-backup short-circuit doesn't make init bail
	// early; we need it to reach the writeBackup call to exercise the fix.
	cmd.SetArgs([]string{"init", "--path", projectDir, "--yes", "--force"})

	execErr := cmd.Execute()

	// The exfiltration target MUST be untouched regardless of whether init
	// errored or succeeded — this is the load-bearing assertion.
	got, err := os.ReadFile(exfilTarget)
	if err != nil {
		t.Fatalf("read exfil target: %v", err)
	}
	if string(got) != originalMarker {
		t.Fatalf("exfil target was overwritten via symlink follow:\n got:  %q\nwant: %q\ninit err: %v", got, originalMarker, execErr)
	}

	// And init must surface a clear error rather than silently succeeding.
	if execErr == nil {
		t.Fatal("expected init to fail when .env.veil-backup is a pre-existing symlink")
	}
}

// TestReclaimOrphanedBackupRefusesSymlink covers the second half of C2:
// the orphan-recovery path calls os.Rename on .env.veil-backup → .env,
// and rename(2) renames the symlink itself. A pre-planted symlinked
// orphan would have replaced the real .env with a dangling symlink, after
// which subsequent writeBackup / atomicWriteFile would leak or clobber
// the symlink target. The Lstat guard refuses up front.
func TestReclaimOrphanedBackupRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, ".env")
	if err := os.WriteFile(src, []byte("KEY=value"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Symlink the would-be backup to an external file the attacker controls.
	external := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(external, []byte("external"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, src+backupSuffix); err != nil {
		t.Skipf("symlink: %v", err)
	}

	if err := reclaimOrphanedBackup(src); err == nil {
		t.Fatal("expected reclaimOrphanedBackup to refuse a symlinked backup")
	}
	// .env must remain the original regular file — rename must not have
	// replaced it with a symlink.
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error(".env was replaced by a symlink — reclaim must refuse before rename")
	}
}

// TestInitRefusesSymlinkedParentDir covers C3: a parent directory of the
// MCP config that is itself a symlink redirects the leaf write to an
// attacker-controlled location, even though the leaf Lstat passes (Lstat
// follows parent symlinks). The fix walks each parent component from the
// trust anchor down and refuses if any is a symlink.
func TestInitRefusesSymlinkedParentDir(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "") // opt back in: this test exercises the discovery path

	// Build a fake home where the platform-canonical Claude config dir
	// is a symlink to an attacker-chosen directory. We need
	// os.UserHomeDir to return our fake home so mcpconfig.ParentAnchor
	// anchors the walk there, NOT at the developer's real home.
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)

	// Resolve the OS-specific Claude config subpath the same way init's
	// symlink guard does, so the layout matches whatever platform the
	// test is running on (.config/Claude on Linux, Library/Application
	// Support/Claude on macOS).
	anchors, err := mcpconfig.ParentAnchors()
	if err != nil {
		t.Fatalf("ParentAnchors: %v", err)
	}
	var anchor string
	var subpath []string
	for _, pa := range anchors {
		if pa.Client == mcpconfig.ClaudeDesktop {
			anchor = pa.Anchor
			subpath = pa.Subpath
			break
		}
	}
	if anchor == "" || len(subpath) == 0 {
		t.Skip("no canonical Claude config path on this platform")
	}
	if anchor != fakeHome {
		t.Fatalf("ParentAnchor anchor %q != fakeHome %q (HOME override not picked up)", anchor, fakeHome)
	}

	// Materialize all but the last subpath component as real dirs; the
	// last component is the malicious symlink.
	parentDir := filepath.Join(append([]string{fakeHome}, subpath[:len(subpath)-1]...)...)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The malicious redirect: <Claude dir> is a symlink to /tmp/attacker/.
	attackerDir := t.TempDir()
	exfilSentinel := filepath.Join(attackerDir, "claude_desktop_config.json")
	if err := os.WriteFile(exfilSentinel, []byte(`{"mcpServers":{"x":{"command":"x","env":{"OPENAI_API_KEY":"sk-real-secret-xxxxxxxx"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	claudeSymlink := filepath.Join(parentDir, subpath[len(subpath)-1])
	if err := os.Symlink(attackerDir, claudeSymlink); err != nil {
		t.Skipf("symlink: %v", err)
	}

	// Pin discovery to the symlinked-parent path so the test exercises the
	// real discovery code path (not the override hook). The leaf is a
	// regular file at the resolved location, so a leaf-only Lstat passes —
	// the parent-walk is the only line of defense.
	t.Setenv("VEIL_MCP_CONFIG_PATH", "") // ensure default discovery
	// Sanity: discovery sees the leaf via the symlinked parent.
	discovered, err := mcpconfig.Discover()
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	var desktopPath string
	for _, dc := range discovered {
		if dc.Client == mcpconfig.ClaudeDesktop {
			desktopPath = dc.Path
			break
		}
	}
	if desktopPath == "" {
		t.Fatalf("discovery returned no Claude Desktop config — fake home layout is wrong")
	}

	projectDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projectDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Need a vaultable .env so init actually runs the MCP phase.
	envPath := filepath.Join(projectDir, ".env")
	if err := os.WriteFile(envPath, []byte("OPENAI_API_KEY=sk-proj-real-secret-xxxxxxxxxxxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{"init", "--path", projectDir, "--yes"})

	execErr := cmd.Execute()
	if execErr == nil {
		t.Fatal("expected init to refuse symlinked parent dir, got nil error")
	}

	// Critical: no .veil-backup must have been written next to the
	// attacker's file. If it was, the cleartext MCP config has been
	// duplicated into the attacker dir.
	if _, err := os.Stat(exfilSentinel + ".veil-backup"); err == nil {
		t.Errorf("attacker dir received a cleartext .veil-backup: refusal must precede any write")
	}

	// And the attacker's "config" must be unmodified (no placeholder rewrite).
	got, err := os.ReadFile(exfilSentinel)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("sk-real-secret")) {
		t.Errorf("attacker file was rewritten — placeholder substitution leaked through symlinked parent")
	}
}

func TestFilterInputs_NoOpWhenOnlyOneInput(t *testing.T) {
	// With exactly one input total, the upfront filter must NOT prompt
	// (matches today's filterEnvPaths short-circuit).
	in := strings.NewReader("")
	out := new(bytes.Buffer)
	envs, mcps := filterInputs(in, out, "/tmp/root",
		[]string{"/tmp/root/.env"},
		nil,
		true,
	)
	if len(envs) != 1 || len(mcps) != 0 {
		t.Errorf("expected pass-through, got envs=%v mcps=%v", envs, mcps)
	}
	if out.Len() > 0 {
		t.Errorf("filterInputs printed unexpectedly: %q", out.String())
	}
}

func TestFilterInputs_NonInteractivePassThrough(t *testing.T) {
	envs := []string{"/tmp/a/.env", "/tmp/b/.env"}
	mcps := []mcpconfig.DiscoveredConfig{
		{Path: "/tmp/.mcp.json", Client: mcpconfig.ClaudeCode, Scope: mcpconfig.ProjectScope},
	}
	in := strings.NewReader("")
	out := new(bytes.Buffer)
	gotEnvs, gotMCPs := filterInputs(in, out, "/tmp", envs, mcps, false)
	if len(gotEnvs) != 2 || len(gotMCPs) != 1 {
		t.Errorf("non-interactive must pass through: %v / %v", gotEnvs, gotMCPs)
	}
}

func TestFilterInputs_AcceptAll(t *testing.T) {
	envs := []string{"/tmp/a/.env", "/tmp/b/.env"}
	mcps := []mcpconfig.DiscoveredConfig{
		{Path: "/tmp/.mcp.json", Client: mcpconfig.ClaudeCode, Scope: mcpconfig.ProjectScope},
	}
	in := strings.NewReader("y\n")
	out := new(bytes.Buffer)
	gotEnvs, gotMCPs := filterInputs(in, out, "/tmp", envs, mcps, true)
	if len(gotEnvs) != 2 || len(gotMCPs) != 1 {
		t.Errorf("expected accept-all, got %v / %v", gotEnvs, gotMCPs)
	}
}

func TestFilterInputs_DeclineDropsAll(t *testing.T) {
	envs := []string{"/tmp/a/.env", "/tmp/b/.env"}
	mcps := []mcpconfig.DiscoveredConfig{
		{Path: "/tmp/.mcp.json", Client: mcpconfig.ClaudeCode, Scope: mcpconfig.ProjectScope},
	}
	in := strings.NewReader("n\n")
	out := new(bytes.Buffer)
	gotEnvs, gotMCPs := filterInputs(in, out, "/tmp", envs, mcps, true)
	if len(gotEnvs) != 0 || len(gotMCPs) != 0 {
		t.Errorf("decline must drop all, got %v / %v", gotEnvs, gotMCPs)
	}
}

func TestInit_DiscoversMonorepoEnvFiles(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "1")

	root := t.TempDir()

	// Layout:
	//   .env                       (vault)
	//   apps/api/.env              (vault)
	//   packages/db/.env.local     (vault)
	//   apps/web/.env.example      (skip — sample suffix)
	//   apps/web/.gitignore        (excludes web/.env)
	//   apps/web/.env              (skip — gitignored)
	//   node_modules/.env          (skip — baseline)
	writeEnv := func(rel, content string) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeEnv(".env", "GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	writeEnv(filepath.Join("apps", "api", ".env"), "OPENAI_API_KEY=sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	writeEnv(filepath.Join("packages", "db", ".env.local"), "STRIPE_API_KEY=sk_test_aaaaaaaaaaaaaaaaaaaaaaaa\n")
	writeEnv(filepath.Join("apps", "web", ".env.example"), "OPENAI_API_KEY=sk-proj-EXAMPLE\n")
	writeEnv(filepath.Join("apps", "web", ".gitignore"), ".env\n")
	writeEnv(filepath.Join("apps", "web", ".env"), "SECRET=should-be-ignored\n")
	writeEnv(filepath.Join("node_modules", "pkg", ".env"), "X=leaked\n")

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v\n%s", err, out.String())
	}

	// The three real .env files should now contain placeholders.
	for _, rel := range []string{".env", filepath.Join("apps", "api", ".env"), filepath.Join("packages", "db", ".env.local")} {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		if bytes.Contains(data, []byte("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")) ||
			bytes.Contains(data, []byte("sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")) ||
			bytes.Contains(data, []byte("sk_test_aaaaaaaaaaaaaaaaaaaaaaaa")) {
			t.Errorf("%s still contains real secret after init", rel)
		}
	}

	// The skipped files should be untouched.
	for _, rel := range []string{filepath.Join("apps", "web", ".env.example"), filepath.Join("apps", "web", ".env"), filepath.Join("node_modules", "pkg", ".env")} {
		_, err := os.Stat(filepath.Join(root, rel+".veil-backup"))
		if err == nil {
			t.Errorf("%s.veil-backup exists; file should not have been processed", rel)
		}
	}

	// Apps/web/.env still holds its original value.
	data, err := os.ReadFile(filepath.Join(root, "apps", "web", ".env"))
	if err != nil {
		t.Fatalf("reading apps/web/.env: %v", err)
	}
	if !bytes.Contains(data, []byte("should-be-ignored")) {
		t.Errorf("gitignored apps/web/.env was modified: %s", string(data))
	}
}

func TestInit_DiscoversMultipleMCPConfigs(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("VEIL_MCP_CONFIG_PATH", "")
	t.Setenv("VEIL_MCP_DISABLE_DISCOVERY", "")

	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)

	// User-scope: Claude Code at ~/.claude.json.
	claudeCodePath := filepath.Join(fakeHome, ".claude.json")
	mcpJSON := `{"mcpServers":{"gh":{"command":"npx","args":["-y","x"],"env":{"GITHUB_TOKEN":"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}}`
	if err := os.WriteFile(claudeCodePath, []byte(mcpJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	// User-scope: Cursor at ~/.cursor/mcp.json.
	cursorDir := filepath.Join(fakeHome, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cursorPath := filepath.Join(cursorDir, "mcp.json")
	cursorJSON := `{"mcpServers":{"st":{"command":"npx","args":["-y","x"],"env":{"STRIPE_API_KEY":"sk_test_aaaaaaaaaaaaaaaaaaaaaaaa"}}}}`
	if err := os.WriteFile(cursorPath, []byte(cursorJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	// Project-scope: .mcp.json inside the project root.
	root := t.TempDir()
	projectMCPPath := filepath.Join(root, ".mcp.json")
	projectJSON := `{"mcpServers":{"oa":{"command":"npx","args":["-y","x"],"env":{"OPENAI_API_KEY":"sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}}`
	if err := os.WriteFile(projectMCPPath, []byte(projectJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v\n%s", err, out.String())
	}

	for _, p := range []string{claudeCodePath, cursorPath, projectMCPPath} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("reading %s: %v", p, err)
		}
		// None of the original secret values should remain.
		for _, secret := range []string{
			"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"sk_test_aaaaaaaaaaaaaaaaaaaaaaaa",
			"sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		} {
			if bytes.Contains(data, []byte(secret)) {
				t.Errorf("%s still contains secret %q", p, secret)
			}
		}
		// A backup must exist for each.
		if _, err := os.Stat(p + ".veil-backup"); err != nil {
			t.Errorf("missing backup for %s: %v", p, err)
		}
	}
}
