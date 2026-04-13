package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8enji/veil/internal/config"
)

// initProject sets up a temporary directory with .git, .env, and runs veil init.
// It returns the project root path.
func initProject(t *testing.T) string {
	t.Helper()
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "OPENAI_API_KEY=sk-proj-1234567890abcdef\n"
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
	return tmpDir
}

func TestRunRequiresInit(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	// Create .git but no .veil/.
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"run", "--path", tmpDir, "--", "echo", "hi"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for uninitialized project")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("error should mention 'not initialized', got: %v", err)
	}
}

func TestAddAndList(t *testing.T) {
	root := initProject(t)

	// Add a secret via stdin.
	addCmd := NewRoot("test")
	addOut := new(bytes.Buffer)
	addCmd.SetOut(addOut)
	addCmd.SetErr(new(bytes.Buffer))
	addCmd.SetIn(strings.NewReader("my-secret-value-123456\n"))
	addCmd.SetArgs([]string{"add", "--path", root, "CUSTOM_SECRET"})

	if err := addCmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	if !strings.Contains(addOut.String(), "CUSTOM_SECRET") {
		t.Errorf("expected confirmation, got: %s", addOut.String())
	}

	// List credentials.
	listCmd := NewRoot("test")
	listOut := new(bytes.Buffer)
	listCmd.SetOut(listOut)
	listCmd.SetErr(new(bytes.Buffer))
	listCmd.SetArgs([]string{"list", "--path", root})

	if err := listCmd.Execute(); err != nil {
		t.Fatalf("list failed: %v", err)
	}
	output := listOut.String()
	if !strings.Contains(output, "CUSTOM_SECRET") {
		t.Errorf("list should contain CUSTOM_SECRET, got: %s", output)
	}
	if !strings.Contains(output, "manual") {
		t.Errorf("list should show source 'manual', got: %s", output)
	}
	if !strings.Contains(output, "OPENAI_API_KEY") {
		t.Errorf("list should contain OPENAI_API_KEY, got: %s", output)
	}
	if strings.Contains(output, "CREATED") {
		t.Errorf("list should not contain CREATED column, got: %s", output)
	}
	if !strings.Contains(output, "credentials") {
		t.Errorf("list should contain footer with 'credentials', got: %s", output)
	}
}

func TestAddForce(t *testing.T) {
	root := initProject(t)

	// Add a secret.
	cmd1 := NewRoot("test")
	cmd1.SetOut(new(bytes.Buffer))
	cmd1.SetErr(new(bytes.Buffer))
	cmd1.SetIn(strings.NewReader("value1\n"))
	cmd1.SetArgs([]string{"add", "--path", root, "MY_KEY"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first add failed: %v", err)
	}

	// Add same key without --force should fail.
	cmd2 := NewRoot("test")
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetIn(strings.NewReader("value2\n"))
	cmd2.SetArgs([]string{"add", "--path", root, "MY_KEY"})
	if err := cmd2.Execute(); err == nil {
		t.Fatal("expected error for duplicate key without --force")
	}

	// Add same key with --force should succeed.
	cmd3 := NewRoot("test")
	cmd3.SetOut(new(bytes.Buffer))
	cmd3.SetErr(new(bytes.Buffer))
	cmd3.SetIn(strings.NewReader("value3\n"))
	cmd3.SetArgs([]string{"add", "--path", root, "--force", "MY_KEY"})
	if err := cmd3.Execute(); err != nil {
		t.Fatalf("add --force failed: %v", err)
	}
}

func TestLogEmpty(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"log", "--path", root})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("log failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "No credential injections") {
		t.Errorf("expected empty log message, got: %s", output)
	}
	if !strings.Contains(output, "proxy was active") {
		t.Errorf("expected proxy-active clarification, got: %s", output)
	}
}

func TestLogJSON(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"log", "--path", root, "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("log --json failed: %v", err)
	}
	// Empty audit, so no JSON output is expected (no error either).
	if out.String() != "" {
		t.Errorf("expected empty JSON output, got: %s", out.String())
	}
}

func TestStatusOutput(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"status", "--path", root})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("status failed: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Credentials") {
		t.Errorf("status should contain 'Credentials', got: %s", output)
	}
	if !strings.Contains(output, "CA") {
		t.Errorf("status should contain 'CA', got: %s", output)
	}
	if !strings.Contains(output, "Veil Status") {
		t.Errorf("status should contain 'Veil Status', got: %s", output)
	}
	if !strings.Contains(output, "Injections") {
		t.Errorf("status should contain 'Injections', got: %s", output)
	}
}

func TestListEmpty(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	// Create .env with no secrets (non-secret-like value).
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("HOSTNAME=myserver\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Init (should vault nothing).
	initCmd := NewRoot("test")
	initCmd.SetOut(new(bytes.Buffer))
	initCmd.SetErr(new(bytes.Buffer))
	initCmd.SetArgs([]string{"init", "--path", tmpDir})
	// This may not produce a vault with 0 creds since init might not create vault
	// if no envs found. Use a project that was initialized.
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Check if .veil exists; if not, this test just validates the no-.env path.
	if _, err := os.Stat(filepath.Join(tmpDir, ".veil")); err != nil {
		t.Skip(".veil not created (no secrets found)")
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"list", "--path", tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list failed: %v", err)
	}
}

func TestColorFlagNoColor(t *testing.T) {
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--no-color", "status", "--path", "/nonexistent"})
	_ = cmd.Execute()
}

func TestRemove(t *testing.T) {
	root := initProject(t)

	// Add a credential.
	addCmd := NewRoot("test")
	addCmd.SetOut(new(bytes.Buffer))
	addCmd.SetErr(new(bytes.Buffer))
	addCmd.SetIn(strings.NewReader("my-secret-value-123456\n"))
	addCmd.SetArgs([]string{"add", "--path", root, "MY_SECRET"})
	if err := addCmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// Remove it.
	rmCmd := NewRoot("test")
	rmOut := new(bytes.Buffer)
	rmCmd.SetOut(rmOut)
	rmCmd.SetErr(new(bytes.Buffer))
	rmCmd.SetArgs([]string{"remove", "--path", root, "--force", "MY_SECRET"})
	if err := rmCmd.Execute(); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if !strings.Contains(rmOut.String(), "Removed MY_SECRET") {
		t.Errorf("expected removal confirmation, got: %s", rmOut.String())
	}

	// Verify it's gone from list.
	listCmd := NewRoot("test")
	listOut := new(bytes.Buffer)
	listCmd.SetOut(listOut)
	listCmd.SetErr(new(bytes.Buffer))
	listCmd.SetArgs([]string{"list", "--path", root})
	if err := listCmd.Execute(); err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if strings.Contains(listOut.String(), "MY_SECRET") {
		t.Error("MY_SECRET should not appear in list after removal")
	}
}

func TestRemoveNonexistent(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"remove", "--path", root, "--force", "NONEXISTENT"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestAddWithValueFlag(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "my-api-key-1234567890", "API_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add --value failed: %v", err)
	}
	if !strings.Contains(out.String(), "API_KEY") {
		t.Errorf("expected confirmation, got: %s", out.String())
	}

	// Verify it's in the vault.
	listCmd := NewRoot("test")
	listOut := new(bytes.Buffer)
	listCmd.SetOut(listOut)
	listCmd.SetErr(new(bytes.Buffer))
	listCmd.SetArgs([]string{"list", "--path", root})
	if err := listCmd.Execute(); err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if !strings.Contains(listOut.String(), "API_KEY") {
		t.Errorf("API_KEY should appear in list, got: %s", listOut.String())
	}
}

func TestAddWithValueFlagEmpty(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "", "API_KEY"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for empty value")
	}
	if !strings.Contains(err.Error(), "no value") {
		t.Errorf("error should mention 'no value', got: %v", err)
	}
}

func TestAddOutputShowsPlaceholderAndHosts(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "ghp_test1234567890abcdef1234567890abcdef", "GITHUB_TOKEN"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	output := out.String()

	// Should show styled success with checkmark.
	if !strings.Contains(output, "✓") {
		t.Errorf("expected checkmark in output, got: %s", output)
	}
	// Should show the placeholder value.
	if !strings.Contains(output, "Placeholder:") {
		t.Errorf("expected placeholder display, got: %s", output)
	}
	// Should show detected hosts.
	if !strings.Contains(output, "api.github.com") {
		t.Errorf("expected auto-detected host in output, got: %s", output)
	}
}

func TestAddForceUpdatesEnvFile(t *testing.T) {
	root := initProject(t)

	// Read the .env to find the existing placeholder for OPENAI_API_KEY.
	envData, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	var oldPlaceholder string
	for _, line := range strings.Split(string(envData), "\n") {
		if strings.HasPrefix(line, "OPENAI_API_KEY=") {
			oldPlaceholder = strings.TrimPrefix(line, "OPENAI_API_KEY=")
			break
		}
	}
	if oldPlaceholder == "" {
		t.Fatal("could not find OPENAI_API_KEY placeholder in .env")
	}

	// Force-replace OPENAI_API_KEY with a new value.
	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--force", "--value", "sk-proj-newkey9876543210fedcba", "OPENAI_API_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add --force failed: %v", err)
	}

	// Read .env again — the old placeholder should be replaced with the new one.
	envData2, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	envStr := string(envData2)
	if strings.Contains(envStr, oldPlaceholder) {
		t.Error("old placeholder should have been replaced in .env")
	}
	if !strings.Contains(envStr, "OPENAI_API_KEY=") {
		t.Error("OPENAI_API_KEY key should still exist in .env")
	}
}

func TestListPlaceholder(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"list", "--path", root, "--placeholder"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("list --placeholder failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "PLACEHOLDER") {
		t.Errorf("expected PLACEHOLDER column header, got: %s", output)
	}
	// The placeholder for OPENAI_API_KEY should start with sk-proj- (format-aware).
	if !strings.Contains(output, "sk-proj-") {
		t.Errorf("expected placeholder value with sk-proj- prefix, got: %s", output)
	}
}

func TestStatusShowsProxyNotRunning(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"status", "--path", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "Proxy") {
		t.Errorf("status should show Proxy line, got: %s", output)
	}
	if !strings.Contains(output, "not running") {
		t.Errorf("status should show 'not running' when proxy is inactive, got: %s", output)
	}
}

func TestRunVaultDecryptError(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	// Create .veil with a corrupted vault.
	veilDir := filepath.Join(tmpDir, ".veil")
	if err := os.MkdirAll(veilDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(veilDir, "vault.meta"), []byte(`{"project_id":"test","version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(veilDir, "vault.bin"), []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"run", "--path", tmpDir, "--", "echo", "hi"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for corrupted vault")
	}
	errStr := err.Error()
	// Should get a user-friendly message, not a raw Go error.
	if !strings.Contains(errStr, "decrypt") && !strings.Contains(errStr, "vault") {
		t.Errorf("error should reference vault/decrypt issue, got: %v", err)
	}
}

func TestVersionOutput(t *testing.T) {
	cmd := NewRoot("0.1.0")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--version failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "veil v0.1.0") {
		t.Errorf("version should contain 'veil v0.1.0', got: %s", output)
	}
}

func TestHelpOutput(t *testing.T) {
	cmd := NewRoot("0.1.0")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--help failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "Quick start") {
		t.Errorf("help should contain 'Quick start' section, got: %s", output)
	}
	if !strings.Contains(output, "veil init") {
		t.Errorf("help should mention 'veil init', got: %s", output)
	}
	if !strings.Contains(output, "veil run") {
		t.Errorf("help should mention 'veil run', got: %s", output)
	}
}

func TestInitGeneratesConfig(t *testing.T) {
	root := initProject(t)

	// Config file should exist after init.
	configPath := filepath.Join(root, ".veil", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config file should exist after init: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "scoping:") {
		t.Error("config should contain scoping section")
	}
	if !strings.Contains(content, "OPENAI_API_KEY") {
		t.Error("config should contain the vaulted credential name")
	}
	if !strings.Contains(content, "api.openai.com") {
		t.Error("config should contain auto-detected host")
	}
}

func TestInitRespectsIgnorePatterns(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create two .env files.
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("API_KEY=sk-proj-1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".env.local"), []byte("LOCAL_KEY=sk-proj-abcdef1234567890\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create .veil dir and config that ignores .env.local.
	veilDir := filepath.Join(tmpDir, ".veil")
	if err := os.MkdirAll(veilDir, 0700); err != nil {
		t.Fatal(err)
	}
	configContent := "ignore:\n  - \".env.local\"\n"
	if err := os.WriteFile(filepath.Join(veilDir, "config.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	output := out.String()
	// Should process 1 .env file (not .env.local).
	if !strings.Contains(output, "1 secret") {
		t.Errorf("expected 1 secret vaulted (ignoring .env.local), got: %s", output)
	}
}

func TestInitRespectsScopingConfig(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("CUSTOM_TOKEN=secret1234567890abc\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Pre-create config with scoping.
	veilDir := filepath.Join(tmpDir, ".veil")
	if err := os.MkdirAll(veilDir, 0700); err != nil {
		t.Fatal(err)
	}
	configContent := "scoping:\n  CUSTOM_TOKEN:\n    - api.custom.com\n    - cdn.custom.com\n"
	if err := os.WriteFile(filepath.Join(veilDir, "config.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Verify the credential got the config-specified hosts.
	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	cred, found := v.Get("CUSTOM_TOKEN")
	if !found {
		t.Fatal("CUSTOM_TOKEN not found in vault")
	}
	if len(cred.AllowedHosts) != 2 {
		t.Fatalf("expected 2 allowed hosts from config, got %d: %v", len(cred.AllowedHosts), cred.AllowedHosts)
	}
	if cred.AllowedHosts[0] != "api.custom.com" {
		t.Errorf("expected first host 'api.custom.com', got %q", cred.AllowedHosts[0])
	}
}

func TestAddRespectsConfigScoping(t *testing.T) {
	root := initProject(t)

	// Write config with scoping for a new credential.
	configPath := filepath.Join(root, ".veil", "config.yaml")
	configContent := "scoping:\n  NEW_TOKEN:\n    - api.newservice.com\n    - cdn.newservice.com\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Add credential without --host flags.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "some-secret-value-123456", "NEW_TOKEN"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// Check vault has config-specified hosts.
	v, err := openVault(root)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	cred, found := v.Get("NEW_TOKEN")
	if !found {
		t.Fatal("NEW_TOKEN not found in vault")
	}
	if len(cred.AllowedHosts) != 2 || cred.AllowedHosts[0] != "api.newservice.com" {
		t.Errorf("expected config hosts, got %v", cred.AllowedHosts)
	}
}

func TestAddHostFlagOverridesConfig(t *testing.T) {
	root := initProject(t)

	// Write config with scoping.
	configPath := filepath.Join(root, ".veil", "config.yaml")
	configContent := "scoping:\n  NEW_TOKEN:\n    - api.config.com\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Add credential with explicit --host flag — should override config.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "some-secret-value-123456", "--host", "api.override.com", "NEW_TOKEN"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	cred, found := v.Get("NEW_TOKEN")
	if !found {
		t.Fatal("NEW_TOKEN not found")
	}
	if len(cred.AllowedHosts) != 1 || cred.AllowedHosts[0] != "api.override.com" {
		t.Errorf("--host flag should override config, got %v", cred.AllowedHosts)
	}
}

func TestCheckConfigDrift_Stale(t *testing.T) {
	cfg := &config.ProjectConfig{
		Scoping: map[string][]string{
			"EXISTS":    {"api.example.com"},
			"STALE_KEY": {"api.stale.com"},
		},
	}
	warnings := checkConfigDrift(cfg, []string{"EXISTS"})

	var foundStale bool
	for _, w := range warnings {
		if strings.Contains(w, "STALE_KEY") && strings.Contains(w, "stale") {
			foundStale = true
		}
	}
	if !foundStale {
		t.Errorf("expected stale warning for STALE_KEY, got: %v", warnings)
	}
}

func TestCheckConfigDrift_Uncovered(t *testing.T) {
	cfg := &config.ProjectConfig{
		Scoping: map[string][]string{
			"COVERED": {"api.example.com"},
		},
	}
	warnings := checkConfigDrift(cfg, []string{"COVERED", "UNCOVERED_KEY"})

	var found bool
	for _, w := range warnings {
		if strings.Contains(w, "UNCOVERED_KEY") && strings.Contains(w, "no scoping") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected uncovered warning for UNCOVERED_KEY, got: %v", warnings)
	}
}

func TestCheckConfigDrift_ZeroCredentials(t *testing.T) {
	cfg := &config.ProjectConfig{
		Scoping: map[string][]string{
			"ANYTHING": {"api.example.com"},
		},
	}
	warnings := checkConfigDrift(cfg, nil)
	if len(warnings) != 0 {
		t.Errorf("zero credentials should suppress drift warnings, got: %v", warnings)
	}
}

func TestCheckConfigDrift_NoDrift(t *testing.T) {
	cfg := &config.ProjectConfig{
		Scoping: map[string][]string{
			"KEY_A": {"api.a.com"},
			"KEY_B": {"api.b.com"},
		},
	}
	warnings := checkConfigDrift(cfg, []string{"KEY_A", "KEY_B"})
	if len(warnings) != 0 {
		t.Errorf("expected no drift, got: %v", warnings)
	}
}

func TestCheckConfigDrift_EmptyScoping(t *testing.T) {
	cfg := &config.ProjectConfig{
		Scoping: map[string][]string{}, // no scoping entries
	}
	// Should NOT warn about uncovered credentials when scoping is empty.
	warnings := checkConfigDrift(cfg, []string{"KEY_A", "KEY_B"})
	if len(warnings) != 0 {
		t.Errorf("expected no warnings when scoping is empty, got: %v", warnings)
	}
}

func TestSyncAddsNewCredential(t *testing.T) {
	root := initProject(t)

	// Add a new credential that won't be in the generated config.
	addCmd := NewRoot("test")
	addCmd.SetOut(new(bytes.Buffer))
	addCmd.SetErr(new(bytes.Buffer))
	addCmd.SetArgs([]string{"add", "--path", root, "--value", "my-new-secret-value-1234", "BRAND_NEW_KEY"})
	if err := addCmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// Run sync.
	syncCmd := NewRoot("test")
	syncOut := new(bytes.Buffer)
	syncCmd.SetOut(syncOut)
	syncCmd.SetErr(new(bytes.Buffer))
	syncCmd.SetArgs([]string{"sync", "--path", root})
	if err := syncCmd.Execute(); err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	output := syncOut.String()
	if !strings.Contains(output, "BRAND_NEW_KEY") {
		t.Errorf("sync should report adding BRAND_NEW_KEY, got: %s", output)
	}

	// Verify config file contains the new credential.
	configData, err := os.ReadFile(filepath.Join(root, ".veil", "config.yaml"))
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	if !strings.Contains(string(configData), "BRAND_NEW_KEY") {
		t.Error("config file should contain BRAND_NEW_KEY after sync")
	}
}

func TestSyncDryRun(t *testing.T) {
	root := initProject(t)

	// Add a credential.
	addCmd := NewRoot("test")
	addCmd.SetOut(new(bytes.Buffer))
	addCmd.SetErr(new(bytes.Buffer))
	addCmd.SetArgs([]string{"add", "--path", root, "--value", "another-secret-value-1234", "DRY_KEY"})
	if err := addCmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// Read config before sync.
	configBefore, err := os.ReadFile(filepath.Join(root, ".veil", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	// Run sync --dry-run.
	syncCmd := NewRoot("test")
	syncOut := new(bytes.Buffer)
	syncCmd.SetOut(syncOut)
	syncCmd.SetErr(new(bytes.Buffer))
	syncCmd.SetArgs([]string{"sync", "--path", root, "--dry-run"})
	if err := syncCmd.Execute(); err != nil {
		t.Fatalf("sync --dry-run failed: %v", err)
	}

	if !strings.Contains(syncOut.String(), "dry run") {
		t.Error("expected dry run notice in output")
	}

	// Config file should be unchanged.
	configAfter, err := os.ReadFile(filepath.Join(root, ".veil", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(configBefore) != string(configAfter) {
		t.Error("config should not change during dry run")
	}
}

func TestSyncNoChanges(t *testing.T) {
	root := initProject(t)

	// Sync immediately after init — should be in sync already.
	syncCmd := NewRoot("test")
	syncOut := new(bytes.Buffer)
	syncCmd.SetOut(syncOut)
	syncCmd.SetErr(new(bytes.Buffer))
	syncCmd.SetArgs([]string{"sync", "--path", root})
	if err := syncCmd.Execute(); err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	if !strings.Contains(syncOut.String(), "in sync") {
		t.Errorf("expected 'in sync' message, got: %s", syncOut.String())
	}
}

func TestParseSince(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"24h", false},
		{"7d", false},
		{"1h30m", false},
		{"2026-01-15T10:30:00Z", false},
		{"invalid", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := parseSince(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSince(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
