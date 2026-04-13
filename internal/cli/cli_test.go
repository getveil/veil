package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
