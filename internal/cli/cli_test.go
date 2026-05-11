package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/skiphost"
)

// initProject sets up a temporary directory with .git, .env, and runs veil init.
// It returns the project root path.
func initProject(t *testing.T) string {
	t.Helper()
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	// Shell-env scanning would otherwise pull secret-like vars (e.g. CLAUDE_*)
	// from the test runner's environment into the vault, inflating the
	// credential count in tests that assert on exact totals.
	clearShellEnvTestNoise(t)

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
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
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

// TestList_MutuallyExclusiveFlagsError is the F-8 regression at the cobra
// boundary. The cobra error must (1) be returned to the caller and (2) name
// both flags so cmd/veil/main.go can surface it. Errors that exit run() with
// IsAlreadyPrinted == false are the ones that get printed; cobra-internal
// validation errors fall in that bucket.
func TestList_MutuallyExclusiveFlagsError(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"list", "--path", root, "--placeholder", "--reveal", "--yes"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for --placeholder + --reveal")
	}
	msg := err.Error()
	for _, want := range []string{"placeholder", "reveal", "none of the others"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
	if IsAlreadyPrinted(err) {
		t.Error("cobra-internal flag-group error should not be marked as already printed")
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

func TestAddHostResolution(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "sk-test-1234567890abcdef", "--host", "api.custom.com", "MY_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add with --host failed: %v", err)
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	cred, ok := v.Get("MY_KEY")
	if !ok {
		t.Fatal("MY_KEY not found in vault")
	}
	if len(cred.AllowedHosts) != 1 || cred.AllowedHosts[0] != "api.custom.com" {
		t.Errorf("expected [api.custom.com], got %v", cred.AllowedHosts)
	}
}

func TestAddAutoDetectsHosts(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234", "GITHUB_TOKEN"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	cred, ok := v.Get("GITHUB_TOKEN")
	if !ok {
		t.Fatal("GITHUB_TOKEN not found in vault")
	}
	if len(cred.AllowedHosts) == 0 {
		t.Error("expected auto-detected hosts, got none")
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

// --- Audit log filter tests ---

func TestLogWithFilters(t *testing.T) {
	root := initProject(t)

	// Seed audit records directly via the audit store.
	auditDBPath := filepath.Join(root, ".veil", "audit.sqlite")
	store, err := audit.Open(auditDBPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}

	now := time.Now()
	store.Record(audit.Injection{
		Timestamp:      now.Add(-30 * time.Minute),
		RequestID:      "req1",
		Host:           "api.openai.com",
		Method:         "POST",
		URLPath:        "/v1/chat/completions",
		CredentialID:   "cred1",
		CredentialName: "OPENAI_API_KEY",
		AgentPID:       1234,
		AgentCmd:       "testclient",
		BytesBefore:    100,
		BytesAfter:     120,
		Location:       "header",
	})
	store.Record(audit.Injection{
		Timestamp:      now.Add(-10 * time.Minute),
		RequestID:      "req2",
		Host:           "api.github.com",
		Method:         "GET",
		URLPath:        "/repos",
		CredentialID:   "cred2",
		CredentialName: "GITHUB_TOKEN",
		AgentPID:       1234,
		AgentCmd:       "testclient",
		BytesBefore:    50,
		BytesAfter:     80,
		Location:       "header",
	})
	store.Record(audit.Injection{
		Timestamp:      now.Add(-5 * time.Minute),
		RequestID:      "req3",
		Host:           "api.openai.com",
		Method:         "POST",
		URLPath:        "/v1/embeddings",
		CredentialID:   "cred1",
		CredentialName: "OPENAI_API_KEY",
		AgentPID:       1234,
		AgentCmd:       "testclient",
		BytesBefore:    0,
		BytesAfter:     0,
		Location:       "blocked",
	})
	if err := store.Close(); err != nil {
		t.Fatalf("close audit db: %v", err)
	}

	// T-8.6: --host filter
	t.Run("host_filter", func(t *testing.T) {
		cmd := NewRoot("test")
		out := new(bytes.Buffer)
		cmd.SetOut(out)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"log", "--path", root, "--host", "api.github.com"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("log --host failed: %v", err)
		}
		output := out.String()
		if !strings.Contains(output, "GITHUB_TOKEN") {
			t.Error("expected GITHUB_TOKEN in output")
		}
		if strings.Contains(output, "OPENAI_API_KEY") {
			t.Error("OPENAI_API_KEY should be excluded by host filter")
		}
	})

	// T-8.7: --credential filter
	t.Run("credential_filter", func(t *testing.T) {
		cmd := NewRoot("test")
		out := new(bytes.Buffer)
		cmd.SetOut(out)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"log", "--path", root, "--credential", "OPENAI_API_KEY"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("log --credential failed: %v", err)
		}
		output := out.String()
		if !strings.Contains(output, "OPENAI_API_KEY") {
			t.Error("expected OPENAI_API_KEY in output")
		}
		if strings.Contains(output, "GITHUB_TOKEN") {
			t.Error("GITHUB_TOKEN should be excluded by credential filter")
		}
	})

	// T-8.4: --blocked filter
	t.Run("blocked_filter", func(t *testing.T) {
		cmd := NewRoot("test")
		out := new(bytes.Buffer)
		cmd.SetOut(out)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"log", "--path", root, "--blocked"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("log --blocked failed: %v", err)
		}
		output := out.String()
		if !strings.Contains(output, "blocked") {
			t.Error("expected blocked event in output")
		}
	})

	// T-8.8: --limit flag
	t.Run("limit", func(t *testing.T) {
		cmd := NewRoot("test")
		out := new(bytes.Buffer)
		cmd.SetOut(out)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"log", "--path", root, "--blocked", "--limit", "1"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("log --limit failed: %v", err)
		}
		output := out.String()
		// Count data rows (non-header, non-footer lines with actual content).
		lines := strings.Split(strings.TrimSpace(output), "\n")
		dataLines := 0
		for _, line := range lines {
			// Header line contains "TIMESTAMP" and footer starts with spaces or has "events".
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.Contains(trimmed, "TIMESTAMP") || strings.Contains(trimmed, "event") {
				continue
			}
			dataLines++
		}
		if dataLines > 1 {
			t.Errorf("expected at most 1 data row with --limit 1, got %d", dataLines)
		}
	})

	// T-8.3: --json with actual data
	t.Run("json_output", func(t *testing.T) {
		cmd := NewRoot("test")
		out := new(bytes.Buffer)
		cmd.SetOut(out)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"log", "--path", root, "--json", "--blocked"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("log --json failed: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(lines) == 0 || lines[0] == "" {
			t.Fatal("expected at least one JSON line")
		}
		for _, line := range lines {
			var entry map[string]interface{}
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatalf("invalid JSON line: %v\nline: %s", err, line)
			}
			// Validate required fields.
			for _, field := range []string{"timestamp", "host", "method", "credential", "location"} {
				if _, ok := entry[field]; !ok {
					t.Errorf("JSON entry missing field %q: %v", field, entry)
				}
			}
		}
	})

	// T-8.9: Combined filters
	t.Run("combined_filters", func(t *testing.T) {
		cmd := NewRoot("test")
		out := new(bytes.Buffer)
		cmd.SetOut(out)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"log", "--path", root, "--host", "api.openai.com", "--credential", "OPENAI_API_KEY", "--since", "1h", "--limit", "10", "--json", "--blocked"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("combined filter failed: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			var entry map[string]interface{}
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if entry["host"] != "api.openai.com" {
				t.Errorf("host filter not applied: %v", entry["host"])
			}
			if entry["credential"] != "OPENAI_API_KEY" {
				t.Errorf("credential filter not applied: %v", entry["credential"])
			}
		}
	})

	// T-8.10: Invalid --since value
	t.Run("invalid_since", func(t *testing.T) {
		cmd := NewRoot("test")
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"log", "--path", root, "--since", "gibberish"})
		err := cmd.Execute()
		if err == nil {
			t.Fatal("expected error for invalid --since")
		}
		if !strings.Contains(err.Error(), "invalid") {
			t.Errorf("error should mention 'invalid', got: %v", err)
		}
	})
}

// --- First-run and help tests ---

func TestUnknownSubcommand(t *testing.T) {
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	errBuf := new(bytes.Buffer)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{"foobar"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("error should mention 'unknown', got: %v", err)
	}
}

func TestSubcommandHelp(t *testing.T) {
	subcommands := []string{"init", "run", "status", "add", "list", "log", "remove", "skip"}
	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			cmd := NewRoot("test")
			out := new(bytes.Buffer)
			cmd.SetOut(out)
			cmd.SetErr(new(bytes.Buffer))
			cmd.SetArgs([]string{sub, "--help"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("%s --help failed: %v", sub, err)
			}
			if out.Len() == 0 {
				t.Errorf("%s --help produced no output", sub)
			}
		})
	}
}

func TestNoArgsShowsHelp(t *testing.T) {
	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("no-args failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "Available Commands") {
		t.Errorf("expected 'Available Commands' in help output, got: %s", output)
	}
	for _, sub := range []string{"init", "run", "status", "add", "list", "log", "remove", "skip"} {
		if !strings.Contains(output, sub) {
			t.Errorf("help should list %q subcommand", sub)
		}
	}
}

// --- Add/remove edge case tests ---

func TestAddUnscopedWarning(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "some-random-long-value-with-no-provider-match-1234567890", "GENERIC_SECRET"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "No target hosts") {
		t.Errorf("expected unscoped warning, got: %s", output)
	}
}

func TestAddViaPipedStdinNoNewline(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	// Simulate piped input without trailing newline.
	cmd.SetIn(strings.NewReader("my-secret-value-1234567890"))
	cmd.SetArgs([]string{"add", "--path", root, "PIPED_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add with piped stdin failed: %v", err)
	}
	if !strings.Contains(out.String(), "PIPED_KEY") {
		t.Errorf("expected confirmation, got: %s", out.String())
	}

	// Verify it's in the vault.
	v, err := openVault(root)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	cred, found := v.Get("PIPED_KEY")
	if !found {
		t.Fatal("PIPED_KEY not found in vault")
	}
	if cred.Real != "my-secret-value-1234567890" {
		t.Errorf("unexpected value: %s", cred.Real)
	}
}

func TestRemoveCancelled(t *testing.T) {
	root := initProject(t)

	// Add a credential.
	addCmd := NewRoot("test")
	addCmd.SetOut(new(bytes.Buffer))
	addCmd.SetErr(new(bytes.Buffer))
	addCmd.SetIn(strings.NewReader("my-secret-1234567890abc\n"))
	addCmd.SetArgs([]string{"add", "--path", root, "CANCEL_ME"})
	if err := addCmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// Attempt to remove but say "n".
	rmCmd := NewRoot("test")
	rmOut := new(bytes.Buffer)
	rmCmd.SetOut(rmOut)
	rmCmd.SetErr(new(bytes.Buffer))
	rmCmd.SetIn(strings.NewReader("n\n"))
	rmCmd.SetArgs([]string{"remove", "--path", root, "CANCEL_ME"})
	if err := rmCmd.Execute(); err != nil {
		t.Fatalf("remove cancelled should not error: %v", err)
	}
	if !strings.Contains(rmOut.String(), "Cancelled") {
		t.Errorf("expected Cancelled message, got: %s", rmOut.String())
	}

	// Credential should still exist.
	v, err := openVault(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := v.Get("CANCEL_ME"); !found {
		t.Error("CANCEL_ME should still exist after cancelled removal")
	}
}

// --- Init edge case tests ---

func TestInitEmptyEnvFile(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("VEIL_MCP_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.json"))

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init with empty .env should not error: %v", err)
	}
}

func TestInitExportPrefixPreserved(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "export OPENAI_API_KEY=sk-proj-1234567890abcdef\n"
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

	envData, err := os.ReadFile(filepath.Join(tmpDir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	envStr := string(envData)
	if !strings.HasPrefix(envStr, "export OPENAI_API_KEY=") {
		t.Errorf("export prefix should be preserved, got: %s", envStr)
	}
	if strings.Contains(envStr, "sk-proj-1234567890abcdef") {
		t.Error("original value should be replaced")
	}
}

func TestInitQuotedValuesRoundTrip(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "SINGLE='my-very-long-secret-value-1234567890'\nDOUBLE=\"my-very-long-secret-value-0987654321\"\n"
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

	envData, err := os.ReadFile(filepath.Join(tmpDir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	envStr := string(envData)

	// Single-quoted line should still use single quotes.
	for _, line := range strings.Split(envStr, "\n") {
		if strings.HasPrefix(line, "SINGLE=") {
			val := strings.TrimPrefix(line, "SINGLE=")
			if !strings.HasPrefix(val, "'") || !strings.HasSuffix(val, "'") {
				t.Errorf("SINGLE should remain single-quoted, got: %s", line)
			}
		}
		if strings.HasPrefix(line, "DOUBLE=") {
			val := strings.TrimPrefix(line, "DOUBLE=")
			if !strings.HasPrefix(val, "\"") || !strings.HasSuffix(val, "\"") {
				t.Errorf("DOUBLE should remain double-quoted, got: %s", line)
			}
		}
	}
}

func TestInitNoSecretsInOutput(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	secretValue := "sk-proj-supersecretvalue1234567890"
	envContent := "OPENAI_API_KEY=" + secretValue + "\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	cmd.SetOut(outBuf)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{"init", "--path", tmpDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	allOutput := outBuf.String() + errBuf.String()
	if strings.Contains(allOutput, secretValue) {
		t.Error("real secret value should never appear in init output")
	}
}

// --- Scale tests ---

func TestManyCredentials(t *testing.T) {
	root := initProject(t)

	// Add 50 credentials.
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("KEY_%03d", i)
		value := fmt.Sprintf("secret-value-%03d-1234567890abcdefghij", i)
		cmd := NewRoot("test")
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"add", "--path", root, "--value", value, name})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("add %s failed: %v", name, err)
		}
	}

	// List should show all of them plus the initial OPENAI_API_KEY.
	listCmd := NewRoot("test")
	listOut := new(bytes.Buffer)
	listCmd.SetOut(listOut)
	listCmd.SetErr(new(bytes.Buffer))
	listCmd.SetArgs([]string{"list", "--path", root})
	if err := listCmd.Execute(); err != nil {
		t.Fatalf("list failed: %v", err)
	}
	output := listOut.String()
	if !strings.Contains(output, "KEY_000") {
		t.Error("KEY_000 missing from list")
	}
	if !strings.Contains(output, "KEY_049") {
		t.Error("KEY_049 missing from list")
	}
	if !strings.Contains(output, "51 credentials") {
		t.Errorf("expected 51 credentials in footer, got: %s", output)
	}
}

func TestSkipAdd(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"skip", "--path", root, "api.anthropic.com"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("skip add failed: %v", err)
	}

	if !strings.Contains(out.String(), "api.anthropic.com") {
		t.Errorf("expected confirmation output, got %q", out.String())
	}

	hosts, err := skiphost.Load(config.SkipHostsFile(root))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "api.anthropic.com" {
		t.Errorf("expected [api.anthropic.com], got %v", hosts)
	}
}

func TestSkipDuplicate(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"skip", "--path", root, "api.anthropic.com"})
	_ = cmd.Execute()

	cmd2 := NewRoot("test")
	out := new(bytes.Buffer)
	cmd2.SetOut(out)
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"skip", "--path", root, "api.anthropic.com"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("skip duplicate failed: %v", err)
	}

	hosts, _ := skiphost.Load(config.SkipHostsFile(root))
	if len(hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(hosts))
	}
}

func TestSkipList(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"skip", "--path", root, "api.anthropic.com"})
	_ = cmd.Execute()

	cmd2 := NewRoot("test")
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"skip", "--path", root, "*.internal.com"})
	_ = cmd2.Execute()

	cmd3 := NewRoot("test")
	out := new(bytes.Buffer)
	cmd3.SetOut(out)
	cmd3.SetErr(new(bytes.Buffer))
	cmd3.SetArgs([]string{"skip", "--path", root, "--list"})
	if err := cmd3.Execute(); err != nil {
		t.Fatalf("skip list failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "api.anthropic.com") || !strings.Contains(output, "*.internal.com") {
		t.Errorf("expected both hosts in output, got %q", output)
	}
}

func TestSkipRemove(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"skip", "--path", root, "api.anthropic.com"})
	_ = cmd.Execute()

	cmd2 := NewRoot("test")
	out := new(bytes.Buffer)
	cmd2.SetOut(out)
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"skip", "--path", root, "--remove", "api.anthropic.com"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("skip remove failed: %v", err)
	}

	hosts, _ := skiphost.Load(config.SkipHostsFile(root))
	if len(hosts) != 0 {
		t.Errorf("expected empty list, got %v", hosts)
	}
}

func TestSkipRemoveNotFound(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"skip", "--path", root, "--remove", "not.there.com"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for removing nonexistent host")
	}
}

func TestAddWithUserFlag(t *testing.T) {
	root := initProject(t)

	addCmd := NewRoot("test")
	addOut := new(bytes.Buffer)
	addCmd.SetOut(addOut)
	addCmd.SetErr(new(bytes.Buffer))
	addCmd.SetArgs([]string{
		"add", "--path", root, "github-pat",
		"--user", "johndoe",
		"--host", "github.com",
		"--value", "ghp_realtoken",
	})
	if err := addCmd.Execute(); err != nil {
		t.Fatalf("add: %v\n%s", err, addOut.String())
	}
	out := addOut.String()
	if !strings.Contains(out, "User placeholder:") {
		t.Errorf("output missing user placeholder line:\n%s", out)
	}
	if !strings.Contains(out, "Secret placeholder:") {
		t.Errorf("output missing secret placeholder line:\n%s", out)
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	c, ok := v.Get("github-pat")
	if !ok {
		t.Fatal("credential not stored")
	}
	if c.Username != "johndoe" {
		t.Errorf("Username = %q", c.Username)
	}
	if c.UsernamePlaceholder == "" {
		t.Error("UsernamePlaceholder not set")
	}
	if c.UsernamePlaceholder == c.Placeholder {
		t.Error("UsernamePlaceholder collided with Placeholder")
	}
}

func TestAddRejectsEmptyUser(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "x",
		"--user", "", "--host", "x.test", "--value", "v"})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error for empty --user")
	}
}

func TestAddRejectsUserWithColon(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "x",
		"--user", "bad:user", "--host", "x.test", "--value", "v"})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error for colon in --user")
	}
}

func TestListShowsBasicTag(t *testing.T) {
	root := initProject(t)

	// Add a Basic credential.
	addBasic := NewRoot("test")
	addBasic.SetOut(new(bytes.Buffer))
	addBasic.SetErr(new(bytes.Buffer))
	addBasic.SetArgs([]string{
		"add", "--path", root, "gh-basic",
		"--user", "johndoe", "--host", "github.com", "--value", "ghp_real",
	})
	if err := addBasic.Execute(); err != nil {
		t.Fatalf("add basic: %v", err)
	}

	// Add a bearer credential.
	addBearer := NewRoot("test")
	addBearer.SetOut(new(bytes.Buffer))
	addBearer.SetErr(new(bytes.Buffer))
	addBearer.SetArgs([]string{
		"add", "--path", root, "oa-bearer",
		"--host", "api.openai.com", "--value", "sk-abc",
	})
	if err := addBearer.Execute(); err != nil {
		t.Fatalf("add bearer: %v", err)
	}

	listCmd := NewRoot("test")
	listOut := new(bytes.Buffer)
	listCmd.SetOut(listOut)
	listCmd.SetErr(new(bytes.Buffer))
	listCmd.SetArgs([]string{"list", "--path", root})
	if err := listCmd.Execute(); err != nil {
		t.Fatalf("list: %v\n%s", err, listOut.String())
	}

	out := listOut.String()
	var basicLine, bearerLine string
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "gh-basic") {
			basicLine = ln
		}
		if strings.Contains(ln, "oa-bearer") {
			bearerLine = ln
		}
	}
	if !strings.Contains(basicLine, "(basic)") {
		t.Errorf("basic row missing (basic) tag: %q", basicLine)
	}
	if strings.Contains(bearerLine, "(basic)") {
		t.Errorf("bearer row incorrectly shows (basic): %q", bearerLine)
	}
}

func TestLogShowsSuspectMarker(t *testing.T) {
	root := initProject(t)

	// Insert a suspect row directly into the audit DB.
	dbPath := config.AuditDBFile(root)
	store, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	store.Record(audit.Injection{
		Timestamp:   time.Now(),
		RequestID:   "req-susp-1",
		Host:        "api.example.com",
		Method:      "GET",
		URLPath:     "/x",
		Location:    "mismatch_suspected",
		SuspectFlag: true,
		AuthSignal:  "authorization_header",
	})
	_ = store.Close()

	// Default output should include the suspect row tagged with [!].
	logCmd := NewRoot("test")
	logOut := new(bytes.Buffer)
	logCmd.SetOut(logOut)
	logCmd.SetErr(new(bytes.Buffer))
	logCmd.SetArgs([]string{"log", "--path", root})
	if err := logCmd.Execute(); err != nil {
		t.Fatalf("log: %v\n%s", err, logOut.String())
	}
	if !strings.Contains(logOut.String(), "[!]") {
		t.Errorf("log output missing [!] marker:\n%s", logOut.String())
	}

	// --suspect filter returns only suspect rows.
	suspectCmd := NewRoot("test")
	susOut := new(bytes.Buffer)
	suspectCmd.SetOut(susOut)
	suspectCmd.SetErr(new(bytes.Buffer))
	suspectCmd.SetArgs([]string{"log", "--path", root, "--suspect"})
	if err := suspectCmd.Execute(); err != nil {
		t.Fatalf("log --suspect: %v\n%s", err, susOut.String())
	}
	susText := susOut.String()
	if !strings.Contains(susText, "api.example.com") {
		t.Errorf("--suspect output missing host:\n%s", susText)
	}

	// --json output includes `"suspect":true`.
	jsonCmd := NewRoot("test")
	jsonOut := new(bytes.Buffer)
	jsonCmd.SetOut(jsonOut)
	jsonCmd.SetErr(new(bytes.Buffer))
	jsonCmd.SetArgs([]string{"log", "--path", root, "--json"})
	if err := jsonCmd.Execute(); err != nil {
		t.Fatalf("log --json: %v\n%s", err, jsonOut.String())
	}
	if !strings.Contains(jsonOut.String(), `"suspect":true`) {
		t.Errorf("--json output missing suspect flag:\n%s", jsonOut.String())
	}
}

func TestStatusShowsAuditHealthDegraded(t *testing.T) {
	root := initProject(t)
	dbPath := filepath.Join(root, ".veil", "audit.sqlite")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	sidecar := dbPath + ".health"
	contents := fmt.Sprintf("dropped=7\nlast_error_ms=%d\nlast_error=disk full\n", time.Now().UnixMilli())
	if err := os.WriteFile(sidecar, []byte(contents), 0o600); err != nil {
		t.Fatalf("seed health sidecar: %v", err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"status", "--path", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "Audit subsystem reported issues") {
		t.Errorf("status output missing audit-health warning:\n%s", output)
	}
	if !strings.Contains(output, "7 event(s) dropped") {
		t.Errorf("status output missing dropped count:\n%s", output)
	}
	if !strings.Contains(output, "disk full") {
		t.Errorf("status output missing last error message:\n%s", output)
	}
}
