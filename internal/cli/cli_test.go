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

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/envkeys"
	"github.com/getveil/veil/internal/skiphost"
)

// TestMain probes the test-keystore seam: tests in this package set
// VEIL_TEST_KEYSTORE=mem expecting writes to route to an in-memory
// keystore, but the seam is gated behind -tags testkeystore. Without
// that tag the env var is silently ignored and tests fall through to
// the real OS keychain — polluting it (and producing exit-154 errors
// once enough entries accumulate). Fail loud here.
func TestMain(m *testing.M) {
	prev, hadPrev := os.LookupEnv(envkeys.TestKeystoreToggle)
	if err := os.Setenv(envkeys.TestKeystoreToggle, "mem"); err != nil {
		panic(err)
	}
	_, seamActive := MaybeTestKeystoreForTest()
	if hadPrev {
		_ = os.Setenv(envkeys.TestKeystoreToggle, prev)
	} else {
		_ = os.Unsetenv(envkeys.TestKeystoreToggle)
	}
	if !seamActive {
		fmt.Fprintln(os.Stderr,
			"FATAL: internal/cli tests require -tags testkeystore. "+
				"Run via `make test`, not bare `go test`, so tests do not "+
				"write to the real OS keychain.")
		os.Exit(1)
	}

	os.Exit(m.Run())
}

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

// TestLogRequiresInit covers the bug where `veil log` on an uninitialized
// project would silently create .veil/audit.sqlite as a side effect (via
// audit.Open's MkdirAll) and report success. A subsequent `veil run` then
// saw .veil/ and produced the misleading "Cannot decrypt vault. Run veil
// init --force to reinitialize." — recommending a dangerous remedy for a
// vault that never existed.
//
// `veil log` must instead refuse to operate on an uninitialized project,
// matching the behavior of every other state-touching command, and must NOT
// create .veil/ as a side effect of the failure.
func TestLogRequiresInit(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"log", "--path", tmpDir})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for uninitialized project")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("error should mention 'not initialized', got: %v", err)
	}
	if code := ExitCodeFor(err); code != ExitNotInitialized {
		t.Errorf("expected exit code %d (ExitNotInitialized), got %d", ExitNotInitialized, code)
	}
	if _, statErr := os.Stat(filepath.Join(tmpDir, ".veil")); statErr == nil {
		t.Error(".veil/ must not be created as a side effect of `veil log` on an uninitialized project")
	}
}

// TestRunVaultMetaMissing covers the second half of the same bug: even when
// some other code path has created .veil/ without populating vault.meta,
// `veil run` must NOT tell the user to run `veil init --force` — there is no
// vault to lose, and --force would only obscure the real fix. The error must
// route the user to plain `veil init` and exit with ExitNotInitialized so
// scripts can distinguish "uninitialized" from "vault locked".
func TestRunVaultMetaMissing(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	// Simulate the state after `veil log` (pre-fix) ran on this project:
	// .veil/ exists, but no vault.meta or vault.bin.
	if err := os.MkdirAll(filepath.Join(tmpDir, ".veil"), 0700); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	cmd.SetOut(outBuf)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{"run", "--path", tmpDir, "--", "echo", "hi"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when vault.meta is missing")
	}
	combined := outBuf.String() + errBuf.String() + err.Error()
	if !strings.Contains(combined, "not initialized") {
		t.Errorf("error should mention 'not initialized', got:\n%s", combined)
	}
	if strings.Contains(combined, "--force") {
		t.Errorf("error must not recommend `init --force` when there is no vault to lose, got:\n%s", combined)
	}
	if code := ExitCodeFor(err); code != ExitNotInitialized {
		t.Errorf("expected exit code %d (ExitNotInitialized), got %d", ExitNotInitialized, code)
	}
}

// TestVaultCommandsPostUninstall covers F-14: after uninstall (or before
// init), commands that go through withVault must surface a friendly
// "not initialized" message instead of leaking the missing-vault.meta path
// from vault.Open. Each subtest creates a project with no .veil/ and asserts
// the error is friendly, exits non-zero, and never mentions vault.meta or an
// absolute path.
func TestVaultCommandsPostUninstall(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"status", []string{"status"}},
		{"list", []string{"list"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VEIL_TEST_KEYSTORE", "mem")

			tmpDir := t.TempDir()
			if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
				t.Fatal(err)
			}

			cmd := NewRoot("test")
			outBuf := new(bytes.Buffer)
			errBuf := new(bytes.Buffer)
			cmd.SetOut(outBuf)
			cmd.SetErr(errBuf)
			cmd.SetArgs(append(tc.args, "--path", tmpDir))

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected error for uninitialized project, got nil")
			}
			if code := ExitCodeFor(err); code == ExitSuccess {
				t.Errorf("expected non-zero exit code, got %d", code)
			}

			combined := outBuf.String() + errBuf.String() + err.Error()
			if !strings.Contains(combined, "not initialized") {
				t.Errorf("expected 'not initialized' in output, got:\n%s", combined)
			}
			if strings.Contains(combined, "vault.meta") {
				t.Errorf("output should not leak 'vault.meta'; got:\n%s", combined)
			}
			if strings.Contains(combined, tmpDir) {
				t.Errorf("output should not leak the absolute project path %q; got:\n%s", tmpDir, combined)
			}
		})
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

	// T-8.8: --limit flag
	t.Run("limit", func(t *testing.T) {
		cmd := NewRoot("test")
		out := new(bytes.Buffer)
		cmd.SetOut(out)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"log", "--path", root, "--limit", "1"})
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
		cmd.SetArgs([]string{"log", "--path", root, "--json"})
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
		cmd.SetArgs([]string{"log", "--path", root, "--host", "api.openai.com", "--credential", "OPENAI_API_KEY", "--since", "1h", "--limit", "10", "--json"})
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

// Regression: a bare "*" in skip_hosts becomes NO_PROXY=*, which Go's httpproxy
// (and curl/requests) treat as bypass-all — silently disabling Veil for the
// project. The skip command must reject it.
func TestSkipRejectsBareWildcard(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"skip", "--path", root, "*"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected veil skip \"*\" to fail")
	}

	hosts, err := skiphost.Load(config.SkipHostsFile(root))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("expected no hosts persisted, got %v", hosts)
	}
}

// TestStatusShowsLeakCount verifies that when status reports leaks > 0
// the Leaks line appears with the count. The Phase 6 cut removed the
// "Run `veil log --suspect` for details" hint that previously followed
// this line — the count alone is the signal now.
func TestStatusShowsLeakCount(t *testing.T) {
	root := initProject(t)

	// Seed a leaked row so Summary returns leaked > 0.
	store, err := audit.Open(config.AuditDBFile(root))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	store.Record(audit.Injection{
		Timestamp: time.Now(),
		RequestID: "req-leak",
		Host:      "api.example.com",
		Method:    "POST",
		Location:  "leaked",
	})
	store.DrainForTest()
	_ = store.Close()

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"status", "--path", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "Leaks") {
		t.Fatalf("status output missing Leaks line:\n%s", output)
	}
	if strings.Contains(output, "--suspect") {
		t.Errorf("status output must not reference removed --suspect flag:\n%s", output)
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
