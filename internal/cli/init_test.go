package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/skiphost"
	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
)

func TestInitHappyPath(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)

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
	if !strings.Contains(outStr, "Next:") {
		t.Errorf("expected Next: hint in output, got: %s", outStr)
	}
	if !strings.Contains(outStr, "veil run claude") {
		t.Errorf("expected veil run claude hint in output, got: %s", outStr)
	}
	if !strings.Contains(outStr, "veil status") {
		t.Errorf("expected veil status hint in output, got: %s", outStr)
	}
}

func TestInitDryRun(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
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
	pinTestHome(t)
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
	pinTestHome(t)

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
	pinTestHome(t)
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
	pinTestHome(t)
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
	pinTestHome(t)
	resetTestKeystoreForTest(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	// Use a named-provider secret so the vault-eligibility gate lets it through.
	envContent := "GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234\n"
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
	t.Setenv("HOME", t.TempDir())

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
	pinTestHome(t)

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

func TestInitYes_VaultsAll(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
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
	pinTestHome(t)
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
	pinTestHome(t)
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
	pinTestHome(t)
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
	pinTestHome(t)
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
	pinTestHome(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(tmpDir, ".env")
	// "Current" .env is what a stale prior init left: a placeholder, not the
	// real secret. The orphan backup carries the true pre-Veil bytes. The
	// placeholder carries the "VEIL" sentinel inside a ghp_-shaped payload
	// — what a prior Generate would have produced — without the literal
	// substring "placeholder" (which would trip the stub-value pre-gate in
	// placeholder.IsSecretLike and skip the orphan signal).
	if err := os.WriteFile(envPath, []byte("GITHUB_TOKEN=ghp_VEIL_aBcD9876aBcD9876aBcD9876aBcD9876ABCD9876\n"), 0644); err != nil {
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
	pinTestHome(t)

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
	// .gitignore contents (/.veil/, *.veil-backup) are not sensitive, so
	// match the conventional 0644 rather than the tight 0600 used for the
	// vault. A world-unreadable .gitignore confused early E2E testers and
	// diverges from every other repo's convention.
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("created .gitignore should be 0644, got %o", perm)
	}
}

// TestInit_LeavesAWSValuesAlone verifies that AWS credentials in a .env
// file are not vaulted and their cleartext values remain unchanged on
// disk. AWS SigV4 was cut in the v1 launch; AWS_* names get classified as
// unrecognized and skipped. A vaultable provider key (GITHUB_TOKEN) is
// included to prove init still ran end-to-end and produced a non-empty
// vault — without it, an init that does nothing at all would pass.
func TestInit_LeavesAWSValuesAlone(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	envContent := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REDACTD\n" +
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY\n" +
		"AWS_SESSION_TOKEN=FwoGZXIvYXdzEJr//////////wEaDPexample\n" +
		"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789AB\n"
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

	// AWS creds must NOT be vaulted — the AWS provider/correlator were removed.
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		if _, found := v.Get(name); found {
			t.Errorf("unexpected credential %q in vault: AWS is not vaulted post-launch-cut", name)
		}
	}

	// GITHUB_TOKEN proves init actually ran and the vault is non-empty.
	if _, ok := v.Get("GITHUB_TOKEN"); !ok {
		t.Error("vault missing GITHUB_TOKEN (init did not vault any provider key)")
	}

	// AWS values in .env must be unchanged (not replaced with placeholders).
	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	envStr := string(envData)
	for _, real := range []string{
		"AKIAIOSFODNN7REDACTD",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY",
		"FwoGZXIvYXdzEJr//////////wEaDPexample",
	} {
		if !strings.Contains(envStr, real) {
			t.Errorf(".env should still contain original AWS value %q (not vaulted):\n%s", real, envStr)
		}
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
	pinTestHome(t)
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
	pinTestHome(t)

	// External target outside the project — the "safe" location the user
	// deliberately picked to keep secrets out of source control.
	externalDir := t.TempDir()
	target := filepath.Join(externalDir, "secrets")
	originalTarget := "OPENAI_API_KEY=sk-proj-real-secret-ABCDEF1234567890\n"
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

// TestInitRefusesPrePlantedBackupSymlink covers the regression where a
// hostile cloned repo pre-plants `.env.veil-backup` as a symlink pointing
// at e.g. ~/.ssh/authorized_keys. Prior to the writeBackup hardening,
// os.WriteFile followed the symlink and dumped the cleartext .env into
// the attacker-chosen target — the project's .gitignore (which lists
// *.veil-backup) is only updated at the END of init, so the malicious
// symlink isn't filtered out before the destructive write runs.
func TestInitRefusesPrePlantedBackupSymlink(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("HOME", t.TempDir())

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
	envContent := "OPENAI_API_KEY=sk-proj-real-secret-ABCDEF1234567890\n"
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

func TestFilterInputs_NoOpWhenOnlyOneInput(t *testing.T) {
	// With exactly one input, the upfront filter must NOT prompt
	// (matches today's filterInputs short-circuit).
	in := strings.NewReader("")
	out := new(bytes.Buffer)
	envs := filterInputs(in, out, "/tmp/root",
		[]string{"/tmp/root/.env"},
		true,
	)
	if len(envs) != 1 {
		t.Errorf("expected pass-through, got envs=%v", envs)
	}
	if out.Len() > 0 {
		t.Errorf("filterInputs printed unexpectedly: %q", out.String())
	}
}

func TestFilterInputs_NonInteractivePassThrough(t *testing.T) {
	envs := []string{"/tmp/a/.env", "/tmp/b/.env"}
	in := strings.NewReader("")
	out := new(bytes.Buffer)
	gotEnvs := filterInputs(in, out, "/tmp", envs, false)
	if len(gotEnvs) != 2 {
		t.Errorf("non-interactive must pass through: %v", gotEnvs)
	}
}

func TestFilterInputs_AcceptAll(t *testing.T) {
	envs := []string{"/tmp/a/.env", "/tmp/b/.env"}
	in := strings.NewReader("y\n")
	out := new(bytes.Buffer)
	gotEnvs := filterInputs(in, out, "/tmp", envs, true)
	if len(gotEnvs) != 2 {
		t.Errorf("expected accept-all, got %v", gotEnvs)
	}
}

func TestFilterInputs_DeclineDropsAll(t *testing.T) {
	envs := []string{"/tmp/a/.env", "/tmp/b/.env"}
	in := strings.NewReader("n\n")
	out := new(bytes.Buffer)
	gotEnvs := filterInputs(in, out, "/tmp", envs, true)
	if len(gotEnvs) != 0 {
		t.Errorf("decline must drop all, got %v", gotEnvs)
	}
}

func TestInit_DiscoversMonorepoEnvFiles(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("HOME", t.TempDir())

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

// TestInit_DoesNotScanShellEnv verifies that init does NOT pull secret-like
// names from os.Environ() into the vault. The shell-env scanning path was
// cut in the v1 launch (see docs/LAUNCH_CUTS.md Phase 4) — the runner's
// scanUnvaultedSecretLikes warning at `veil run` startup is the only
// remaining surface for shell-exported secrets.
func TestInit_DoesNotScanShellEnv(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	t.Setenv("OPENAI_API_KEY", "sk-proj-shell-1234567890abcdef")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A .env with a different (.env-only) key so init has something to process
	// — we want to reach past the early-exit gate, then assert the shell value
	// was NOT picked up.
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte("HOSTNAME=myserver\nDATABASE_URL=postgres://u:pw@h/db\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v\n%s", err, out.String())
	}

	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	if _, ok := v.Get("OPENAI_API_KEY"); ok {
		t.Errorf("vault has OPENAI_API_KEY; shell-env scanning should be gone (names=%v)", v.Names())
	}

	outStr := out.String()
	for _, forbidden := range []string{"Scanning shell environment", "shell-exported", "from shell"} {
		if strings.Contains(outStr, forbidden) {
			t.Errorf("output mentions %q; shell-env phase should be gone:\n%s", forbidden, outStr)
		}
	}
}

// TestInit_RejectsScanShellEnvFlag verifies the removed --scan-shell-env
// flag is no longer accepted. Cobra returns an "unknown flag" error.
func TestInit_RejectsScanShellEnvFlag(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes", "--scan-shell-env"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from removed --scan-shell-env flag, got nil")
	}
	// Pin the specific flag name so a rename like `--shell-scan` still trips
	// the test instead of passing on any "unknown flag" error.
	if !strings.Contains(err.Error(), "scan-shell-env") {
		t.Errorf("expected 'scan-shell-env' in error, got: %v", err)
	}
}

// TestInit_WarnsWhenPathOutsideCWDProjectRoot verifies that when --path points
// at a directory outside the cwd's project root, the user sees an advisory at
// the end of init explaining how to roll back. Otherwise a user who typo'd a
// path lands with a .veil/ they can't easily find or undo.
func TestInit_WarnsWhenPathOutsideCWDProjectRoot(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("HOME", t.TempDir())

	// The cwd's project root — what FindProjectRoot will land on for ".".
	cwdProject := t.TempDir()
	if err := os.Mkdir(filepath.Join(cwdProject, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwdProject)

	// The OUTSIDE project — has its own .git and .env so init succeeds.
	outsideProject := t.TempDir()
	if err := os.Mkdir(filepath.Join(outsideProject, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(outsideProject, ".env")
	if err := os.WriteFile(envPath, []byte("GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", outsideProject, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --path <outside> failed: %v", err)
	}

	outStr := out.String()
	if !strings.Contains(outStr, "outside the current project root") {
		t.Errorf("expected 'outside the current project root' notice, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "veil uninstall --path") {
		t.Errorf("expected uninstall hint, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, outsideProject) && !strings.Contains(outStr, ui.RedactPath(outsideProject)) {
		t.Errorf("expected the outside path to be mentioned in the notice, got:\n%s", outStr)
	}
}

// TestInit_DoesNotWarnWhenPathInsideCWDProjectRoot verifies that the new
// advisory is suppressed when the --path is a subdirectory of the cwd
// project root — that's a perfectly reasonable monorepo workflow and
// emitting the notice would be noise.
func TestInit_DoesNotWarnWhenPathInsideCWDProjectRoot(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("HOME", t.TempDir())

	cwdProject := t.TempDir()
	if err := os.Mkdir(filepath.Join(cwdProject, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwdProject)

	// Subdirectory inside the cwd project.
	sub := filepath.Join(cwdProject, "apps", "api")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, ".env"), []byte("GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", sub, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --path <subdir> failed: %v", err)
	}
	if strings.Contains(out.String(), "outside the current project root") {
		t.Errorf("must not emit out-of-project notice for a subdirectory, got:\n%s", out.String())
	}
}

// TestInit_DoesNotWarnWhenPathFlagOmitted verifies the advisory is gated on
// the user actually passing --path. With no flag the path resolves from cwd
// and the "outside" comparison would be a tautology.
func TestInit_DoesNotWarnWhenPathFlagOmitted(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("HOME", t.TempDir())

	cwdProject := t.TempDir()
	if err := os.Mkdir(filepath.Join(cwdProject, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwdProject, ".env"), []byte("GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwdProject)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init without --path failed: %v", err)
	}
	if strings.Contains(out.String(), "outside the current project root") {
		t.Errorf("must not emit out-of-project notice without --path, got:\n%s", out.String())
	}
}

// TestAnnounceFileBackedKeystore_WithoutPassphraseErrors verifies that when
// the keystore fell back to FileKeystore AND VEIL_PASSPHRASE is unset, the
// announce helper surfaces a warning and returns a typed error so the caller
// short-circuits before the first vault op (which would have produced an
// opaque ErrKeystoreUnavailable instead).
func TestAnnounceFileBackedKeystore_WithoutPassphraseErrors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VEIL_PASSPHRASE", "")

	fallback := filepath.Join(t.TempDir(), "master.key.age")
	ks := vault.NewFileKeystore(fallback)
	var buf bytes.Buffer
	err := announceFileBackedKeystore(&buf, ks)
	if err == nil {
		t.Fatal("expected announceFileBackedKeystore to error when passphrase is unset")
	}
	if !errors.Is(err, vault.ErrKeystoreUnavailable) {
		t.Errorf("expected wrapped ErrKeystoreUnavailable, got: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No system keyring found") {
		t.Errorf("warning should mention 'No system keyring found', got:\n%s", out)
	}
	if !strings.Contains(out, "VEIL_PASSPHRASE") {
		t.Errorf("warning should mention VEIL_PASSPHRASE, got:\n%s", out)
	}
}

// TestAnnounceFileBackedKeystore_WithPassphraseInfoOnly verifies that when
// the keystore is file-backed AND VEIL_PASSPHRASE is set, the helper prints
// an informational note (so the user knows they're in file-backed mode) but
// does not return an error.
func TestAnnounceFileBackedKeystore_WithPassphraseInfoOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VEIL_PASSPHRASE", "hunter2")

	fallback := filepath.Join(t.TempDir(), "master.key.age")
	ks := vault.NewFileKeystore(fallback)
	var buf bytes.Buffer
	if err := announceFileBackedKeystore(&buf, ks); err != nil {
		t.Fatalf("announceFileBackedKeystore with passphrase set: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Using file-backed keystore") {
		t.Errorf("expected info note about file-backed mode, got:\n%s", out)
	}
	if strings.Contains(out, "No system keyring found") {
		t.Errorf("must not surface the unset-passphrase warning when passphrase IS set, got:\n%s", out)
	}
}

// TestAnnounceFileBackedKeystore_NonFileNoOp verifies that for the happy-path
// system-keyring keystore the helper prints nothing and returns nil.
func TestAnnounceFileBackedKeystore_NonFileNoOp(t *testing.T) {
	ks := vault.NewMemKeystore()
	var buf bytes.Buffer
	if err := announceFileBackedKeystore(&buf, ks); err != nil {
		t.Fatalf("announce should no-op for non-file keystore: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("announce should print nothing for non-file keystore, got: %q", buf.String())
	}
}
