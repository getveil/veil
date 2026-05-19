package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/scanner"
	"github.com/getveil/veil/internal/vault"
)

// clearShellEnvTestNoise unsets environment variables that commonly appear
// in CI and developer shells and would otherwise register as shell-exported
// secret-like entries during init (turning on an extra interactive prompt
// that can desynchronize carefully-crafted stdin scripts in older tests).
//
// Tests that care about init's exact prompt sequence or its exact vault
// contents should call this helper so `scanner.ScanEnviron(os.Environ())`
// returns nothing outside the test's explicit t.Setenv() declarations.
func clearShellEnvTestNoise(t *testing.T) {
	t.Helper()
	// Scan the current process env and unset anything secret-like that's
	// outside our denylist, so tests start from a blank slate regardless of
	// what the developer's machine or CI runner happens to export.
	for _, c := range scanner.ScanEnviron(os.Environ()) {
		t.Setenv(c.Name, "")
	}
}

func TestProcessShellEnv_VaultsSecrets(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	tmp := t.TempDir()

	ks, err := buildKeystore()
	if err != nil {
		t.Fatalf("buildKeystore: %v", err)
	}
	v, err := vault.CreateVault(tmp, vault.NewID(), ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	candidates := []scanner.EnvironCandidate{
		{Name: "OPENAI_API_KEY", Value: "sk-proj-abcdefghijklmnopqrst"},
	}
	var out bytes.Buffer

	// Non-interactive path: all candidates are vaulted.
	count, scoped, err := processShellEnv(&out, strings.NewReader(""), v, candidates /*dryRun*/, false /*interactive*/, false)
	if err != nil {
		t.Fatalf("processShellEnv: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	_ = scoped // may be 0 or 1 depending on provider registry — not asserting

	if _, ok := v.Get("OPENAI_API_KEY"); !ok {
		t.Error("vault missing OPENAI_API_KEY after processShellEnv")
	}

	// Ensure the literal keeps TempDir from being unused.
	_ = filepath.Base(tmp)
}

func TestProcessShellEnv_SkipsNamesAlreadyInVault(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	tmp := t.TempDir()

	ks, err := buildKeystore()
	if err != nil {
		t.Fatalf("buildKeystore: %v", err)
	}
	v, err := vault.CreateVault(tmp, vault.NewID(), ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	// Pre-populate vault with OPENAI_API_KEY (simulating a prior .env capture).
	if err := v.Add(&vault.Credential{
		ID:          vault.NewID(),
		Name:        "OPENAI_API_KEY",
		Real:        "sk-from-env-file",
		Placeholder: "VEIL_XXX",
		Source:      "init",
	}); err != nil {
		t.Fatalf("v.Add: %v", err)
	}

	candidates := []scanner.EnvironCandidate{
		{Name: "OPENAI_API_KEY", Value: "sk-from-shell"},
		{Name: "NEW_TOKEN", Value: "tk-highentropy-1234567890xyzxyz"},
	}
	var out bytes.Buffer

	count, _, err := processShellEnv(&out, strings.NewReader(""), v, candidates, false, false)
	if err != nil {
		t.Fatalf("processShellEnv: %v", err)
	}
	// Only NEW_TOKEN should have been added (OPENAI_API_KEY was pre-existing).
	if count != 1 {
		t.Errorf("count = %d, want 1 (skip duplicate)", count)
	}
	// Original vault entry must be untouched (value unchanged).
	c, ok := v.Get("OPENAI_API_KEY")
	if !ok {
		t.Fatal("vault lost OPENAI_API_KEY")
	}
	if c.Real != "sk-from-env-file" {
		t.Errorf("OPENAI_API_KEY value changed: got %q, want sk-from-env-file", c.Real)
	}

	_ = filepath.Base(tmp)
}

func TestInit_CapturesShellEnvSecrets(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)
	// Simulate a user with OPENAI_API_KEY exported in their shell but no .env.
	t.Setenv("OPENAI_API_KEY", "sk-proj-shell-1234567890abcdef")

	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	// --yes = non-interactive; all detected secrets are vaulted by default.
	cmd.SetArgs([]string{"init", "--path", tmp, "--yes", "--scan-shell-env"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v\n%s", err, out.String())
	}

	// Open the vault and confirm OPENAI_API_KEY was captured from the shell.
	ks, err := buildKeystore()
	if err != nil {
		t.Fatalf("buildKeystore: %v", err)
	}
	v, err := vault.Open(tmp, ks)
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	c, ok := v.Get("OPENAI_API_KEY")
	if !ok {
		t.Fatalf("vault missing OPENAI_API_KEY; vault names = %v", v.Names())
	}
	if c.Real != "sk-proj-shell-1234567890abcdef" {
		t.Errorf("vaulted value = %q, want sk-proj-shell-1234567890abcdef", c.Real)
	}
}

// TestInit_ShellOnlyProject verifies that `veil init` still runs the shell-env
// capture phase when a project has NO .env files and NO MCP config. The prior
// early-exit gate returned before reaching that phase, silently defeating SEC-1
// coverage for users whose credentials live exclusively in their shell.
func TestInit_ShellOnlyProject(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)
	t.Setenv("TEST_SHELL_ONLY_API_KEY", "sk-abc-highentropy-1234567890")

	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	// Deliberately no .env files and no MCP config — this project has only
	// the shell-exported secret.

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmp, "--yes", "--scan-shell-env"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v\n%s", err, out.String())
	}

	ks, err := buildKeystore()
	if err != nil {
		t.Fatalf("buildKeystore: %v", err)
	}
	v, err := vault.Open(tmp, ks)
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	c, ok := v.Get("TEST_SHELL_ONLY_API_KEY")
	if !ok {
		t.Fatalf("vault missing TEST_SHELL_ONLY_API_KEY; vault names = %v", v.Names())
	}
	if c.Real != "sk-abc-highentropy-1234567890" {
		t.Errorf("vaulted value = %q, want sk-abc-highentropy-1234567890", c.Real)
	}
}

func TestInit_CorrelatesAWSTripleFromShellEnv(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "FwoGZXIvYXdzEJr//////////wEaDPshell")

	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmp, "--yes", "--scan-shell-env"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v\n%s", err, out.String())
	}

	ks, err := buildKeystore()
	if err != nil {
		t.Fatalf("buildKeystore: %v", err)
	}
	v, err := vault.Open(tmp, ks)
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
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
		t.Errorf("Real = %q", awsCred.Real)
	}
	if awsCred.AWSSessionToken != "FwoGZXIvYXdzEJr//////////wEaDPshell" {
		t.Errorf("AWSSessionToken = %q", awsCred.AWSSessionToken)
	}

	for _, name := range []string{"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		if _, found := v.Get(name); found {
			t.Errorf("unexpected bearer credential %q in vault", name)
		}
	}
}

func TestProcessShellEnv_BasicPairFromShellExports(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	tmp := t.TempDir()

	ks, err := buildKeystore()
	if err != nil {
		t.Fatalf("buildKeystore: %v", err)
	}
	v, err := vault.CreateVault(tmp, vault.NewID(), ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	candidates := []scanner.EnvironCandidate{
		{Name: "GH_PASSWORD", Value: "ghp_realtoken1234"}, // ScanEnviron-style: only secret-like
	}
	pairCands := []scanner.EnvironCandidate{
		{Name: "GH_USERNAME", Value: "alice"}, // ScanEnvironForPairs adds the user half
		{Name: "GH_PASSWORD", Value: "ghp_realtoken1234"},
	}
	in := strings.NewReader("")
	var out bytes.Buffer
	vaulted, scoped, err := processShellEnvWithPool(&out, in, v, candidates, pairCands, false /*dryRun*/, false /*interactive*/)
	if err != nil {
		t.Fatalf("processShellEnv: %v", err)
	}
	if vaulted != 1 {
		t.Fatalf("vaulted = %d, want 1", vaulted)
	}
	if scoped != 0 && scoped != 1 {
		t.Fatalf("scoped = %d, want 0 or 1", scoped)
	}

	bc, ok := v.Get("GH_PASSWORD")
	if !ok {
		t.Fatal("expected GH_PASSWORD credential present")
	}
	if bc.Username != "alice" {
		t.Errorf("Username = %q, want alice", bc.Username)
	}
	if _, ok := v.Get("GH_USERNAME"); ok {
		t.Error("GH_USERNAME should be folded into GH_PASSWORD, not separate")
	}
}

func TestInit_ShellAWSWithSameNameInVaultDropsWholeGroup(t *testing.T) {
	// Regression guard for the "orphan sibling" scenario: .env already
	// vaulted AWS_ACCESS_KEY_ID as an aws-scheme credential; shell exports
	// the same triple. The post-correlation name filter must drop the
	// whole shell group — not drop only the ID and then vault the two
	// siblings as redundant bearer credentials.
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "FwoGZXIvYXdzEJr//////////wEaDPshell")

	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	envContent := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
		"AWS_SESSION_TOKEN=FwoGZXIvYXdzEJr//////////wEaDPshell\n"
	if err := os.WriteFile(filepath.Join(tmp, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmp, "--yes", "--scan-shell-env"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	ks, err := buildKeystore()
	if err != nil {
		t.Fatalf("buildKeystore: %v", err)
	}
	v, err := vault.Open(tmp, ks)
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}

	names := v.Names()
	if len(names) != 1 || names[0] != "AWS_ACCESS_KEY_ID" {
		t.Fatalf("vault names = %v, want [AWS_ACCESS_KEY_ID] exactly", names)
	}
	for _, leaked := range []string{"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		if _, ok := v.Get(leaked); ok {
			t.Errorf("leaked bearer credential %q in vault (orphan sibling)", leaked)
		}
	}
}
