package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// vaultMetaShape mirrors internal/vault.vaultMeta enough to inspect the
// stored project_id from a black-box test. Field tags match the production
// JSON.
type vaultMetaShape struct {
	ProjectID string `json:"project_id"`
	Version   int    `json:"version"`
}

func readVaultMeta(t *testing.T, projDir string) vaultMetaShape {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(projDir, ".veil", "vault.meta"))
	if err != nil {
		t.Fatalf("read vault.meta: %v", err)
	}
	var m vaultMetaShape
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse vault.meta: %v", err)
	}
	return m
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// runVeilInit invokes the compiled veil binary's init subcommand in
// non-interactive mode and returns its combined stdout/stderr.
func runVeilInit(t *testing.T, veilBin, projDir string, env []string, extraArgs ...string) ([]byte, error) {
	t.Helper()
	args := append([]string{"init", "--path", projDir, "--yes"}, extraArgs...)
	cmd := exec.Command(veilBin, args...)
	cmd.Env = env
	return cmd.CombinedOutput()
}

// TestE2E_InitOrphanBackupFromPriorInstall covers the production-reachable
// orphan-recovery path: a .veil-backup that is NOT in any current
// vault.meta — typically because the prior install was uninstalled or its
// .veil/ directory wiped — must be treated as the source of truth, with the
// stale placeholder-filled .env discarded.
func TestE2E_InitOrphanBackupFromPriorInstall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	env := makeEnv(t)
	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	envPath := filepath.Join(projDir, ".env")
	// Use a named-provider secret (GitHub PAT) so the vault-eligibility gate
	// lets it through. AWS_SECRET_ACCESS_KEY (SigV4) is no longer vaulted by
	// v0.1.x init.
	originalSecret := "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"
	original := "GITHUB_TOKEN=" + originalSecret + "\n"
	// Prior placeholder carries the VEIL sentinel inside a ghp_-shaped body
	// — what Generate would have produced — without the literal substring
	// "placeholder", which would trip the stub-value pre-gate in
	// placeholder.IsSecretLike and hide the orphan signal from the new
	// content-based detector.
	priorPlaceholder := "GITHUB_TOKEN=ghp_VEILpriorAaBbCcDd1122334455AaBbCcDd1122\n"

	if err := os.WriteFile(envPath+".veil-backup", []byte(original), 0600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	if err := os.WriteFile(envPath, []byte(priorPlaceholder), 0644); err != nil {
		t.Fatalf("seed placeholder env: %v", err)
	}

	out, err := runVeilInit(t, veilBin, projDir, env)
	if err != nil {
		t.Fatalf("init over orphan backup failed: %v\n%s", err, out)
	}
	got := mustReadFile(t, envPath)
	if strings.Contains(got, "veil-prior-placeholder") {
		t.Errorf("init kept prior placeholder text instead of re-vaulting from backup:\n%s", got)
	}
	if strings.Contains(got, originalSecret) {
		t.Errorf("cleartext leaked through after orphan recovery:\n%s", got)
	}

	listCmd := exec.Command(veilBin, "list", "--path", projDir)
	listCmd.Env = env
	listOut, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil list after orphan recovery: %v\n%s", err, listOut)
	}
	if !strings.Contains(string(listOut), "GITHUB_TOKEN") {
		t.Errorf("vault list missing GITHUB_TOKEN after orphan recovery; got:\n%s", listOut)
	}
}

// TestE2E_InitMultipleEnvFiles exercises the outer init loop that processes
// multiple .env files in one invocation. Each file must get its own
// .veil-backup, be registered in vault.meta, and have its secret values
// replaced with placeholders. Failures in any one file must not silently
// corrupt others (verified by the staged-commit write order in
// processEnvFile).
func TestE2E_InitMultipleEnvFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	env := makeEnv(t)
	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	type fixture struct {
		name    string
		key     string
		secret  string
		content string
	}
	fixtures := []fixture{
		{
			name:    ".env",
			key:     "OPENAI_API_KEY",
			secret:  "sk-proj-multifile111aaaaa222bbbbb333ccccc",
			content: "OPENAI_API_KEY=sk-proj-multifile111aaaaa222bbbbb333ccccc\n",
		},
		{
			name:    ".env.local",
			key:     "GITHUB_TOKEN",
			secret:  "ghp_multifileaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			content: "GITHUB_TOKEN=ghp_multifileaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
		},
		{
			name:    ".env.development",
			key:     "STRIPE_API_KEY",
			secret:  "sk_test_multifileaaaaaaaaaaaaaaaaaaaaaaa",
			content: "STRIPE_API_KEY=sk_test_multifileaaaaaaaaaaaaaaaaaaaaaaa\n",
		},
	}
	for _, f := range fixtures {
		if err := os.WriteFile(filepath.Join(projDir, f.name), []byte(f.content), 0644); err != nil {
			t.Fatalf("write %s: %v", f.name, err)
		}
	}

	out, err := runVeilInit(t, veilBin, projDir, env)
	if err != nil {
		t.Fatalf("multi-file init failed: %v\n%s", err, out)
	}

	for _, f := range fixtures {
		path := filepath.Join(projDir, f.name)
		got := mustReadFile(t, path)
		if strings.Contains(got, f.secret) {
			t.Errorf("%s still contains cleartext secret %q:\n%s", f.name, f.secret, got)
		}
		if _, err := os.Stat(path + ".veil-backup"); err != nil {
			t.Errorf("%s.veil-backup not created: %v", f.name, err)
		}
		backupBytes, err := os.ReadFile(path + ".veil-backup")
		if err != nil {
			t.Errorf("read %s.veil-backup: %v", f.name, err)
		} else if string(backupBytes) != f.content {
			t.Errorf("%s.veil-backup content mismatch:\n  want: %q\n  got:  %q",
				f.name, f.content, string(backupBytes))
		}
	}

	// vault.meta must still load cleanly (sanity: project_id present). The
	// pre-v1 vaulted-files registry that this test used to assert against
	// was dropped in the launch cuts — the .veil-backup sidecars on disk
	// are now the source of truth for which files init touched.
	m := readVaultMeta(t, projDir)
	if m.ProjectID == "" {
		t.Errorf("vault.meta missing project_id after multi-file init")
	}

	listCmd := exec.Command(veilBin, "list", "--path", projDir)
	listCmd.Env = env
	listOut, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil list after multi-file init: %v\n%s", err, listOut)
	}
	for _, f := range fixtures {
		if !strings.Contains(string(listOut), f.key) {
			t.Errorf("vault list missing %s after multi-file init; got:\n%s", f.key, listOut)
		}
	}
}

// TestE2E_InitForceReVaultsCleanly verifies the --force flow that re-vaults
// a project whose state may be inconsistent (for example, after an
// interrupted init). The user-facing escape hatch must produce a clean vault
// and clean .env, regardless of what was there before. Without the
// per-file atomicity refactor, --force could leave duplicate credentials
// or partially-replaced lines.
func TestE2E_InitForceReVaultsCleanly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	env := makeEnv(t)
	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	envPath := filepath.Join(projDir, ".env")
	// Use a named-provider secret (GitHub PAT) so the vault-eligibility gate
	// lets it through. Generic tok_* values have no matching provider in v0.1.x.
	original := "GITHUB_TOKEN=ghp_originalvalue1234567890abcdefABCD\n"
	if err := os.WriteFile(envPath, []byte(original), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	if out, err := runVeilInit(t, veilBin, projDir, env); err != nil {
		t.Fatalf("first init failed: %v\n%s", err, out)
	}

	// Simulate the user rotating the secret in .env, then re-running
	// with --force to refresh the vault. (Manually mutating the .env
	// here is a stand-in for any state-divergence the user may see after
	// an interruption or unrelated edit.)
	rotated := "GITHUB_TOKEN=ghp_rotatedvalue9876543210xyzaaBBBB\n"
	if err := os.WriteFile(envPath, []byte(rotated), 0644); err != nil {
		t.Fatalf("simulate user rotation: %v", err)
	}

	out, err := runVeilInit(t, veilBin, projDir, env, "--force")
	if err != nil {
		t.Fatalf("forced re-init failed: %v\n%s", err, out)
	}

	got := mustReadFile(t, envPath)
	if strings.Contains(got, "ghp_rotatedvalue9876543210xyzaaBBBB") {
		t.Errorf(".env still contains the rotated secret after --force re-vault:\n%s", got)
	}
	if strings.Contains(got, "ghp_originalvalue1234567890abcdefABCD") {
		t.Errorf(".env contains the stale original secret after --force re-vault:\n%s", got)
	}

	listCmd := exec.Command(veilBin, "list", "--path", projDir)
	listCmd.Env = env
	listOut, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil list after forced re-init: %v\n%s", err, listOut)
	}
	count := strings.Count(string(listOut), "GITHUB_TOKEN")
	if count != 1 {
		t.Errorf("expected exactly one GITHUB_TOKEN entry after --force re-vault, got %d:\n%s", count, listOut)
	}
}

// TestE2E_InitRejectsSecondInitWithoutForce documents the user-facing UX
// guard that prevents accidental clobbering. A user whose first init
// succeeded must use --force to re-run; the bare `veil init` command exits
// cleanly with a clear message rather than silently rewriting state. This
// is the gate that makes the per-file atomicity refactor's recovery paths
// reachable only deliberately, not by accident.
func TestE2E_InitRejectsSecondInitWithoutForce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	env := makeEnv(t)
	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	envPath := filepath.Join(projDir, ".env")
	original := "SUPABASE_KEY=sk_supabasevalueaaaaaaaaaaaaaaaaaaaa\n"
	if err := os.WriteFile(envPath, []byte(original), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	if out, err := runVeilInit(t, veilBin, projDir, env); err != nil {
		t.Fatalf("first init failed: %v\n%s", err, out)
	}
	postFirst := mustReadFile(t, envPath)

	out, err := runVeilInit(t, veilBin, projDir, env)
	if err == nil {
		t.Fatalf("second init should have failed; got output:\n%s", out)
	}
	if !strings.Contains(string(out), "already initialized") {
		t.Errorf("error should mention 'already initialized'; got:\n%s", out)
	}
	if !strings.Contains(string(out), "--force") {
		t.Errorf("error should point user to --force; got:\n%s", out)
	}

	// State must be byte-identical to after the first init — no silent
	// mutation by the failed re-run.
	postSecond := mustReadFile(t, envPath)
	if postFirst != postSecond {
		t.Errorf(".env mutated by rejected second init:\n  before: %q\n  after:  %q", postFirst, postSecond)
	}
}
