package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getveil/veil/internal/placeholder"
	"github.com/getveil/veil/internal/scanner"
	"github.com/getveil/veil/internal/vault"
	"github.com/spf13/cobra"
)

// newPhasesTestCmd returns a cobra.Command suitable for calling processEnvFile
// directly. Stdout/stderr go to the provided buffers (caller-owned).
func newPhasesTestCmd(out, errBuf io.Writer, in io.Reader) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	cmd.SetIn(in)
	return cmd
}

// initEnvFixture creates a project root with a .git dir and writes content
// to .env. Returns the project root and .env path.
func initEnvFixture(t *testing.T, content string) (root, envPath string) {
	t.Helper()
	root = t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	envPath = filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, envPath
}

// TestProcessEnvFileVaultWriteFailure asserts that when AddBatch fails, the
// .env file is unchanged, vault.meta has no entry for this path, and the
// vault contains no credentials (rollback). A backup MAY exist on disk —
// per the design, backup is written before the vault write so the next-run
// orphan-recovery path has a known-good source of truth. The point of this
// test is that the user-visible state (cleartext .env, no meta entry) is
// safe to recover from.
func TestProcessEnvFileVaultWriteFailure(t *testing.T) {
	original := "OPENAI_API_KEY=sk-proj-1234567890abcdef\n"
	root, envPath := initEnvFixture(t, original)

	ks := vault.NewMemKeystore()
	v, err := vault.CreateVault(root, "proj-fail", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	// Force AddBatch's Save to fail by removing the master key. CreateVault
	// already populated the master key, so Open works but Save fails.
	if err := ks.Delete("proj-fail"); err != nil {
		t.Fatalf("Delete master key: %v", err)
	}

	out := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd := newPhasesTestCmd(out, errBuf, strings.NewReader(""))

	seen := make(placeholder.Set)
	_, _, err = processEnvFile(cmd, strings.NewReader(""), v, seen, root, envPath, false, false, false)
	if err == nil {
		t.Fatal("expected processEnvFile to error when AddBatch fails")
	}

	// .env unchanged — atomicity is preserved.
	got, rerr := os.ReadFile(envPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != original {
		t.Errorf(".env should be unchanged after vault failure\n got: %q\nwant: %q", got, original)
	}

	// If the backup exists, it must match the original .env — i.e., it is a
	// harmless duplicate, not a stale snapshot of cleartext.
	if data, berr := os.ReadFile(envPath + ".veil-backup"); berr == nil {
		if string(data) != original {
			t.Errorf("backup should match original .env when left after vault failure\n got: %q\nwant: %q", data, original)
		}
	}

	// Vault contains zero credentials (rollback after Save failure).
	if got := len(v.List()); got != 0 {
		t.Errorf("vault should have 0 credentials after rollback, got %d", got)
	}
}

// TestProcessEnvFileRecoversAfterBackupBeforeVault simulates a crash AFTER
// writing the backup but BEFORE updating vault state: the backup exists,
// the .env carries a Veil-shaped placeholder, and the current vault does
// not own that placeholder (it's the artefact of a prior install whose
// state is gone). Init must reclaim the backup as the source of truth and
// re-vault from it. With the vault.meta vaulted-files registry dropped in
// the launch cuts, the orphan signal is now content-based: a sentinel-
// bearing value the current vault doesn't own.
func TestProcessEnvFileRecoversAfterBackupBeforeVault(t *testing.T) {
	original := "GITHUB_TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"
	// The .env's value carries the "VEIL" sentinel inside a ghp_-shaped
	// payload — exactly what a prior Veil install's Generate would have
	// produced. Avoid the literal substring "placeholder" because the
	// stub-value pre-gate in placeholder.IsSecretLike short-circuits on it.
	root, envPath := initEnvFixture(t, "GITHUB_TOKEN=ghp_VEIL_aBcD9876aBcD9876aBcD9876aBcD9876ABCD9876\n")
	// Plant the orphan backup; the .env's sentinel-bearing value is not in
	// the current vault, so isOrphanByContent treats it as a stale prior
	// install's output.
	if err := os.WriteFile(envPath+".veil-backup", []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	ks := vault.NewMemKeystore()
	v, err := vault.CreateVault(root, "proj-orphan", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	out := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd := newPhasesTestCmd(out, errBuf, strings.NewReader(""))

	seen := make(placeholder.Set)
	vaulted, _, err := processEnvFile(cmd, strings.NewReader(""), v, seen, root, envPath, false, false, false)
	if err != nil {
		t.Fatalf("processEnvFile: %v", err)
	}
	if vaulted != 1 {
		t.Errorf("vaulted = %d, want 1", vaulted)
	}
	if !strings.Contains(errBuf.String(), "orphaned backup") {
		t.Errorf("expected 'orphaned backup' notice, got: %s", errBuf.String())
	}

	cred, ok := v.Get("GITHUB_TOKEN")
	if !ok {
		t.Fatal("GITHUB_TOKEN not vaulted")
	}
	if cred.Real != "ghp_real1234567890abcdef1234567890abcdef" {
		t.Errorf("vaulted real value should come from the backup; got %q", cred.Real)
	}
}

// TestProcessEnvFileRecoversAfterMetaBeforeRewrite simulates a crash AFTER
// vault commit but BEFORE the atomic .env rewrite. The backup is in place,
// the credential is in the vault, but .env still has cleartext. Init must
// detect this (vault has a matching cred, .env value matches Real) and
// replay only the rewrite step.
func TestProcessEnvFileRecoversAfterMetaBeforeRewrite(t *testing.T) {
	original := "API_TOKEN=tok_1234567890abcdefghij\n"
	root, envPath := initEnvFixture(t, original)

	ks := vault.NewMemKeystore()
	v, err := vault.CreateVault(root, "proj-pending-rewrite", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Hand-build the half-finished state: backup + cred-in-vault, but the
	// .env never got rewritten with the placeholder.
	if err := os.WriteFile(envPath+".veil-backup", []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := v.Add(&vault.Credential{
		ID:          vault.NewID(),
		Name:        "API_TOKEN",
		Real:        "tok_1234567890abcdefghij",
		Placeholder: "VEIL_PENDING_PH_API_TOKEN",
		Source:      "init",
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("v.Add: %v", err)
	}

	out := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd := newPhasesTestCmd(out, errBuf, strings.NewReader(""))

	seen := make(placeholder.Set)
	vaulted, _, err := processEnvFile(cmd, strings.NewReader(""), v, seen, root, envPath, false, false, false)
	if err != nil {
		t.Fatalf("processEnvFile: %v", err)
	}
	// Recovery must not re-vault — the credential is already present.
	if vaulted != 0 {
		t.Errorf("vaulted = %d after recovery, want 0", vaulted)
	}

	// The .env must now contain the placeholder, not cleartext.
	got, rerr := os.ReadFile(envPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.Contains(string(got), "VEIL_PENDING_PH_API_TOKEN") {
		t.Errorf(".env should contain placeholder after rewrite, got: %q", got)
	}
	if strings.Contains(string(got), "tok_1234567890abcdefghij") {
		t.Errorf("cleartext should be gone after recovery rewrite, got: %q", got)
	}

	// Vault still has exactly one credential (no duplicate added).
	if got := len(v.List()); got != 1 {
		t.Errorf("vault should have 1 credential after recovery, got %d", got)
	}

	if !strings.Contains(errBuf.String(), "recovering interrupted init") {
		t.Errorf("expected recovery notice, got: %s", errBuf.String())
	}
}

// TestRecoverPendingEnvRewriteDetectsUserEdits simulates the recovery state
// where the user has edited the .env file between the crash and the re-run.
// In that case, the value in the .env no longer matches the credential's
// stored Real, and silently rewriting would lose the user's edit. The
// recovery path must refuse and return an actionable error.
func TestRecoverPendingEnvRewriteDetectsUserEdits(t *testing.T) {
	originalReal := "tok_originalvalue1234567890abcdef"
	userEdited := "API_TOKEN=tok_USER_edited_NEW_value_1234567890\n"
	root, envPath := initEnvFixture(t, userEdited)

	ks := vault.NewMemKeystore()
	v, err := vault.CreateVault(root, "proj-user-edit", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Hand-build the crash state: backup written, vault credential
	// committed — but .env was never rewritten and was since edited
	// by the user.
	if err := os.WriteFile(envPath+".veil-backup", []byte("API_TOKEN="+originalReal+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := v.Add(&vault.Credential{
		ID:          vault.NewID(),
		Name:        "API_TOKEN",
		Real:        originalReal,
		Placeholder: "VEIL_PENDING_PH_API_TOKEN",
		Source:      "init",
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("v.Add: %v", err)
	}

	out := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd := newPhasesTestCmd(out, errBuf, strings.NewReader(""))

	seen := make(placeholder.Set)
	_, _, err = processEnvFile(cmd, strings.NewReader(""), v, seen, root, envPath, false, false, false)
	if err == nil {
		t.Fatal("expected processEnvFile to error when user edited .env between crash and re-run")
	}
	if !strings.Contains(err.Error(), "API_TOKEN") {
		t.Errorf("error message should mention the diverging key API_TOKEN, got: %v", err)
	}

	// .env content must be unchanged on disk.
	gotEnv, rerr := os.ReadFile(envPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(gotEnv) != userEdited {
		t.Errorf(".env should be unchanged on user-edit detection\n got: %q\nwant: %q", gotEnv, userEdited)
	}
}

// TestRecoverPendingEnvRewriteHappyPath asserts that when the .env value
// still matches the credential's Real (i.e. the crash truly was between
// register and rewrite with no user edits), recovery rewrites the .env
// with the placeholder and does not re-prompt or duplicate vault entries.
func TestRecoverPendingEnvRewriteHappyPath(t *testing.T) {
	originalReal := "tok_unchanged_value_1234567890abcd"
	envContent := "API_TOKEN=" + originalReal + "\n"
	root, envPath := initEnvFixture(t, envContent)

	ks := vault.NewMemKeystore()
	v, err := vault.CreateVault(root, "proj-happy-recovery", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	if err := os.WriteFile(envPath+".veil-backup", []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := v.Add(&vault.Credential{
		ID:          vault.NewID(),
		Name:        "API_TOKEN",
		Real:        originalReal,
		Placeholder: "VEIL_PENDING_PH_API_TOKEN",
		Source:      "init",
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("v.Add: %v", err)
	}

	out := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd := newPhasesTestCmd(out, errBuf, strings.NewReader(""))

	seen := make(placeholder.Set)
	vaulted, _, err := processEnvFile(cmd, strings.NewReader(""), v, seen, root, envPath, false, false, false)
	if err != nil {
		t.Fatalf("processEnvFile: %v", err)
	}
	if vaulted != 0 {
		t.Errorf("vaulted = %d after recovery, want 0", vaulted)
	}

	gotEnv, rerr := os.ReadFile(envPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.Contains(string(gotEnv), "VEIL_PENDING_PH_API_TOKEN") {
		t.Errorf(".env should contain placeholder after recovery, got: %q", gotEnv)
	}
	if strings.Contains(string(gotEnv), originalReal) {
		t.Errorf("cleartext should be gone after recovery rewrite, got: %q", gotEnv)
	}

	if got := len(v.List()); got != 1 {
		t.Errorf("vault should have 1 credential after recovery, got %d", got)
	}
}

// TestProcessEnvFileDuplicateIsHardErrorWithoutForce asserts that a duplicate
// credential at AddBatch time is a fatal error for the file when --force is
// not set. The .env must not be rewritten and no backup must be written.
func TestProcessEnvFileDuplicateIsHardErrorWithoutForce(t *testing.T) {
	original := "STRIPE_KEY=sk_live_12345678901234567890abcd\n"
	root, envPath := initEnvFixture(t, original)

	ks := vault.NewMemKeystore()
	v, err := vault.CreateVault(root, "proj-dup", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	// Pre-populate vault with a credential whose name matches the .env key.
	if err := v.Add(&vault.Credential{
		ID:          vault.NewID(),
		Name:        "STRIPE_KEY",
		Real:        "sk_live_old_value_99999999999",
		Placeholder: "VEIL_OLD_STRIPE_PH",
		Source:      "init",
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("v.Add: %v", err)
	}

	out := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd := newPhasesTestCmd(out, errBuf, strings.NewReader(""))

	seen := make(placeholder.Set)
	_, _, err = processEnvFile(cmd, strings.NewReader(""), v, seen, root, envPath, false, false, false)
	if err == nil {
		t.Fatal("expected processEnvFile to error on duplicate without --force")
	}
	if !errors.Is(err, vault.ErrDuplicateCredential) {
		t.Errorf("expected ErrDuplicateCredential, got: %v", err)
	}

	got, rerr := os.ReadFile(envPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != original {
		t.Errorf(".env changed on duplicate failure:\n got: %q\nwant: %q", got, original)
	}
	// Backup may exist (backup-first ordering) but if present must match the
	// original — orphan-recovery on the next run handles cleanup.
	if data, berr := os.ReadFile(envPath + ".veil-backup"); berr == nil {
		if string(data) != original {
			t.Errorf("backup should match original .env when left after duplicate failure\n got: %q\nwant: %q", data, original)
		}
	}
}

// TestProcessEnvFileForceRemovesAndReplaces asserts that --force removes the
// existing duplicate credential before vaulting the new one. The result is
// success: .env rewritten with the new placeholder, vault has the new cred.
func TestProcessEnvFileForceRemovesAndReplaces(t *testing.T) {
	original := "STRIPE_KEY=sk_live_NEW_VALUE_1234567890abcd\n"
	root, envPath := initEnvFixture(t, original)

	ks := vault.NewMemKeystore()
	v, err := vault.CreateVault(root, "proj-force", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if err := v.Add(&vault.Credential{
		ID:          vault.NewID(),
		Name:        "STRIPE_KEY",
		Real:        "sk_live_old_value_99999999999",
		Placeholder: "VEIL_OLD_STRIPE_PH",
		Source:      "init",
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("v.Add: %v", err)
	}

	out := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd := newPhasesTestCmd(out, errBuf, strings.NewReader(""))

	seen := make(placeholder.Set)
	vaulted, _, err := processEnvFile(cmd, strings.NewReader(""), v, seen, root, envPath, true /*force*/, false /*dryRun*/, false /*interactive*/)
	if err != nil {
		t.Fatalf("processEnvFile with --force: %v", err)
	}
	if vaulted != 1 {
		t.Errorf("vaulted = %d, want 1", vaulted)
	}

	cred, ok := v.Get("STRIPE_KEY")
	if !ok {
		t.Fatal("STRIPE_KEY missing from vault after --force")
	}
	if cred.Real != "sk_live_NEW_VALUE_1234567890abcd" {
		t.Errorf("vaulted Real should be the new value; got %q", cred.Real)
	}

	got, rerr := os.ReadFile(envPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if strings.Contains(string(got), "sk_live_NEW_VALUE_1234567890abcd") {
		t.Errorf("cleartext should be gone from .env, got: %q", got)
	}
	if !strings.Contains(string(got), cred.Placeholder) {
		t.Errorf(".env should contain new placeholder %q, got: %q", cred.Placeholder, got)
	}
}

// TestProcessEnvFileDryRunNoSideEffects asserts that --dry-run performs no
// disk I/O: .env unchanged, no backup, no meta entry, no vault changes.
func TestProcessEnvFileDryRunNoSideEffects(t *testing.T) {
	original := "OPENAI_API_KEY=sk-proj-1234567890abcdef\n"
	root, envPath := initEnvFixture(t, original)

	v := vault.NewInMemoryVault(root, vault.NewID())

	out := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd := newPhasesTestCmd(out, errBuf, strings.NewReader(""))

	seen := make(placeholder.Set)
	vaulted, _, err := processEnvFile(cmd, strings.NewReader(""), v, seen, root, envPath, false /*force*/, true /*dryRun*/, false /*interactive*/)
	if err != nil {
		t.Fatalf("processEnvFile dry-run: %v", err)
	}
	if vaulted != 1 {
		t.Errorf("dry-run vaulted count = %d, want 1", vaulted)
	}

	got, rerr := os.ReadFile(envPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != original {
		t.Errorf(".env should be unchanged in dry-run\n got: %q\nwant: %q", got, original)
	}
	if _, sterr := os.Stat(envPath + ".veil-backup"); !os.IsNotExist(sterr) {
		t.Errorf(".veil-backup must not exist after dry-run, got err: %v", sterr)
	}
	if got := len(v.List()); got != 0 {
		t.Errorf("in-memory vault must be empty after dry-run, got: %d", got)
	}
	if !strings.Contains(out.String(), "would vault:") {
		t.Errorf("expected dry-run output, got: %s", out.String())
	}
}

func TestBuildEnvFileCredentials_SkipsAWS(t *testing.T) {
	envFile := scanner.ParseBytes([]byte(
		"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789AB\n" +
			"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REDACTD\n" +
			"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY\n"))

	// Build the secret list the way processEnvFile would.
	var secrets []secretLine
	for i, line := range envFile.Lines {
		if line.Kind == scanner.KVLine && placeholder.IsSecretLike(line.Key, line.Value) {
			secrets = append(secrets, secretLine{key: line.Key, value: line.Value, index: i})
		}
	}

	res, err := buildEnvFileCredentials(envFile, secrets, placeholder.Set{})
	if err != nil {
		t.Fatalf("buildEnvFileCredentials: %v", err)
	}

	// Only GITHUB_TOKEN may be vaulted; both AWS_* land in Skipped (the AWS
	// provider was removed in the v1 launch cut so no provider claims them).
	if len(res.Creds) != 1 || res.Creds[0].Name != "GITHUB_TOKEN" {
		t.Fatalf("Creds = %+v, want exactly GITHUB_TOKEN", res.Creds)
	}
	if len(res.Skipped) != 2 {
		t.Fatalf("Skipped len = %d, want 2 (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY)", len(res.Skipped))
	}
}

// TestBuildEnvFileCredentials_PostgresURLNotVaulted locks in the Phase-5
// cut: postgres://, mysql://, redis:// and the other TCP-protocol URL
// schemes bypass Veil's HTTP proxy entirely, so DATABASE_URL=postgres://...
// is not vaulted. If a postgres URL is still surfaced to
// buildEnvFileCredentials (e.g. via a name-hint gate match like
// DB_PASSWORD or via the entropy gate on a long value), it lands in
// Skipped rather than Creds because no provider claims it.
func TestBuildEnvFileCredentials_PostgresURLNotVaulted(t *testing.T) {
	// IsSecretLike no longer recognizes a postgres URL by name alone, so
	// DATABASE_URL=postgres://... is not surfaced at all. The DB_PASSWORD
	// name hint, however, will trip the value-shape gate and surface the
	// line — that's the path we want to lock in here.
	envFile := scanner.ParseBytes([]byte(
		"DB_PASSWORD=postgres://user:secret@db.prod.internal/app\n"))
	var secrets []secretLine
	for i, line := range envFile.Lines {
		if line.Kind == scanner.KVLine && placeholder.IsSecretLike(line.Key, line.Value) {
			secrets = append(secrets, secretLine{key: line.Key, value: line.Value, index: i})
		}
	}
	if len(secrets) != 1 {
		t.Fatalf("secrets len = %d, want 1 (DB_PASSWORD name-hint gate fires)", len(secrets))
	}

	res, err := buildEnvFileCredentials(envFile, secrets, placeholder.Set{})
	if err != nil {
		t.Fatalf("buildEnvFileCredentials: %v", err)
	}
	if len(res.Creds) != 0 {
		t.Fatalf("Creds = %+v, want empty (postgres:// has no provider and TCP can't be proxied)", res.Creds)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].key != "DB_PASSWORD" {
		t.Fatalf("Skipped = %+v, want exactly DB_PASSWORD", res.Skipped)
	}
}

func TestBuildEnvFileCredentials_SkipsUnrecognized(t *testing.T) {
	envFile := scanner.ParseBytes([]byte(
		"OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF01\n" +
			"WEIRD_SECRET=just_a_long_random_value_with_no_known_format_42\n"))
	var secrets []secretLine
	for i, line := range envFile.Lines {
		if line.Kind == scanner.KVLine && placeholder.IsSecretLike(line.Key, line.Value) {
			secrets = append(secrets, secretLine{key: line.Key, value: line.Value, index: i})
		}
	}

	res, err := buildEnvFileCredentials(envFile, secrets, placeholder.Set{})
	if err != nil {
		t.Fatalf("buildEnvFileCredentials: %v", err)
	}
	if len(res.Creds) != 1 || res.Creds[0].Name != "OPENAI_API_KEY" {
		t.Fatalf("Creds = %+v, want exactly OPENAI_API_KEY", res.Creds)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].key != "WEIRD_SECRET" {
		t.Fatalf("Skipped = %+v, want exactly WEIRD_SECRET", res.Skipped)
	}
}

// TestPrintDryRunVaultLines_SkipsNonEligibleByName guards against a
// counter-pairing regression: when secrets contain entries that didn't
// produce a Credential (skipped via the binary isVaultEligible gate),
// the dry-run output must skip them rather than print the next eligible
// credential's placeholder against the wrong key.
func TestPrintDryRunVaultLines_SkipsNonEligibleByName(t *testing.T) {
	secrets := []secretLine{
		{key: "OPENAI_API_KEY", value: "sk-real"},
		{key: "RANDOM_NOT_SECRET", value: "hello"},
		{key: "STRIPE_SECRET_KEY", value: "sk_live_xxx"},
	}
	creds := []*vault.Credential{
		{Name: "OPENAI_API_KEY", Placeholder: "veilph-openai"},
		{Name: "STRIPE_SECRET_KEY", Placeholder: "veilph-stripe"},
	}
	var buf bytes.Buffer
	printDryRunVaultLines(&buf, secrets, creds)
	out := buf.String()
	if !strings.Contains(out, "OPENAI_API_KEY -> veilph-openai") {
		t.Errorf("missing OPENAI line:\n%s", out)
	}
	if !strings.Contains(out, "STRIPE_SECRET_KEY -> veilph-stripe") {
		t.Errorf("missing STRIPE line:\n%s", out)
	}
	if strings.Contains(out, "RANDOM_NOT_SECRET") {
		t.Errorf("non-eligible key surfaced in dry-run:\n%s", out)
	}
	if strings.Contains(out, "RANDOM_NOT_SECRET -> veilph-stripe") {
		t.Errorf("pairing bug: non-eligible key bound to next credential's placeholder:\n%s", out)
	}
}

// TestPrintVaultSummary_RendersVaultedSection verifies the simplified
// post-launch-cut summary: a single Vaulted line per credential, with no
// per-line Reason annotation (the Reason machinery was removed in Phase 9).
func TestPrintVaultSummary_RendersVaultedSection(t *testing.T) {
	res := vaultBuildResult{
		Creds: []*vault.Credential{
			{Name: "OPENAI_API_KEY", Placeholder: "veilph-openai-XX"},
		},
	}
	var buf bytes.Buffer
	printVaultSummary(&buf, res, false)
	out := buf.String()
	if !strings.Contains(out, "Vaulted (1)") {
		t.Errorf("output missing 'Vaulted (1)' header:\n%s", out)
	}
	if !strings.Contains(out, "OPENAI_API_KEY") {
		t.Errorf("output missing OPENAI_API_KEY:\n%s", out)
	}
	if !strings.Contains(out, "veilph-openai-XX") {
		t.Errorf("output missing placeholder:\n%s", out)
	}
}

// TestPrintVaultSummary_SkippedShowsAddHintOnce verifies the Skipped section
// prints a single `veil add` hint at the bottom rather than one per skipped
// row. A user with multiple unrecognized values shouldn't read the same
// suggestion repeated N times.
func TestPrintVaultSummary_SkippedShowsAddHintOnce(t *testing.T) {
	res := vaultBuildResult{
		Skipped: []secretLine{
			{key: "WEIRD_SECRET_A"},
			{key: "WEIRD_SECRET_B"},
			{key: "WEIRD_SECRET_C"},
		},
	}
	var buf bytes.Buffer
	printVaultSummary(&buf, res, false)
	out := buf.String()
	// Each skipped key still appears.
	for _, k := range []string{"WEIRD_SECRET_A", "WEIRD_SECRET_B", "WEIRD_SECRET_C"} {
		if !strings.Contains(out, k) {
			t.Errorf("Skipped section missing %s:\n%s", k, out)
		}
	}
	// The hint must appear exactly once.
	hintFragment := "veil add"
	if got := strings.Count(out, hintFragment); got != 1 {
		t.Errorf("expected exactly one 'veil add' hint, got %d:\n%s", got, out)
	}
	if !strings.Contains(out, "--value-stdin") {
		t.Errorf("hint should mention --value-stdin, got:\n%s", out)
	}
	if !strings.Contains(out, "--host") {
		t.Errorf("hint should mention --host, got:\n%s", out)
	}
}

// TestPrintVaultSummary_NoSkippedNoHint verifies the hint is only emitted
// when there's something in the Skipped bucket. A clean file should not
// trigger advice about a section that wasn't rendered.
func TestPrintVaultSummary_NoSkippedNoHint(t *testing.T) {
	res := vaultBuildResult{
		Creds: []*vault.Credential{
			{Name: "OPENAI_API_KEY", Placeholder: "veilph-openai-XX"},
		},
	}
	var buf bytes.Buffer
	printVaultSummary(&buf, res, false)
	if strings.Contains(buf.String(), "veil add") {
		t.Errorf("hint must not appear without a Skipped section:\n%s", buf.String())
	}
}

// TestSetupProxyCA_DryRunNoFilesystemSideEffects verifies that --dry-run
// does not create the CA cert/key files on disk. Without this fix, dry-run
// was creating ~/Library/Application Support/veil/ca/{root.pem,root.key}
// on macOS (and ~/.local/share/veil/ca/* on Linux) the first time the
// user ran init, even though the documented contract is no-side-effects.
func TestSetupProxyCA_DryRunNoFilesystemSideEffects(t *testing.T) {
	// Pin XDG_DATA_HOME inside the per-test HOME so we can assert no file
	// landed under the user's real config locations either.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))

	var buf bytes.Buffer
	if err := setupProxyCA(&buf, true); err != nil {
		t.Fatalf("setupProxyCA(dryRun=true): %v", err)
	}

	// No files anywhere under HOME should have been created by the dry-run.
	var found []string
	_ = filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		// HOME starts empty; any regular file is a side effect.
		found = append(found, path)
		return nil
	})
	if len(found) != 0 {
		t.Errorf("dry-run wrote files to disk: %v", found)
	}

	out := buf.String()
	if !strings.Contains(out, "Would create CA certificate") {
		t.Errorf("expected 'Would create CA certificate' notice, got: %s", out)
	}
}

// TestSetupProxyCA_NonDryRunWritesCA verifies the happy path still actually
// creates the CA when not in dry-run.
func TestSetupProxyCA_NonDryRunWritesCA(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))

	var buf bytes.Buffer
	if err := setupProxyCA(&buf, false); err != nil {
		t.Fatalf("setupProxyCA(dryRun=false): %v", err)
	}
	// Some file must now exist under HOME (the CA cert + key).
	var found []string
	_ = filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		found = append(found, path)
		return nil
	})
	if len(found) == 0 {
		t.Errorf("non-dry-run should have written CA files; HOME is empty")
	}
}
