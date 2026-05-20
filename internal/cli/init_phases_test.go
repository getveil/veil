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

	// vault.meta has no entry for envPath.
	files, ferr := vault.ReadVaultedFiles(root)
	if ferr != nil {
		t.Fatalf("ReadVaultedFiles: %v", ferr)
	}
	abs, _ := filepath.Abs(envPath)
	for _, f := range files {
		if f.Path == abs {
			t.Errorf("vault.meta should not register %s after vault failure", envPath)
		}
	}

	// Vault contains zero credentials (rollback after Save failure).
	if got := len(v.List()); got != 0 {
		t.Errorf("vault should have 0 credentials after rollback, got %d", got)
	}
}

// TestProcessEnvFileRecoversAfterBackupBeforeVault simulates a crash AFTER
// writing the backup but BEFORE updating vault state: the backup exists, but
// no meta entry. This is the orphaned-backup recovery path. Init must
// reclaim the backup as the source of truth and re-vault from it.
func TestProcessEnvFileRecoversAfterBackupBeforeVault(t *testing.T) {
	original := "GITHUB_TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"
	root, envPath := initEnvFixture(t, "GITHUB_TOKEN=ghp_VEIL_oldplaceholder\n")
	// Plant the orphan backup (no matching vault.meta entry).
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
// vault commit AND meta-register but BEFORE the atomic .env rewrite. The
// backup is in place, vault.meta is registered, and the credential is in
// the vault, but .env still has cleartext. Init must detect this and replay
// only the rewrite step.
func TestProcessEnvFileRecoversAfterMetaBeforeRewrite(t *testing.T) {
	original := "API_TOKEN=tok_1234567890abcdefghij\n"
	root, envPath := initEnvFixture(t, original)

	ks := vault.NewMemKeystore()
	v, err := vault.CreateVault(root, "proj-pending-rewrite", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Hand-build the half-finished state.
	if err := os.WriteFile(envPath+".veil-backup", []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := vault.AddVaultedFile(root, envPath, vault.KindEnv); err != nil {
		t.Fatalf("AddVaultedFile: %v", err)
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

// TestProcessEnvFileOrphanReclaimCleansStaleVaultCreds simulates a crash
// between writeBackup and registerVaultedFile: the backup exists, the
// vault already has credentials with names matching .env keys (from the
// crashed run), but vault.meta has no entry. The next init must reclaim
// the orphaned backup AND remove the stale vault credentials so the re-run
// can re-vault from scratch without a duplicate-credential error.
func TestProcessEnvFileOrphanReclaimCleansStaleVaultCreds(t *testing.T) {
	original := "GITHUB_TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"
	// Current .env content holds the OLD placeholder from the crashed run,
	// so the cleartext is only in the backup.
	root, envPath := initEnvFixture(t, "GITHUB_TOKEN=ghp_VEIL_oldplaceholder\n")
	if err := os.WriteFile(envPath+".veil-backup", []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	ks := vault.NewMemKeystore()
	v, err := vault.CreateVault(root, "proj-orphan-stale", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	// Pre-populate the vault with a STALE credential matching the .env key
	// — simulates credentials that AddBatch persisted before the crash.
	staleReal := "ghp_STALE_value_from_crashed_run_98765432109"
	if err := v.Add(&vault.Credential{
		ID:          vault.NewID(),
		Name:        "GITHUB_TOKEN",
		Real:        staleReal,
		Placeholder: "ghp_VEIL_oldplaceholder",
		Source:      "init",
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("v.Add stale: %v", err)
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

	// The vault must now hold the FRESH credential, not the stale one.
	cred, ok := v.Get("GITHUB_TOKEN")
	if !ok {
		t.Fatal("GITHUB_TOKEN not present in vault after re-vault")
	}
	if cred.Real == staleReal {
		t.Errorf("vault still holds stale credential; expected fresh value from backup, got %q", cred.Real)
	}
	if cred.Real != "ghp_real1234567890abcdef1234567890abcdef" {
		t.Errorf("vault Real should equal restored cleartext; got %q", cred.Real)
	}
	if got := len(v.List()); got != 1 {
		t.Errorf("vault should have exactly 1 credential after cleanup + re-vault, got %d", got)
	}

	// The .env must now contain the new placeholder, not cleartext or the
	// stale placeholder.
	gotEnv, rerr := os.ReadFile(envPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.Contains(string(gotEnv), cred.Placeholder) {
		t.Errorf(".env should contain new placeholder %q, got: %q", cred.Placeholder, gotEnv)
	}
	if strings.Contains(string(gotEnv), "ghp_real1234567890abcdef1234567890abcdef") {
		t.Errorf("cleartext should be gone from .env, got: %q", gotEnv)
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

	// Hand-build the crash-3-4 state: backup written, vault credential
	// committed, meta registered — but .env was never rewritten and was
	// since edited by the user.
	if err := os.WriteFile(envPath+".veil-backup", []byte("API_TOKEN="+originalReal+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := vault.AddVaultedFile(root, envPath, vault.KindEnv); err != nil {
		t.Fatalf("AddVaultedFile: %v", err)
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
	if err := vault.AddVaultedFile(root, envPath, vault.KindEnv); err != nil {
		t.Fatalf("AddVaultedFile: %v", err)
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
	files, ferr := vault.ReadVaultedFiles(root)
	if ferr != nil {
		t.Fatalf("ReadVaultedFiles: %v", ferr)
	}
	if len(files) != 0 {
		t.Errorf("vault.meta must be empty after dry-run, got: %v", files)
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

	// Only GITHUB_TOKEN may be vaulted; both AWS_* are unrecognized post-cut
	// (the AWS provider was removed in the v1 launch cut).
	if len(res.Creds) != 1 || res.Creds[0].Name != "GITHUB_TOKEN" {
		t.Fatalf("Creds = %+v, want exactly GITHUB_TOKEN", res.Creds)
	}
	if len(res.Unrecognized) != 2 {
		t.Fatalf("Unrecognized len = %d, want 2 (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY)", len(res.Unrecognized))
	}
}

func TestBuildEnvFileCredentials_URLWithPasswordIsVaulted(t *testing.T) {
	envFile := scanner.ParseBytes([]byte(
		"DATABASE_URL=postgres://user:secret@db.prod.internal/app\n"))
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
	if len(res.Creds) != 1 || res.Creds[0].Name != "DATABASE_URL" {
		t.Fatalf("Creds = %+v, want exactly DATABASE_URL", res.Creds)
	}
	if len(res.Unrecognized) != 0 {
		t.Fatalf("Unrecognized = %+v, want empty (URL-with-password should be vaulted)", res.Unrecognized)
	}
	if len(res.NotManaged) != 0 {
		t.Fatalf("NotManaged = %+v, want empty", res.NotManaged)
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
	if len(res.Unrecognized) != 1 || res.Unrecognized[0].key != "WEIRD_SECRET" {
		t.Fatalf("Unrecognized = %+v, want exactly WEIRD_SECRET", res.Unrecognized)
	}
}

// TestBuildEnvFileCredentials_PopulatesCredReasons verifies that each entry
// in res.Creds has a parallel entry in res.CredReasons describing which
// detection gate fired.
func TestBuildEnvFileCredentials_PopulatesCredReasons(t *testing.T) {
	envFile := scanner.ParseBytes([]byte(
		"OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890abcdef\n" +
			"DATABASE_URL=postgres://u:longerpassword@db.prod.internal/app\n"))

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
	if len(res.Creds) != 2 {
		t.Fatalf("Creds len = %d, want 2", len(res.Creds))
	}
	if len(res.CredReasons) != len(res.Creds) {
		t.Fatalf("CredReasons len = %d, want %d (same as Creds)", len(res.CredReasons), len(res.Creds))
	}
	// OPENAI_API_KEY → provider:openai.
	openaiIdx := -1
	for i, c := range res.Creds {
		if c.Name == "OPENAI_API_KEY" {
			openaiIdx = i
		}
	}
	if openaiIdx == -1 {
		t.Fatal("OPENAI_API_KEY not in Creds")
	}
	if res.CredReasons[openaiIdx].Kind != placeholder.ReasonProvider {
		t.Errorf("OPENAI reason kind = %v, want ReasonProvider", res.CredReasons[openaiIdx].Kind)
	}
	if res.CredReasons[openaiIdx].Detail != "openai" {
		t.Errorf("OPENAI reason detail = %q, want %q", res.CredReasons[openaiIdx].Detail, "openai")
	}
	// DATABASE_URL → url userinfo.
	dbIdx := -1
	for i, c := range res.Creds {
		if c.Name == "DATABASE_URL" {
			dbIdx = i
		}
	}
	if dbIdx == -1 {
		t.Fatal("DATABASE_URL not in Creds")
	}
	if res.CredReasons[dbIdx].Kind != placeholder.ReasonURLUserinfo {
		t.Errorf("DATABASE_URL reason kind = %v, want ReasonURLUserinfo", res.CredReasons[dbIdx].Kind)
	}
}

// TestPrintDryRunVaultLines_SkipsNonEligibleByName guards against a
// counter-pairing regression: when secrets contain entries that didn't
// produce a Credential (not-managed / unrecognized), the dry-run output
// must skip them rather than print the next eligible credential's
// placeholder against the wrong key.
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

// TestPrintVaultSummary_AnnotatesManagedReason verifies that each Managed
// line in the summary carries a parenthesized annotation describing why
// the value was classified as a secret. The annotation is transparent
// info — it does not gate which credentials get vaulted.
func TestPrintVaultSummary_AnnotatesManagedReason(t *testing.T) {
	res := vaultBuildResult{
		Creds: []*vault.Credential{
			{Name: "OPENAI_API_KEY", Placeholder: "veilph-openai-XX"},
			{Name: "DATABASE_URL", Placeholder: "veilph-url-XX"},
		},
		CredReasons: []placeholder.Reason{
			{Kind: placeholder.ReasonProvider, Detail: "openai"},
			{Kind: placeholder.ReasonURLUserinfo},
		},
	}
	var buf bytes.Buffer
	printVaultSummary(&buf, res, false)
	out := buf.String()
	if !strings.Contains(out, "OPENAI_API_KEY") {
		t.Errorf("output missing OPENAI_API_KEY:\n%s", out)
	}
	if !strings.Contains(out, "(provider:openai)") {
		t.Errorf("output missing (provider:openai) annotation:\n%s", out)
	}
	if !strings.Contains(out, "(url)") {
		t.Errorf("output missing (url) annotation:\n%s", out)
	}
}
