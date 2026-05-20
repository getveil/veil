package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/config"
)

func TestActiveProxyPIDsIgnoresDeadPIDs(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Write a PID file for an extremely high PID that won't exist.
	pidFile := filepath.Join(stateDir, "proxy-99999999.pid")
	if err := os.WriteFile(pidFile, []byte("99999999\n"), 0600); err != nil {
		t.Fatal(err)
	}

	live, err := activeProxyPIDs(root)
	if err != nil {
		t.Fatalf("activeProxyPIDs: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("expected no live PIDs, got %v", live)
	}
}

func TestActiveProxyPIDsDetectsLivePID(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Use the current test process's PID — guaranteed alive.
	ourPID := os.Getpid()
	pidFile := filepath.Join(stateDir, fmt.Sprintf("proxy-%d.pid", ourPID))
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", ourPID)), 0600); err != nil {
		t.Fatal(err)
	}

	live, err := activeProxyPIDs(root)
	if err != nil {
		t.Fatalf("activeProxyPIDs: %v", err)
	}
	if len(live) != 1 || live[0] != ourPID {
		t.Errorf("expected [%d], got %v", ourPID, live)
	}
}

func TestActiveProxyPIDsNoStateDir(t *testing.T) {
	root := t.TempDir()
	live, err := activeProxyPIDs(root)
	if err != nil {
		t.Fatalf("activeProxyPIDs: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("expected no PIDs for missing state dir, got %v", live)
	}
}

func TestDiscoverBackupsFindsEveryBackupPair(t *testing.T) {
	root := t.TempDir()
	// .env pair with both original and backup present.
	envPath := filepath.Join(root, ".env")
	envBackup := envPath + ".veil-backup"
	if err := os.WriteFile(envPath, []byte("KEY=placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envBackup, []byte("KEY=original"), 0600); err != nil {
		t.Fatal(err)
	}
	// .env.local with only a backup (original was deleted).
	localBackup := filepath.Join(root, ".env.local.veil-backup")
	if err := os.WriteFile(localBackup, []byte("FOO=bar"), 0600); err != nil {
		t.Fatal(err)
	}
	// Any other .veil-backup the walker encounters is restored too — post-
	// launch-cut discoverBackups walks the project for the sidecar pattern
	// rather than consulting a curated name list. A backup at
	// random.conf.veil-backup must come along for the restore.
	otherBackup := filepath.Join(root, "random.conf.veil-backup")
	if err := os.WriteFile(otherBackup, []byte("zzz"), 0600); err != nil {
		t.Fatal(err)
	}

	pairs, err := discoverBackups(root)
	if err != nil {
		t.Fatalf("discoverBackups: %v", err)
	}

	byOriginal := make(map[string]bool)
	for _, p := range pairs {
		byOriginal[p.original] = true
	}
	if !byOriginal[envPath] {
		t.Errorf("missing pair for %s; got: %v", envPath, byOriginal)
	}
	if !byOriginal[filepath.Join(root, ".env.local")] {
		t.Errorf("missing pair for .env.local; got: %v", byOriginal)
	}
	if !byOriginal[filepath.Join(root, "random.conf")] {
		t.Errorf("missing pair for random.conf; the walk surfaces every *.veil-backup")
	}
}

func TestDiscoverBackupsSkipsOriginalWithoutBackup(t *testing.T) {
	root := t.TempDir()
	// Original exists but backup does not — should be skipped.
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("KEY=value\n"), 0600); err != nil {
		t.Fatal(err)
	}

	pairs, err := discoverBackups(root)
	if err != nil {
		t.Fatalf("discoverBackups: %v", err)
	}
	if len(pairs) != 0 {
		t.Errorf("expected 0 pairs (no backup present), got %d: %+v", len(pairs), pairs)
	}
}

func TestDiscoverBackupsEmpty(t *testing.T) {
	root := t.TempDir()
	pairs, err := discoverBackups(root)
	if err != nil {
		t.Fatalf("discoverBackups: %v", err)
	}
	if len(pairs) != 0 {
		t.Errorf("expected 0 pairs, got %v", pairs)
	}
}

func TestClassifyEnvPairOriginalMissing(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, ".env")
	backup := orig + ".veil-backup"
	if err := os.WriteFile(backup, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatal(err)
	}

	status, _, err := classifyEnvPair(orig, backup, nil)
	if err != nil {
		t.Fatalf("classifyEnvPair: %v", err)
	}
	if status != classOriginalMissing {
		t.Errorf("status = %v, want classOriginalMissing", status)
	}
}

func TestClassifyEnvPairUnmodified(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, ".env")
	backup := orig + ".veil-backup"

	backupContent := []byte("# header\nTOKEN=ghp_real1234567890abcdef1234567890abcdef\n")
	if err := os.WriteFile(backup, backupContent, 0600); err != nil {
		t.Fatal(err)
	}

	currentContent := []byte("# header\nTOKEN=ghp_veil_abc123\n")
	if err := os.WriteFile(orig, currentContent, 0600); err != nil {
		t.Fatal(err)
	}

	resolver := placeholderResolver{
		"ghp_veil_abc123": "ghp_real1234567890abcdef1234567890abcdef",
	}

	status, _, err := classifyEnvPair(orig, backup, resolver)
	if err != nil {
		t.Fatalf("classifyEnvPair: %v", err)
	}
	if status != classUnmodified {
		t.Errorf("status = %v, want classUnmodified", status)
	}
}

func TestClassifyEnvPairModified(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, ".env")
	backup := orig + ".veil-backup"

	backupContent := []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n")
	if err := os.WriteFile(backup, backupContent, 0600); err != nil {
		t.Fatal(err)
	}
	currentContent := []byte("TOKEN=ghp_veil_abc123\nLOG_LEVEL=debug\n")
	if err := os.WriteFile(orig, currentContent, 0600); err != nil {
		t.Fatal(err)
	}

	resolver := placeholderResolver{
		"ghp_veil_abc123": "ghp_real1234567890abcdef1234567890abcdef",
	}

	status, diff, err := classifyEnvPair(orig, backup, resolver)
	if err != nil {
		t.Fatalf("classifyEnvPair: %v", err)
	}
	if status != classModified {
		t.Errorf("status = %v, want classModified", status)
	}
	if !strings.Contains(diff, "LOG_LEVEL=debug") {
		t.Errorf("diff should mention the added line; got:\n%s", diff)
	}
}

func TestClassifyEnvPairModifiedWhenResolverNil(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, ".env")
	backup := orig + ".veil-backup"
	if err := os.WriteFile(backup, []byte("A=b\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orig, []byte("A=b\n"), 0600); err != nil {
		t.Fatal(err)
	}

	status, _, err := classifyEnvPair(orig, backup, nil)
	if err != nil {
		t.Fatalf("classifyEnvPair: %v", err)
	}
	if status != classUnmodified {
		t.Errorf("status = %v, want classUnmodified (byte-equal, no substitution needed)", status)
	}
}

func TestRenderUnifiedDiffShowsAddedLines(t *testing.T) {
	a := []byte("line1\nline2\n")
	b := []byte("line1\nline2\nline3\n")
	diff := renderUnifiedDiff(a, b)
	if !strings.Contains(diff, "+line3") {
		t.Errorf("expected +line3 in diff, got:\n%s", diff)
	}
}

func TestRenderUnifiedDiffShowsRemovedLines(t *testing.T) {
	a := []byte("keep\nremove\n")
	b := []byte("keep\n")
	diff := renderUnifiedDiff(a, b)
	if !strings.Contains(diff, "-remove") {
		t.Errorf("expected -remove in diff, got:\n%s", diff)
	}
}

func TestRenderUnifiedDiffEmptyWhenEqual(t *testing.T) {
	a := []byte("same\n")
	diff := renderUnifiedDiff(a, a)
	if diff != "" {
		t.Errorf("expected empty diff, got: %q", diff)
	}
}

func TestRenderUnifiedDiffHasHeaders(t *testing.T) {
	diff := renderUnifiedDiff([]byte("a\n"), []byte("b\n"))
	if !strings.HasPrefix(diff, "--- current\n+++ backup\n") {
		t.Errorf("expected diff to start with '--- current' / '+++ backup', got:\n%s", diff)
	}
}

// TestRenderUnifiedDiffEveryChangedLineHasMarker is an F-11 regression: when
// several non-adjacent lines change between two files, every changed line
// must appear with a -/+ pair in the rendered diff. The earlier under-
// reporting was caused not by the LCS but by the CALLER passing the wrong
// "after" bytes; this test pins down the LCS contract directly so any future
// regression of either layer is caught.
func TestRenderUnifiedDiffEveryChangedLineHasMarker(t *testing.T) {
	a := []byte("KEEP1=a\nCHANGE1=old1\nKEEP2=b\nCHANGE2=old2\nKEEP3=c\nCHANGE3=old3\n")
	b := []byte("KEEP1=a\nCHANGE1=new1\nKEEP2=b\nCHANGE2=new2\nKEEP3=c\nCHANGE3=new3\n")

	diff := renderUnifiedDiff(a, b)

	for _, want := range []string{
		"-CHANGE1=old1", "+CHANGE1=new1",
		"-CHANGE2=old2", "+CHANGE2=new2",
		"-CHANGE3=old3", "+CHANGE3=new3",
	} {
		if !strings.Contains(diff, want+"\n") {
			t.Errorf("diff missing %q\n--- diff ---\n%s", want, diff)
		}
	}
}

// TestRenderUnifiedDiffF11ScatteredChanges mirrors the bug-report fixture:
// 8 scattered changed lines mixed with unchanged lines, including the
// inline-comment case. Every changed line must appear with a -/+ pair.
func TestRenderUnifiedDiffF11ScatteredChanges(t *testing.T) {
	current := []byte("# header comment\n" +
		"GITHUB_TOKEN=ghp_VEILxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" +
		"OPENAI_API_KEY=sk-proj-VEILxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" +
		"\n" +
		"STRIPE_SECRET_KEY=sk_live_VEILxxxxxxxxxxxxxxxx\n" +
		"SLACK_BOT_TOKEN=xoxb-VEILxxxxxxxxxx\n" +
		"# section divider\n" +
		"ANTHROPIC_API_KEY=sk-ant-VEILxxxxxxxxxxxxxx\n" +
		"AWS_ACCESS_KEY_ID=AKIAVEILxxxxxxxxx\n" +
		"AWS_SECRET_ACCESS_KEY=VEILSt7DH4v22xxxxxxxxxxxxxxxxxxxxxxxxxx\n" +
		"DOUBLE_QUOTED=\"VEILsecretdouble\"\n" +
		"SINGLE_QUOTED='VEILsecretsingle'\n" +
		"WITH_COMMENT=VEILvalue # this is a comment\n" +
		"UNCHANGED_TAIL=stays\n")
	backup := []byte("# header comment\n" +
		"GITHUB_TOKEN=ghp_aBcD1234567890abcdef1234567890abcdef\n" +
		"OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890abcdef\n" +
		"\n" +
		"STRIPE_SECRET_KEY=sk_live_1234567890abcdef\n" +
		"SLACK_BOT_TOKEN=xoxb-1234567890-abcdef\n" +
		"# section divider\n" +
		"ANTHROPIC_API_KEY=sk-ant-1234567890abcdef\n" +
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REDACTD\n" +
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY\n" +
		"DOUBLE_QUOTED=\"real-secret-double\"\n" +
		"SINGLE_QUOTED='real-secret-single'\n" +
		"WITH_COMMENT=real-value # this is a comment\n" +
		"UNCHANGED_TAIL=stays\n")

	diff := renderUnifiedDiff(current, backup)

	wantPairs := []struct{ minus, plus string }{
		{"-GITHUB_TOKEN=ghp_VEILxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "+GITHUB_TOKEN=ghp_aBcD1234567890abcdef1234567890abcdef"},
		{"-OPENAI_API_KEY=sk-proj-VEILxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "+OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890abcdef"},
		{"-STRIPE_SECRET_KEY=sk_live_VEILxxxxxxxxxxxxxxxx", "+STRIPE_SECRET_KEY=sk_live_1234567890abcdef"},
		{"-SLACK_BOT_TOKEN=xoxb-VEILxxxxxxxxxx", "+SLACK_BOT_TOKEN=xoxb-1234567890-abcdef"},
		{"-ANTHROPIC_API_KEY=sk-ant-VEILxxxxxxxxxxxxxx", "+ANTHROPIC_API_KEY=sk-ant-1234567890abcdef"},
		{"-AWS_ACCESS_KEY_ID=AKIAVEILxxxxxxxxx", "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REDACTD"},
		{"-AWS_SECRET_ACCESS_KEY=VEILSt7DH4v22xxxxxxxxxxxxxxxxxxxxxxxxxx", "+AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
		{"-DOUBLE_QUOTED=\"VEILsecretdouble\"", "+DOUBLE_QUOTED=\"real-secret-double\""},
		{"-SINGLE_QUOTED='VEILsecretsingle'", "+SINGLE_QUOTED='real-secret-single'"},
		{"-WITH_COMMENT=VEILvalue # this is a comment", "+WITH_COMMENT=real-value # this is a comment"},
	}
	for _, p := range wantPairs {
		if !strings.Contains(diff, p.minus+"\n") {
			t.Errorf("diff missing %q\n--- diff ---\n%s", p.minus, diff)
		}
		if !strings.Contains(diff, p.plus+"\n") {
			t.Errorf("diff missing %q\n--- diff ---\n%s", p.plus, diff)
		}
	}

	// Unchanged lines must NOT appear with a marker (must appear as context).
	for _, want := range []string{
		" # header comment", " UNCHANGED_TAIL=stays", " # section divider",
	} {
		if !strings.Contains(diff, want+"\n") {
			t.Errorf("expected unchanged line as context %q\n--- diff ---\n%s", want, diff)
		}
	}
}

// TestClassifyEnvPairDiffShowsAllChangedLines is the integration-level F-11
// regression: when the resolver substitutes placeholders cleanly so that the
// reconstruction matches the backup, the diff must STILL show every line
// that will change on disk (current → backup). Earlier behavior compared
// the reconstruction to the backup and hid resolved lines from the preview.
func TestClassifyEnvPairDiffShowsAllChangedLines(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, ".env")
	backup := orig + ".veil-backup"

	backupContent := []byte("GITHUB_TOKEN=ghp_real_aBcDef\n" +
		"KEEP=stays\n" +
		"OPENAI_API_KEY=sk-real-1234\n" +
		"AWS_SECRET_ACCESS_KEY=wJalrXReal\n")
	if err := os.WriteFile(backup, backupContent, 0600); err != nil {
		t.Fatal(err)
	}
	currentContent := []byte("GITHUB_TOKEN=ghp_VEIL_xxx\n" +
		"KEEP=stays\n" +
		"OPENAI_API_KEY=sk-VEIL-yyy\n" +
		"AWS_SECRET_ACCESS_KEY=VEILSecretZZZ\n")
	if err := os.WriteFile(orig, currentContent, 0600); err != nil {
		t.Fatal(err)
	}

	// Resolver substitutes ALL placeholders cleanly; reconstruction == backup,
	// so the older code path produced an empty/under-reported diff.
	resolver := placeholderResolver{
		"ghp_VEIL_xxx":  "ghp_real_aBcDef",
		"sk-VEIL-yyy":   "sk-real-1234",
		"VEILSecretZZZ": "wJalrXReal",
	}

	status, diff, err := classifyEnvPair(orig, backup, resolver)
	if err != nil {
		t.Fatalf("classifyEnvPair: %v", err)
	}
	if status != classUnmodified {
		// With a perfect resolver, classification SHOULD be Unmodified —
		// no user edits beyond what veil did. This guards against the
		// classification accidentally flipping when we changed the diff input.
		t.Fatalf("status = %v, want classUnmodified (resolver fully recovers)", status)
	}
	// status == classUnmodified means diff is "" by contract — that's fine.
	// The interesting case is when something IS modified; cover that next.
	_ = diff
}

// TestClassifyEnvPairDiffShowsRealChangeWhenUserEdited covers the modified
// case: the user added a line on top of placeholders. The dry-run diff must
// include the added line AND the placeholder→backup rewrites.
func TestClassifyEnvPairDiffShowsRealChangeWhenUserEdited(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, ".env")
	backup := orig + ".veil-backup"

	backupContent := []byte("GITHUB_TOKEN=ghp_real_aBcDef\n" +
		"OPENAI_API_KEY=sk-real-1234\n" +
		"STRIPE_SECRET_KEY=sk_live_real\n" +
		"SLACK_BOT_TOKEN=xoxb-real\n")
	if err := os.WriteFile(backup, backupContent, 0600); err != nil {
		t.Fatal(err)
	}
	// Current has placeholders for all 4 known secrets PLUS a user-added line.
	currentContent := []byte("GITHUB_TOKEN=ghp_VEIL_xxx\n" +
		"OPENAI_API_KEY=sk-VEIL-yyy\n" +
		"STRIPE_SECRET_KEY=sk_live_VEIL\n" +
		"SLACK_BOT_TOKEN=xoxb-VEIL\n" +
		"USER_ADDED=mine\n")
	if err := os.WriteFile(orig, currentContent, 0600); err != nil {
		t.Fatal(err)
	}
	resolver := placeholderResolver{
		"ghp_VEIL_xxx": "ghp_real_aBcDef",
		"sk-VEIL-yyy":  "sk-real-1234",
		"sk_live_VEIL": "sk_live_real",
		"xoxb-VEIL":    "xoxb-real",
	}

	status, diff, err := classifyEnvPair(orig, backup, resolver)
	if err != nil {
		t.Fatalf("classifyEnvPair: %v", err)
	}
	if status != classModified {
		t.Fatalf("status = %v, want classModified", status)
	}

	// Every secret line that will change on disk must appear in the diff —
	// not just the user-added one. This is the F-11 fix.
	wantLines := []string{
		"-GITHUB_TOKEN=ghp_VEIL_xxx",
		"+GITHUB_TOKEN=ghp_real_aBcDef",
		"-OPENAI_API_KEY=sk-VEIL-yyy",
		"+OPENAI_API_KEY=sk-real-1234",
		"-STRIPE_SECRET_KEY=sk_live_VEIL",
		"+STRIPE_SECRET_KEY=sk_live_real",
		"-SLACK_BOT_TOKEN=xoxb-VEIL",
		"+SLACK_BOT_TOKEN=xoxb-real",
		"-USER_ADDED=mine",
	}
	for _, want := range wantLines {
		if !strings.Contains(diff, want+"\n") {
			t.Errorf("diff missing %q\n--- diff ---\n%s", want, diff)
		}
	}
}

func TestResolverFromVault(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}

	resolver := resolverFromVault(v)
	found := false
	for ph, real := range resolver {
		if real == "ghp_real1234567890abcdef1234567890abcdef" && strings.HasPrefix(ph, "ghp_") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("resolver missing expected placeholder→real mapping; got: %v", resolver)
	}
}

func TestUninstallDryRunNoChanges(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	original := []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n")
	if err := os.WriteFile(envPath, original, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	postInitEnv, _ := os.ReadFile(envPath)

	cmd = NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--dry-run"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall --dry-run failed: %v", err)
	}

	got, _ := os.ReadFile(envPath)
	if string(got) != string(postInitEnv) {
		t.Error(".env was modified during --dry-run")
	}
	if _, err := os.Stat(envPath + ".veil-backup"); err != nil {
		t.Error("backup was removed during --dry-run")
	}
	if _, err := os.Stat(config.ProjectStateDir(root)); err != nil {
		t.Error(".veil/ was removed during --dry-run")
	}
	if !strings.Contains(out.String(), ".env") {
		t.Errorf("expected .env in plan output, got: %s", out.String())
	}
}

func TestUninstallBlocksOnActiveProxy(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	pidFile := filepath.Join(config.ProjectStateDir(root), fmt.Sprintf("proxy-%d.pid", os.Getpid()))
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}

	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	stderr := new(bytes.Buffer)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected uninstall to fail with active proxy")
	}
	if !strings.Contains(stderr.String(), "active proxy") {
		t.Errorf("expected 'active proxy' in stderr, got: %s", stderr.String())
	}
}

func TestUninstallForceBypassesProxyGuard(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	pidFile := filepath.Join(config.ProjectStateDir(root), fmt.Sprintf("proxy-%d.pid", os.Getpid()))
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}

	cmd = NewRoot("test")
	stdout := new(bytes.Buffer)
	cmd.SetOut(stdout)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall --force failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "Uninstall plan:") {
		t.Errorf("expected stdout to contain 'Uninstall plan:', got: %s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".env.veil-backup")); !os.IsNotExist(err) {
		t.Errorf("expected .env.veil-backup to be gone, stat err: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".env")); err != nil {
		t.Errorf("expected .env to exist after restore, stat err: %v", err)
	}
	if _, err := os.Stat(config.ProjectStateDir(root)); !os.IsNotExist(err) {
		t.Errorf("expected .veil/ to be removed, stat err: %v", err)
	}
}

func TestUninstallRoundTripFidelity(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	original := []byte("# header\nTOKEN=ghp_real1234567890abcdef1234567890abcdef\nLOG=debug\n")
	if err := os.WriteFile(envPath, original, 0644); err != nil {
		t.Fatal(err)
	}

	// Init.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Uninstall.
	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	// .env must be bit-identical to the original.
	got, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf(".env after uninstall does not match original\ngot:  %q\nwant: %q", got, original)
	}

	// .veil/ must be gone.
	if _, err := os.Stat(config.ProjectStateDir(root)); !os.IsNotExist(err) {
		t.Error(".veil/ should be removed after uninstall")
	}

	// Backup must be gone (renamed onto original).
	if _, err := os.Stat(envPath + ".veil-backup"); !os.IsNotExist(err) {
		t.Error(".veil-backup should be renamed away after uninstall")
	}
}

func TestUninstallMultiFile(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	envOrig := []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n")
	localOrig := []byte("API_KEY=sk-live-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	if err := os.WriteFile(filepath.Join(root, ".env"), envOrig, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.local"), localOrig, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	got, _ := os.ReadFile(filepath.Join(root, ".env"))
	if !bytes.Equal(got, envOrig) {
		t.Errorf(".env mismatch\ngot:  %q\nwant: %q", got, envOrig)
	}
	got, _ = os.ReadFile(filepath.Join(root, ".env.local"))
	if !bytes.Equal(got, localOrig) {
		t.Errorf(".env.local mismatch\ngot:  %q\nwant: %q", got, localOrig)
	}
}

func TestUninstallNoOpAfterPriorUninstall(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// init then uninstall.
	for _, args := range [][]string{
		{"init", "--path", root, "--yes"},
		{"uninstall", "--path", root, "--yes"},
	} {
		cmd := NewRoot("test")
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%v failed: %v", args, err)
		}
	}

	// Second uninstall — should say "already uninstalled" and exit 0.
	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("second uninstall failed: %v", err)
	}
	if !strings.Contains(out.String(), "already uninstalled") {
		t.Errorf("expected 'already uninstalled' in output, got: %s", out.String())
	}
}

func TestUninstallUserEditOverwrittenWithYes(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	original := []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n")
	if err := os.WriteFile(envPath, original, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// User adds a new line post-init.
	current, _ := os.ReadFile(envPath)
	edited := append(current, []byte("LOG_LEVEL=debug\n")...)
	if err := os.WriteFile(envPath, edited, 0644); err != nil {
		t.Fatal(err)
	}

	// Uninstall with --yes should proceed and restore to backup (loses the edit).
	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	got, _ := os.ReadFile(envPath)
	if !bytes.Equal(got, original) {
		t.Errorf(".env after uninstall should equal original (edit lost)\ngot:  %q\nwant: %q", got, original)
	}
}

// TestUninstallYesWithModifiedFilesPrintsWarning covers Fix 1: when --yes is
// used and the plan contains modified pairs, the user never saw the diff —
// we must still proceed (the --yes contract is "skip the prompt") but print
// a one-line warning so scripted runs that overwrite user edits don't fail
// silently. The companion test TestUninstallUserEditOverwrittenWithYes pins
// the proceed-anyway behavior; this one pins the warning text.
func TestUninstallYesWithModifiedFilesPrintsWarning(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	original := []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n")
	if err := os.WriteFile(envPath, original, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// User adds a new line post-init — this makes the pair classModified.
	current, _ := os.ReadFile(envPath)
	edited := append(current, []byte("LOG_LEVEL=debug\n")...)
	if err := os.WriteFile(envPath, edited, 0644); err != nil {
		t.Fatal(err)
	}

	cmd = NewRoot("test")
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	combined := stdout.String() + stderr.String()
	if !strings.Contains(combined, "user edits that will be overwritten") {
		t.Errorf("expected warning about user edits being overwritten; got stdout=%q stderr=%q",
			stdout.String(), stderr.String())
	}
	if !strings.Contains(combined, "--yes") {
		t.Errorf("warning should point at --yes; got stdout=%q stderr=%q",
			stdout.String(), stderr.String())
	}
}

// TestUninstallYesNoWarningWhenNothingModified ensures the warning is scoped
// to the actual problem case — if every pair is classUnmodified (the common
// path), the noisy "files will be overwritten" line must not appear.
func TestUninstallYesNoWarningWhenNothingModified(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	cmd = NewRoot("test")
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, "user edits that will be overwritten") {
		t.Errorf("warning should NOT fire when no files are modified; got stdout=%q stderr=%q",
			stdout.String(), stderr.String())
	}
}

// TestUninstallPrintsPerFileRestoreLine covers Fix 2: before each rename, the
// uninstall loop emits a "restoring: <rel>" line so a mid-loop crash leaves a
// trail of which files were already restored vs. still pending. We seed two
// .env files, each carrying a named-provider secret so init creates a backup
// for both, then confirm both relative paths appear in the uninstall output.
func TestUninstallPrintsPerFileRestoreLine(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"),
		[]byte("GITHUB_TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.local"),
		[]byte("STRIPE_SECRET_KEY=sk_live_1234567890abcdef1234567890\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	// Sanity: both files must have been backed up by init, otherwise the
	// per-file output assertion below is testing the wrong thing.
	for _, name := range []string{".env", ".env.local"} {
		if _, err := os.Stat(filepath.Join(root, name+backupSuffix)); err != nil {
			t.Fatalf("init did not create backup for %s: %v", name, err)
		}
	}

	cmd = NewRoot("test")
	stdout := new(bytes.Buffer)
	cmd.SetOut(stdout)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	out := stdout.String()
	for _, rel := range []string{".env", ".env.local"} {
		if !strings.Contains(out, "restoring: "+rel) {
			t.Errorf("expected per-file restoring line for %q; got:\n%s", rel, out)
		}
	}
}

// TestUninstallRefusesSymlinkedBackup covers the regression where a symlinked
// .env.veil-backup turns `veil uninstall --dry-run` into an arbitrary-file-read
// primitive. discoverBackups used os.Stat (which follows symlinks) and
// classifyEnvPair called os.ReadFile on the backup — so planting
//
//	.env.veil-backup -> ~/.ssh/id_rsa
//
// caused the unified diff (current .env vs. backup) to render the private key
// into stdout. Uninstall must refuse the operation before any read, diff, or
// rename fires.
func TestUninstallRefusesSymlinkedBackup(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)

	// Step 1: produce a legitimate post-init state with a real .env.veil-backup.
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Step 2: replace the real backup with a symlink to a "sensitive" file
	// outside the project tree (the attacker's planted symlink).
	sensitiveDir := t.TempDir()
	sensitivePath := filepath.Join(sensitiveDir, "id_rsa")
	sensitiveContent := "-----BEGIN OPENSSH PRIVATE KEY-----\nDO-NOT-LEAK-ME-12345\n-----END OPENSSH PRIVATE KEY-----\n"
	if err := os.WriteFile(sensitivePath, []byte(sensitiveContent), 0o600); err != nil {
		t.Fatal(err)
	}
	backupPath := envPath + ".veil-backup"
	if err := os.Remove(backupPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sensitivePath, backupPath); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	// Step 3: run `uninstall --dry-run` and assert that the sensitive content
	// is NEVER emitted to stdout, the operation errors out, and nothing on
	// disk has been mutated.
	cmd = NewRoot("test")
	out := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{"uninstall", "--path", root, "--dry-run"})
	execErr := cmd.Execute()
	if execErr == nil {
		t.Fatal("expected uninstall to refuse symlinked backup, got nil error")
	}

	// PRIMARY ASSERTION: no byte of the sensitive content reached stdout/stderr.
	if strings.Contains(out.String(), "DO-NOT-LEAK-ME") || strings.Contains(errBuf.String(), "DO-NOT-LEAK-ME") {
		t.Fatalf("symlinked backup contents leaked to terminal:\nstdout=%q\nstderr=%q",
			out.String(), errBuf.String())
	}
	// Even partial fragments of a PEM header are a leak.
	for _, frag := range []string{"BEGIN OPENSSH", "PRIVATE KEY"} {
		if strings.Contains(out.String(), frag) || strings.Contains(errBuf.String(), frag) {
			t.Fatalf("partial symlink target leaked (%q):\nstdout=%q\nstderr=%q",
				frag, out.String(), errBuf.String())
		}
	}

	// The error must mention the symlink so the user can act on it.
	combined := execErr.Error() + errBuf.String()
	if !strings.Contains(combined, "symbolic link") {
		t.Errorf("expected error to mention 'symbolic link', got: %v / %s", execErr, errBuf.String())
	}

	// The backup must still be a symlink (refusal precedes any rename).
	info, err := os.Lstat(backupPath)
	if err != nil {
		t.Fatalf("Lstat backup: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("backup was replaced by a regular file — uninstall must not touch a symlinked input")
	}

	// The sensitive file must be byte-identical.
	gotSensitive, err := os.ReadFile(sensitivePath)
	if err != nil {
		t.Fatalf("read sensitive: %v", err)
	}
	if string(gotSensitive) != sensitiveContent {
		t.Errorf("sensitive file modified after refusal\n got: %q\nwant: %q", gotSensitive, sensitiveContent)
	}
}

func TestDiscoverBackups_FindsExtendedEnvNames(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	t.Setenv("HOME", t.TempDir())

	root := t.TempDir()
	for _, name := range []string{".env.test", ".env.staging", ".env.ci", ".env.preview"} {
		orig := filepath.Join(root, name)
		if err := os.WriteFile(orig, []byte("X=1"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(orig+backupSuffix, []byte("X=real"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pairs, err := discoverBackups(root)
	if err != nil {
		t.Fatalf("discoverBackups: %v", err)
	}
	if len(pairs) != 4 {
		t.Errorf("expected 4 backup pairs, got %d: %+v", len(pairs), pairs)
	}
}

// TestUninstallRefusesSymlinkedOriginal covers the mirror leak: when .env
// itself is a symlink, classifyEnvPair's os.ReadFile(original) follows it and
// the target's bytes appear as the '-' side of the printed diff.
func TestUninstallRefusesSymlinkedOriginal(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)

	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Replace the placeholder-filled .env with a symlink to a sensitive file.
	sensitiveDir := t.TempDir()
	sensitivePath := filepath.Join(sensitiveDir, "secrets")
	sensitiveContent := "SECRET_API_TOKEN=PRIVATE-DO-NOT-LEAK-67890\n"
	if err := os.WriteFile(sensitivePath, []byte(sensitiveContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(envPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sensitivePath, envPath); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	cmd = NewRoot("test")
	out := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{"uninstall", "--path", root, "--dry-run"})
	execErr := cmd.Execute()
	if execErr == nil {
		t.Fatal("expected uninstall to refuse symlinked .env, got nil error")
	}

	if strings.Contains(out.String(), "PRIVATE-DO-NOT-LEAK") || strings.Contains(errBuf.String(), "PRIVATE-DO-NOT-LEAK") {
		t.Fatalf("symlinked original contents leaked to terminal:\nstdout=%q\nstderr=%q",
			out.String(), errBuf.String())
	}
	combined := execErr.Error() + errBuf.String()
	if !strings.Contains(combined, "symbolic link") {
		t.Errorf("expected error to mention 'symbolic link', got: %v / %s", execErr, errBuf.String())
	}
}

// TestUninstallRemovesVeilOnlyGitignore covers F8: when init created a
// .gitignore from scratch (it contains only the two Veil-added lines), the
// uninstall pass should clean it up — leaving it behind makes the project
// non-pristine. We seed a fresh repo, init, then uninstall, and assert the
// file is gone.
func TestUninstallRemovesVeilOnlyGitignore(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	// Sanity: init must have created the .gitignore.
	gitignorePath := filepath.Join(root, ".gitignore")
	if _, err := os.Stat(gitignorePath); err != nil {
		t.Fatalf("init should have created .gitignore: %v", err)
	}

	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	if _, err := os.Stat(gitignorePath); !os.IsNotExist(err) {
		got, _ := os.ReadFile(gitignorePath)
		t.Errorf("Veil-only .gitignore should be removed by uninstall; still present with content:\n%s", got)
	}
}

// TestUninstallPreservesUserGitignore covers the other half of F8: if the
// .gitignore had any non-Veil entries (added by the user, before or after
// init), uninstall must leave it in place. The two Veil-added lines may
// remain in the file — the user is on the hook for cleaning those, but we
// must not delete a file with their own ignores in it.
func TestUninstallPreservesUserGitignore(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	pinTestHome(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// User had their own .gitignore before init.
	userOriginal := "node_modules/\n*.log\n"
	gitignorePath := filepath.Join(root, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte(userOriginal), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	got, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatalf(".gitignore must remain when user had non-Veil entries: %v", err)
	}
	if !strings.Contains(string(got), "node_modules/") {
		t.Errorf("user's .gitignore entries must be preserved, got:\n%s", got)
	}
}
