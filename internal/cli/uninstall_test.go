package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8enji/veil/internal/config"
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

func TestDiscoverBackupsFindsEnvPairs(t *testing.T) {
	root := t.TempDir()
	// Valid pair: both original and backup exist.
	envPath := filepath.Join(root, ".env")
	envBackup := envPath + ".veil-backup"
	if err := os.WriteFile(envPath, []byte("KEY=placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envBackup, []byte("KEY=original"), 0600); err != nil {
		t.Fatal(err)
	}
	// Curated-name alternative: .env.local with only a backup (original deleted).
	localBackup := filepath.Join(root, ".env.local.veil-backup")
	if err := os.WriteFile(localBackup, []byte("FOO=bar"), 0600); err != nil {
		t.Fatal(err)
	}
	// Noise: a backup file with an unsupported name (should be ignored).
	randomBackup := filepath.Join(root, "random.conf.veil-backup")
	if err := os.WriteFile(randomBackup, []byte("zzz"), 0600); err != nil {
		t.Fatal(err)
	}

	pairs, err := discoverBackups(root)
	if err != nil {
		t.Fatalf("discoverBackups: %v", err)
	}

	// Expect exactly two env pairs (the curated names), none for MCP.
	byOriginal := make(map[string]bool)
	for _, p := range pairs {
		if p.kind == backupKindEnv {
			byOriginal[p.original] = true
		}
	}
	if !byOriginal[envPath] {
		t.Errorf("missing pair for %s; got: %v", envPath, byOriginal)
	}
	if !byOriginal[filepath.Join(root, ".env.local")] {
		t.Errorf("missing pair for .env.local; got: %v", byOriginal)
	}
	if byOriginal[filepath.Join(root, "random.conf")] {
		t.Errorf("unexpected pair for non-curated file: random.conf")
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

func TestDiscoverBackupsIncludesMCPWhenDiscoverable(t *testing.T) {
	root := t.TempDir()
	// Set up a fake MCP config + backup via the test env var.
	mcpDir := t.TempDir()
	mcpPath := filepath.Join(mcpDir, "claude_desktop_config.json")
	if err := os.WriteFile(mcpPath, []byte(`{"mcpServers":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mcpPath+".veil-backup", []byte(`{"mcpServers":{"x":{}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_MCP_CONFIG_PATH", mcpPath)

	pairs, err := discoverBackups(root)
	if err != nil {
		t.Fatalf("discoverBackups: %v", err)
	}

	found := false
	for _, p := range pairs {
		if p.kind == backupKindMCP && p.original == mcpPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected MCP pair in results; got: %+v", pairs)
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
	if !strings.HasPrefix(diff, "--- backup\n+++ current\n") {
		t.Errorf("expected diff to start with '--- backup' / '+++ current', got:\n%s", diff)
	}
}

func TestClassifyMCPPairUnmodified(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "claude_desktop_config.json")
	backup := orig + ".veil-backup"

	// backupContent must be in Bytes()-formatted form (2-space indent) because
	// expectedOriginalMCP re-serializes through cfg.Bytes(). The backup
	// represents the file before Veil touched it; Veil's init also writes via
	// Bytes(), so the user's pre-existing file must already be in that shape
	// for the Unmodified case to match.
	backupContent := []byte("{\n  \"mcpServers\": {\n    \"x\": {\n      \"command\": \"\",\n      \"env\": {\n        \"TOKEN\": \"real-value\"\n      }\n    }\n  }\n}\n")
	if err := os.WriteFile(backup, backupContent, 0600); err != nil {
		t.Fatal(err)
	}
	currentContent := []byte("{\n  \"mcpServers\": {\n    \"x\": {\n      \"command\": \"\",\n      \"env\": {\n        \"TOKEN\": \"ghp_veil_abc\"\n      }\n    }\n  }\n}\n")
	if err := os.WriteFile(orig, currentContent, 0600); err != nil {
		t.Fatal(err)
	}

	resolver := placeholderResolver{"ghp_veil_abc": "real-value"}

	status, _, err := classifyMCPPair(orig, backup, resolver)
	if err != nil {
		t.Fatalf("classifyMCPPair: %v", err)
	}
	if status != classUnmodified {
		t.Errorf("status = %v, want classUnmodified", status)
	}
}

func TestClassifyMCPPairModified(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "claude_desktop_config.json")
	backup := orig + ".veil-backup"

	// backupContent in Bytes()-formatted form (only server "x").
	backupContent := []byte("{\n  \"mcpServers\": {\n    \"x\": {\n      \"command\": \"\",\n      \"env\": {\n        \"TOKEN\": \"real\"\n      }\n    }\n  }\n}\n")
	if err := os.WriteFile(backup, backupContent, 0600); err != nil {
		t.Fatal(err)
	}
	// Current has placeholder for TOKEN and a new server "y" added by the user.
	currentContent := []byte("{\n  \"mcpServers\": {\n    \"x\": {\n      \"command\": \"\",\n      \"env\": {\n        \"TOKEN\": \"ghp_veil_abc\"\n      }\n    },\n    \"y\": {\n      \"command\": \"\",\n      \"env\": {\n        \"OTHER\": \"new\"\n      }\n    }\n  }\n}\n")
	if err := os.WriteFile(orig, currentContent, 0600); err != nil {
		t.Fatal(err)
	}

	resolver := placeholderResolver{"ghp_veil_abc": "real"}

	status, _, err := classifyMCPPair(orig, backup, resolver)
	if err != nil {
		t.Fatalf("classifyMCPPair: %v", err)
	}
	if status != classModified {
		t.Errorf("status = %v, want classModified", status)
	}
}

func TestClassifyMCPPairOriginalMissing(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "claude_desktop_config.json")
	backup := orig + ".veil-backup"
	if err := os.WriteFile(backup, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}

	status, _, err := classifyMCPPair(orig, backup, nil)
	if err != nil {
		t.Fatalf("classifyMCPPair: %v", err)
	}
	if status != classOriginalMissing {
		t.Errorf("status = %v, want classOriginalMissing", status)
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

// TestUninstallRestoresMCPConfigOutsideProjectRoot is the F-13 regression
// guard. It initializes a project where the MCP config lives outside the
// project root (via VEIL_MCP_CONFIG_PATH), then runs uninstall and confirms
// the out-of-root file is restored to its original bytes AND its .veil-backup
// is removed. The previous bug: discoverBackups only scanned the project root,
// so the MCP file's backup survived uninstall and the placeholder remained.
func TestUninstallRestoresMCPConfigOutsideProjectRoot(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("HOSTNAME=myserver\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mcpDir := t.TempDir() // deliberately outside `root`
	mcpPath := filepath.Join(mcpDir, "claude_desktop_config.json")
	originalMCP := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "env": {
        "GITHUB_TOKEN": "ghp_real1234567890abcdef1234567890abcdef"
      }
    }
  }
}`
	if err := os.WriteFile(mcpPath, []byte(originalMCP), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_MCP_CONFIG_PATH", mcpPath)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	postInit, err := os.ReadFile(mcpPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(postInit), "ghp_real1234567890abcdef1234567890abcdef") {
		t.Fatal("init did not replace the real token; preconditions broken")
	}
	if _, err := os.Stat(mcpPath + ".veil-backup"); err != nil {
		t.Fatalf("init did not create backup: %v", err)
	}

	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	restored, err := os.ReadFile(mcpPath)
	if err != nil {
		t.Fatalf("MCP config missing after uninstall: %v", err)
	}
	if string(restored) != originalMCP {
		t.Errorf("MCP config not restored to pre-Veil bytes\ngot:  %q\nwant: %q", restored, originalMCP)
	}
	if _, err := os.Stat(mcpPath + ".veil-backup"); !os.IsNotExist(err) {
		t.Errorf("MCP backup should be removed after uninstall, stat err: %v", err)
	}
}

// TestInitFailsLoudlyOnOrphanBackupOutsideProjectRoot is the F-12 regression
// guard. The brief allows either a hard error OR a successful re-vault — what
// must not happen is the silent-skip outcome (the old behaviour). This test
// asserts the chosen behaviour: re-vault from the orphan, ending up with the
// same vaulted set as the first init.
func TestInitFailsLoudlyOnOrphanBackupOutsideProjectRoot(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("HOSTNAME=myserver\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mcpDir := t.TempDir() // outside root
	mcpPath := filepath.Join(mcpDir, "claude_desktop_config.json")
	originalMCP := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "env": {
        "GITHUB_TOKEN": "ghp_real1234567890abcdef1234567890abcdef"
      }
    }
  }
}`
	if err := os.WriteFile(mcpPath, []byte(originalMCP), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_MCP_CONFIG_PATH", mcpPath)

	// First init: vaults the MCP secret, leaves a backup behind.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("first init failed: %v", err)
	}

	// Simulate a wiped registry: blow away .veil/ but leave the placeholder-
	// filled MCP file and the .veil-backup in place. This is exactly the F-12
	// scenario: an interrupted/older Veil left an orphan behind.
	if err := os.RemoveAll(config.ProjectStateDir(root)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mcpPath + ".veil-backup"); err != nil {
		t.Fatalf("preconditions: orphan backup missing: %v", err)
	}

	// Second init: must NOT silently skip. The orphan-reclaim path re-vaults
	// using the backup as the source of truth.
	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	stderr := new(bytes.Buffer)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("second init failed: %v", err)
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	cred, ok := v.Get("mcp:github:GITHUB_TOKEN")
	if !ok {
		t.Fatal("re-init silently dropped the MCP secret (F-12 regression)")
	}
	if cred.Real != "ghp_real1234567890abcdef1234567890abcdef" {
		t.Errorf("re-init captured wrong real value (must come from orphan backup); got %q", cred.Real)
	}
	if !strings.Contains(stderr.String(), "orphaned backup") {
		t.Errorf("expected user-visible 'orphaned backup' notice on stderr, got: %s", stderr.String())
	}
}
