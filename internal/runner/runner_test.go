package runner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8enji/veil/internal/testutil"
)

func TestRunHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := testutil.SetupVaultProject(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := Run(ctx, Config{
		Root:     root,
		Command:  "echo",
		Args:     []string{"hello"},
		Keystore: ks,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
}

func TestRunExitCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := testutil.SetupVaultProject(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := Run(ctx, Config{
		Root:     root,
		Command:  "sh",
		Args:     []string{"-c", "exit 42"},
		Keystore: ks,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 42 {
		t.Fatalf("ExitCode = %d, want 42", result.ExitCode)
	}
}

func TestRunChildEnv(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := testutil.SetupVaultProject(t)
	outFile := filepath.Join(t.TempDir(), "env-out.txt")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := Run(ctx, Config{
		Root:     root,
		Command:  "sh",
		Args:     []string{"-c", "printenv HTTPS_PROXY > " + outFile},
		Keystore: ks,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read env output: %v", err)
	}
	got := strings.TrimSpace(string(data))
	if !strings.HasPrefix(got, "http://127.0.0.1:") {
		t.Fatalf("HTTPS_PROXY = %q, want prefix http://127.0.0.1:", got)
	}
}

func TestRunCommandNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := testutil.SetupVaultProject(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := Run(ctx, Config{
		Root:     root,
		Command:  "/nonexistent/binary",
		Keystore: ks,
	})
	if err == nil {
		t.Fatal("expected error for nonexistent command")
	}
}

func TestRunChildCAEnvVars(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := testutil.SetupVaultProject(t)
	outFile := filepath.Join(t.TempDir(), "ca-env-out.txt")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := Run(ctx, Config{
		Root:     root,
		Command:  "sh",
		Args:     []string{"-c", "printenv SSL_CERT_FILE > " + outFile},
		Keystore: ks,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read env output: %v", err)
	}
	got := strings.TrimSpace(string(data))
	if !strings.HasSuffix(got, "ca-bundle.pem") {
		t.Fatalf("SSL_CERT_FILE = %q, want suffix ca-bundle.pem", got)
	}
}

// TestRunStripsVaultEnvAndAnnounces verifies SEC-1 end-to-end: a shell-exported
// var whose name matches a vault credential does NOT reach the child, and the
// startup stderr block loudly announces which names were stripped.
func TestRunStripsVaultEnvAndAnnounces(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := testutil.SetupVaultProject(t)
	outFile := filepath.Join(t.TempDir(), "child-env.txt")

	// Simulate the user exporting the managed secret in their shell.
	t.Setenv("TEST_SECRET", "real-secret-value-from-shell")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	result, err := Run(ctx, Config{
		Root:    root,
		Command: "sh",
		// Write the child's TEST_SECRET env to a file — empty if stripped.
		Args:     []string{"-c", "printenv TEST_SECRET > " + outFile + "; true"},
		Keystore: ks,
	})

	_ = w.Close()
	os.Stderr = oldStderr

	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read child env: %v", err)
	}
	if strings.Contains(string(data), "real-secret-value-from-shell") {
		t.Fatalf("child still saw real secret: %q — SEC-1 regression", data)
	}
	if strings.TrimSpace(string(data)) != "" {
		t.Fatalf("child TEST_SECRET should be empty after strip, got %q", data)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	stderr := buf.String()

	if !strings.Contains(stderr, "TEST_SECRET") {
		t.Errorf("startup warning must name the stripped var; stderr=\n%s", stderr)
	}
	// Loud UX: warning prefix or keyword should appear so the user cannot miss
	// that their shell env was intervened on.
	if !strings.Contains(strings.ToLower(stderr), "stripped") && !strings.Contains(strings.ToLower(stderr), "removed") {
		t.Errorf("startup warning should clearly say the env was stripped/removed; stderr=\n%s", stderr)
	}
}

// TestRunBannerShowsResolvedAgentPath verifies SEC-23: the startup banner
// records the realpath of the command that was executed (not the original
// unqualified name or a symlink), so that later forensic review can tell
// which binary the agent actually ran.
func TestRunBannerShowsResolvedAgentPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a symlink to /bin/echo (or the local echo) in a temp dir,
	// prepend the dir to PATH, and invoke by symlink name.
	echoPath, err := exec.LookPath("echo")
	if err != nil {
		t.Skipf("echo not in PATH: %v", err)
	}
	echoReal, err := filepath.EvalSymlinks(echoPath)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "shadow-echo")
	if err := os.Symlink(echoPath, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	root, ks := testutil.SetupVaultProject(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	result, err := Run(ctx, Config{
		Root:     root,
		Command:  "shadow-echo",
		Args:     []string{"hi"},
		Keystore: ks,
	})
	_ = w.Close()
	os.Stderr = oldStderr

	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	stderr := buf.String()

	if !strings.Contains(stderr, echoReal) {
		t.Errorf("startup banner should show realpath %q; stderr=\n%s", echoReal, stderr)
	}
}

func TestRunBookends(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := testutil.SetupVaultProject(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Capture stderr to check bookend output.
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	result, err := Run(ctx, Config{
		Root:     root,
		Command:  "echo",
		Args:     []string{"hello"},
		Keystore: ks,
	})

	_ = w.Close()
	os.Stderr = oldStderr

	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	stderr := buf.String()

	if !strings.Contains(stderr, "proxy active") {
		t.Errorf("startup line should contain 'proxy active', got: %q", stderr)
	}
	if !strings.Contains(stderr, "session complete") {
		t.Errorf("exit summary should contain 'session complete', got: %q", stderr)
	}
	if !strings.Contains(stderr, "Duration:") {
		t.Errorf("exit summary should contain 'Duration:', got: %q", stderr)
	}
}

func TestFormatStartupZeroCreds(t *testing.T) {
	msg := formatStartupWarning(0)
	if msg == "" {
		t.Error("expected warning message for zero credentials")
	}
	if !strings.Contains(msg, "No credentials") {
		t.Errorf("expected 'No credentials' in message, got: %s", msg)
	}
}

func TestFormatStartupWithCreds(t *testing.T) {
	msg := formatStartupWarning(5)
	if msg != "" {
		t.Errorf("expected empty message for non-zero credentials, got: %s", msg)
	}
}

func TestFormatExitSummary(t *testing.T) {
	tests := []struct {
		exitCode int
		want     string
	}{
		{0, "session complete"},
		{1, "session ended (exit 1)"},
		{130, "session ended (exit 130)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatExitSummary(tt.exitCode)
			if got != tt.want {
				t.Errorf("formatExitSummary(%d) = %q, want %q", tt.exitCode, got, tt.want)
			}
		})
	}
}

func TestBuildChildEnv(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"HOME=/home/test",
		"HTTP_PROXY=http://old-proxy:8080",
		"HTTPS_PROXY=http://old-proxy:8080",
		"http_proxy=http://old-proxy:8080",
		"https_proxy=http://old-proxy:8080",
		"NO_PROXY=old-no-proxy",
		"no_proxy=old-no-proxy",
		"OTHER_VAR=keep-me",
		"SSL_CERT_FILE=/old/ca.pem",
		"CURL_CA_BUNDLE=/old/curl-ca.pem",
		"REQUESTS_CA_BUNDLE=/old/requests-ca.pem",
	}

	result, _ := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/fake-bundle.pem", "/tmp/fake-truststore.p12", nil, nil)

	env := make(map[string]string)
	for _, kv := range result {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}

	// Verify old proxy vars are stripped.
	for _, kv := range result {
		if strings.Contains(kv, "old-proxy") || strings.Contains(kv, "old-no-proxy") {
			t.Fatalf("old proxy var not stripped: %s", kv)
		}
	}

	// Verify old CA vars are stripped.
	for _, kv := range result {
		if strings.Contains(kv, "/old/") {
			t.Fatalf("old CA var not stripped: %s", kv)
		}
	}

	// Verify new proxy vars are present.
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if env[key] != "http://127.0.0.1:9999" {
			t.Fatalf("%s = %q, want %q", key, env[key], "http://127.0.0.1:9999")
		}
	}
	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		if env[key] != "localhost,127.0.0.1,::1" {
			t.Fatalf("%s = %q, want %q", key, env[key], "localhost,127.0.0.1,::1")
		}
	}

	// Verify CA env vars all point to the bundle.
	caVars := []string{
		"NODE_EXTRA_CA_CERTS",
		"SSL_CERT_FILE",
		"CURL_CA_BUNDLE",
		"REQUESTS_CA_BUNDLE",
		"HTTPLIB2_CA_CERTS",
	}
	for _, key := range caVars {
		if env[key] != "/tmp/fake-bundle.pem" {
			t.Fatalf("%s = %q, want %q", key, env[key], "/tmp/fake-bundle.pem")
		}
	}

	// Verify non-proxy vars are preserved.
	if env["PATH"] != "/usr/bin" {
		t.Fatalf("PATH = %q, want /usr/bin", env["PATH"])
	}
	if env["OTHER_VAR"] != "keep-me" {
		t.Fatalf("OTHER_VAR = %q, want keep-me", env["OTHER_VAR"])
	}
}

func TestBuildChildEnv_MergesSkipHosts(t *testing.T) {
	env, _ := buildChildEnv([]string{"HOME=/home/user"}, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", []string{"staging.internal.com", "*.metrics.corp"}, nil)

	var noProxy string
	for _, kv := range env {
		if strings.HasPrefix(kv, "NO_PROXY=") {
			noProxy = strings.TrimPrefix(kv, "NO_PROXY=")
			break
		}
	}

	if noProxy == "" {
		t.Fatal("NO_PROXY not found in env")
	}
	if !strings.Contains(noProxy, "localhost") {
		t.Error("NO_PROXY should contain default localhost")
	}
	if !strings.Contains(noProxy, "staging.internal.com") {
		t.Error("NO_PROXY should contain staging.internal.com from skip_hosts")
	}
	if !strings.Contains(noProxy, "*.metrics.corp") {
		t.Error("NO_PROXY should contain *.metrics.corp from skip_hosts")
	}
}

func TestBuildChildEnv_EmptySkipHosts(t *testing.T) {
	env, _ := buildChildEnv([]string{"HOME=/home/user"}, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", nil, nil)

	var noProxy string
	for _, kv := range env {
		if strings.HasPrefix(kv, "NO_PROXY=") {
			noProxy = strings.TrimPrefix(kv, "NO_PROXY=")
			break
		}
	}
	// Should still have the defaults.
	want := "localhost,127.0.0.1,::1"
	if noProxy != want {
		t.Errorf("NO_PROXY = %q, want %q", noProxy, want)
	}
}

// TestBuildChildEnv_StripsVaultNamedEnvVar verifies that an env var whose name
// matches a loaded vault credential is removed from the child environment.
// This is SEC-1: if the user has exported OPENAI_API_KEY in their shell, the
// child must not see it — otherwise Veil's placeholder injection is bypassed.
func TestBuildChildEnv_StripsVaultNamedEnvVar(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"OPENAI_API_KEY=sk-real-live-secret",
		"AWS_ACCESS_KEY_ID=AKIAREAL",
		"OTHER_VAR=keep-me",
	}
	env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", nil, []string{"OPENAI_API_KEY", "AWS_ACCESS_KEY_ID"})

	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if k == "OPENAI_API_KEY" || k == "AWS_ACCESS_KEY_ID" {
			t.Fatalf("vault-named var leaked to child env: %s", kv)
		}
		if strings.Contains(kv, "sk-real-live-secret") || strings.Contains(kv, "AKIAREAL") {
			t.Fatalf("real secret value leaked to child env: %s", kv)
		}
	}

	if len(stripped) != 2 {
		t.Fatalf("stripped names len = %d, want 2 (%v)", len(stripped), stripped)
	}
	want := map[string]bool{"OPENAI_API_KEY": true, "AWS_ACCESS_KEY_ID": true}
	for _, n := range stripped {
		if !want[n] {
			t.Errorf("unexpected stripped name %q", n)
		}
	}
}

// TestBuildChildEnv_PassesThroughNonMatchingVar verifies that env vars whose
// names do NOT match any vault credential are preserved — the stripping
// targets vault-managed names only.
func TestBuildChildEnv_PassesThroughNonMatchingVar(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"LANG=en_US.UTF-8",
	}
	env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", nil, []string{"OPENAI_API_KEY"})

	if len(stripped) != 0 {
		t.Fatalf("stripped should be empty when no matches, got %v", stripped)
	}
	m := make(map[string]string)
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	for _, k := range []string{"PATH", "HOME", "LANG"} {
		if m[k] == "" {
			t.Errorf("expected %s to be preserved", k)
		}
	}
}

// TestBuildChildEnv_StripVaultNameCaseInsensitive verifies that matching is
// case-insensitive so that a credential named "openai_api_key" still strips
// a shell-exported "OPENAI_API_KEY".
func TestBuildChildEnv_StripVaultNameCaseInsensitive(t *testing.T) {
	base := []string{"OPENAI_API_KEY=shell-value"}
	env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", nil, []string{"openai_api_key"})

	for _, kv := range env {
		if strings.HasPrefix(kv, "OPENAI_API_KEY=") {
			t.Fatalf("case-insensitive match should have stripped: %s", kv)
		}
	}
	if len(stripped) != 1 || stripped[0] != "OPENAI_API_KEY" {
		t.Fatalf("stripped = %v, want [OPENAI_API_KEY]", stripped)
	}
}

// TestResolveAgentCommand_BareNameResolvesRealpath verifies that a bare
// command name is resolved to a realpath via LookPath+EvalSymlinks. This is
// SEC-23: we need a forensic record of which binary was actually executed so
// that a later shadow-binary attack via a writable PATH dir is auditable.
func TestResolveAgentCommand_BareNameResolvesRealpath(t *testing.T) {
	// Create a symlink in a temp dir that points to a real binary (sh),
	// prepend the dir to PATH, and resolve. The result must be the
	// symlink *target*, not the symlink itself.
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not in PATH: %v", err)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "myagent")
	if err := os.Symlink(shPath, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)

	got, err := resolveAgentCommand("myagent")
	if err != nil {
		t.Fatalf("resolveAgentCommand: %v", err)
	}

	wantReal, err := filepath.EvalSymlinks(shPath)
	if err != nil {
		t.Fatalf("EvalSymlinks(sh): %v", err)
	}
	if got != wantReal {
		t.Fatalf("resolveAgentCommand(myagent) = %q, want realpath %q (symlink target)", got, wantReal)
	}
}

// TestResolveAgentCommand_AbsolutePathThroughSymlink verifies that an
// absolute path is still resolved through symlinks.
func TestResolveAgentCommand_AbsolutePathThroughSymlink(t *testing.T) {
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not in PATH: %v", err)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "linked-sh")
	if err := os.Symlink(shPath, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	got, err := resolveAgentCommand(link)
	if err != nil {
		t.Fatalf("resolveAgentCommand(abs): %v", err)
	}
	wantReal, err := filepath.EvalSymlinks(shPath)
	if err != nil {
		t.Fatalf("EvalSymlinks(sh): %v", err)
	}
	if got != wantReal {
		t.Fatalf("resolveAgentCommand = %q, want %q", got, wantReal)
	}
}

// TestResolveAgentCommand_NotFound verifies that a nonexistent command
// returns an error.
func TestResolveAgentCommand_NotFound(t *testing.T) {
	if _, err := resolveAgentCommand("this-binary-absolutely-does-not-exist-xyzzy"); err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
}

// TestResolveAgentCommand_EmptyCommandIsError verifies that an empty command
// string is rejected up front.
func TestResolveAgentCommand_EmptyCommandIsError(t *testing.T) {
	if _, err := resolveAgentCommand(""); err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestSweepStaleSessionDirs(t *testing.T) {
	root := t.TempDir()
	stale, err := os.MkdirTemp(root, "veil-session-*")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(stale, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	SweepStaleSessionDirsForTest(root)

	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected stale dir removed, got err=%v", err)
	}
}

func TestSweepStaleSessionDirsLeavesFresh(t *testing.T) {
	root := t.TempDir()
	fresh, err := os.MkdirTemp(root, "veil-session-*")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	SweepStaleSessionDirsForTest(root)

	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh dir should survive, got err=%v", err)
	}
}
