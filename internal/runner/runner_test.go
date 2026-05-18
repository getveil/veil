package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/testutil"
	"github.com/oklog/ulid/v2"
)

// allowAllAmbientSecretLikes returns the list of env-var names in the current
// process environment that look secret-like per scanUnvaultedSecretLikes.
// Tests that exercise Run() use this as AllowEnvSecrets so they don't trip on
// the test runner's shell env (e.g. PATH, OAUTH tokens in CI). The contract
// under test is separately covered by TestRun_FailsClosedOnUnvaultedShellSecrets.
func allowAllAmbientSecretLikes() []string {
	return scanUnvaultedSecretLikes(os.Environ(), nil, nil)
}

func TestRunHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := testutil.SetupVaultProject(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := Run(ctx, Config{
		Root:            root,
		Command:         "echo",
		Args:            []string{"hello"},
		Keystore:        ks,
		AllowEnvSecrets: allowAllAmbientSecretLikes(),
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
		Root:            root,
		Command:         "sh",
		Args:            []string{"-c", "exit 42"},
		Keystore:        ks,
		AllowEnvSecrets: allowAllAmbientSecretLikes(),
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
		Root:            root,
		Command:         "sh",
		Args:            []string{"-c", "printenv HTTPS_PROXY > " + outFile},
		Keystore:        ks,
		AllowEnvSecrets: allowAllAmbientSecretLikes(),
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
		Root:            root,
		Command:         "/nonexistent/binary",
		Keystore:        ks,
		AllowEnvSecrets: allowAllAmbientSecretLikes(),
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
		Root:            root,
		Command:         "sh",
		Args:            []string{"-c", "printenv SSL_CERT_FILE > " + outFile},
		Keystore:        ks,
		AllowEnvSecrets: allowAllAmbientSecretLikes(),
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
		Args:            []string{"-c", "printenv TEST_SECRET > " + outFile + "; true"},
		Keystore:        ks,
		AllowEnvSecrets: allowAllAmbientSecretLikes(),
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
	// After strip, the child must see the placeholder under the same name,
	// not the real value and not an empty string.
	if got := strings.TrimSpace(string(data)); got != "VEIL_PH_test_secret" {
		t.Fatalf("child TEST_SECRET = %q, want placeholder %q", got, "VEIL_PH_test_secret")
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
		Root:            root,
		Command:         "shadow-echo",
		Args:            []string{"hi"},
		Keystore:        ks,
		AllowEnvSecrets: allowAllAmbientSecretLikes(),
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
		Root:            root,
		Command:         "echo",
		Args:            []string{"hello"},
		Keystore:        ks,
		AllowEnvSecrets: allowAllAmbientSecretLikes(),
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
		"ALL_PROXY=http://old-proxy:8080",
		"http_proxy=http://old-proxy:8080",
		"https_proxy=http://old-proxy:8080",
		"all_proxy=http://old-proxy:8080",
		"NO_PROXY=old-no-proxy",
		"no_proxy=old-no-proxy",
		"OTHER_VAR=keep-me",
		"SSL_CERT_FILE=/old/ca.pem",
		"CURL_CA_BUNDLE=/old/curl-ca.pem",
		"REQUESTS_CA_BUNDLE=/old/requests-ca.pem",
		"CARGO_HTTP_CAINFO=/old/cargo-ca.pem",
	}

	result, _, _ := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/fake-bundle.pem", "/tmp/fake-truststore.p12", "test-pw", nil, nil)

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
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
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
		"CARGO_HTTP_CAINFO",
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
	env, _, _ := buildChildEnv([]string{"HOME=/home/user"}, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", "test-pw", []string{"staging.internal.com", "*.metrics.corp"}, nil)

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
	env, _, _ := buildChildEnv([]string{"HOME=/home/user"}, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", "test-pw", nil, nil)

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
	env, stripped, _ := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", "test-pw", nil, []vaultEntry{
		{Name: "OPENAI_API_KEY", Placeholder: "VEIL_OPENAI_KEY_AAA"},
		{Name: "AWS_ACCESS_KEY_ID", Placeholder: "VEIL_AWS_BBB"},
	})

	for _, kv := range env {
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

	// New assertion: each stripped name must be re-injected with its placeholder.
	for _, want := range []string{"OPENAI_API_KEY=VEIL_OPENAI_KEY_AAA", "AWS_ACCESS_KEY_ID=VEIL_AWS_BBB"} {
		found := false
		for _, kv := range env {
			if kv == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("env missing placeholder re-injection %q", want)
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
	env, stripped, _ := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", "test-pw", nil, []vaultEntry{
		{Name: "OPENAI_API_KEY", Placeholder: "VEIL_OPENAI_KEY_AAA"},
	})

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

// TestBuildChildEnv_ReinjectsPlaceholderForStrippedVar verifies that when a
// shell-exported env var's name matches a vault credential, the real value
// is stripped AND the credential's placeholder is re-injected under the same
// name so the child still has a value (the placeholder) to send upstream.
func TestBuildChildEnv_ReinjectsPlaceholderForStrippedVar(t *testing.T) {
	base := []string{
		"HOME=/home/user",
		"OPENAI_API_KEY=sk-real-secret-value-1234567890",
	}
	vaultEntries := []vaultEntry{
		{Name: "OPENAI_API_KEY", Placeholder: "VEIL_OPENAI_API_KEY_XYZ"},
	}

	env, stripped, _ := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", "test-pw", nil, vaultEntries)

	if len(stripped) != 1 || stripped[0] != "OPENAI_API_KEY" {
		t.Fatalf("stripped = %v, want [OPENAI_API_KEY]", stripped)
	}
	// Real value must NOT appear.
	for _, kv := range env {
		if strings.Contains(kv, "sk-real-secret-value-1234567890") {
			t.Fatalf("real secret leaked into env: %q", kv)
		}
	}
	// Placeholder MUST appear, keyed by the original var name.
	want := "OPENAI_API_KEY=VEIL_OPENAI_API_KEY_XYZ"
	found := false
	for _, kv := range env {
		if kv == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("env missing re-injected placeholder %q; env=%v", want, env)
	}
}

// TestBuildChildEnv_StripVaultNameCaseInsensitive verifies that matching is
// case-insensitive so that a credential named "openai_api_key" still strips
// a shell-exported "OPENAI_API_KEY".
func TestBuildChildEnv_StripVaultNameCaseInsensitive(t *testing.T) {
	base := []string{"OPENAI_API_KEY=shell-value"}
	env, stripped, _ := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", "test-pw", nil, []vaultEntry{
		{Name: "openai_api_key", Placeholder: "VEIL_OPENAI_KEY_AAA"},
	})

	for _, kv := range env {
		if kv == "OPENAI_API_KEY=shell-value" {
			t.Fatalf("case-insensitive match should have stripped: %s", kv)
		}
	}
	if len(stripped) != 1 || stripped[0] != "OPENAI_API_KEY" {
		t.Fatalf("stripped = %v, want [OPENAI_API_KEY]", stripped)
	}
}

// TestBuildChildEnv_StripsVeilInternalKeys verifies that Veil's own control
// env vars never reach the agent. On Linux file-keystore systems VEIL_PASSPHRASE
// is sufficient (with read access to master.key.age) to decrypt the entire
// vault — so it must be stripped even though it is not a vault credential name.
// VEIL_TEST_KEYSTORE, VEIL_MCP_CONFIG_PATH, and VEIL_MCP_DISABLE_DISCOVERY
// could be used by an agent that shells out to "veil" to redirect Veil's
// own behavior; strip them too.
func TestBuildChildEnv_StripsVeilInternalKeys(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"VEIL_PASSPHRASE=correct-horse-battery-staple",
		"VEIL_TEST_KEYSTORE=mem",
		"VEIL_MCP_CONFIG_PATH=/tmp/agent-controlled.json",
		"VEIL_MCP_DISABLE_DISCOVERY=1",
		"OTHER_VAR=keep-me",
	}
	env, _, strippedInternal := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", "test-pw", nil, nil)

	leakValues := []string{"correct-horse-battery-staple", "mem", "/tmp/agent-controlled.json"}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if k == "VEIL_PASSPHRASE" || k == "VEIL_TEST_KEYSTORE" || k == "VEIL_MCP_CONFIG_PATH" || k == "VEIL_MCP_DISABLE_DISCOVERY" {
			t.Fatalf("veil-internal var %s reached agent env: %s", k, kv)
		}
		for _, leak := range leakValues {
			if v == leak {
				t.Fatalf("veil-internal value %q leaked under key %s", leak, k)
			}
		}
	}

	wantInternal := map[string]bool{
		"VEIL_PASSPHRASE":            true,
		"VEIL_TEST_KEYSTORE":         true,
		"VEIL_MCP_CONFIG_PATH":       true,
		"VEIL_MCP_DISABLE_DISCOVERY": true,
	}
	if len(strippedInternal) != len(wantInternal) {
		t.Fatalf("strippedInternal = %v, want all four keys", strippedInternal)
	}
	for _, n := range strippedInternal {
		if !wantInternal[n] {
			t.Errorf("unexpected stripped-internal name %q", n)
		}
	}

	// OTHER_VAR and PATH must pass through.
	foundOther, foundPath := false, false
	for _, kv := range env {
		if kv == "OTHER_VAR=keep-me" {
			foundOther = true
		}
		if kv == "PATH=/usr/bin" {
			foundPath = true
		}
	}
	if !foundOther {
		t.Error("OTHER_VAR was stripped; only veil-internal vars should be")
	}
	if !foundPath {
		t.Error("PATH was stripped; only veil-internal vars should be")
	}
}

// TestBuildChildEnv_VeilInternalCaseInsensitive verifies stripping is
// case-insensitive: veil_passphrase (lowercase) still must not reach the agent.
func TestBuildChildEnv_VeilInternalCaseInsensitive(t *testing.T) {
	base := []string{"veil_passphrase=secret"}
	env, _, strippedInternal := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", "test-pw", nil, nil)

	for _, kv := range env {
		if strings.Contains(kv, "secret") {
			t.Fatalf("case-insensitive match should have stripped: %s", kv)
		}
	}
	if len(strippedInternal) != 1 {
		t.Fatalf("strippedInternal = %v, want 1 entry", strippedInternal)
	}
}

// TestRunChildJavaTruststore verifies that Run() builds a per-session PKCS12
// truststore and exposes its path via JAVA_TOOL_OPTIONS. The child sh reads
// back JAVA_TOOL_OPTIONS and we assert the path points to a file with the
// expected suffix inside a tempdir that exists while the child runs.
func TestRunChildJavaTruststore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := testutil.SetupVaultProject(t)
	outFile := filepath.Join(t.TempDir(), "java-opts.txt")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := Run(ctx, Config{
		Root:            root,
		Command:         "sh",
		Args:            []string{"-c", "printenv JAVA_TOOL_OPTIONS > " + outFile},
		Keystore:        ks,
		AllowEnvSecrets: allowAllAmbientSecretLikes(),
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
	if !strings.Contains(got, "-Djavax.net.ssl.trustStore=") {
		t.Fatalf("JAVA_TOOL_OPTIONS missing trustStore flag: %q", got)
	}
	if !strings.Contains(got, "java-truststore.p12") {
		t.Fatalf("JAVA_TOOL_OPTIONS does not reference java-truststore.p12: %q", got)
	}
	if !strings.Contains(got, "-Djavax.net.ssl.trustStoreType=PKCS12") {
		t.Fatalf("JAVA_TOOL_OPTIONS missing trustStoreType=PKCS12: %q", got)
	}
}

// TestBuildChildEnv_InjectsJavaToolOptions verifies that buildChildEnv emits
// JAVA_TOOL_OPTIONS pointing at the per-session PKCS12 truststore when no
// pre-existing value is set. Veil's flags include the truststore path, type,
// and the per-session random password — both rendered as double-quoted
// segments so a path or password containing whitespace would still parse.
func TestBuildChildEnv_InjectsJavaToolOptions(t *testing.T) {
	base := []string{"PATH=/usr/bin"}
	env, _, _ := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/bundle.pem", "/tmp/ts.p12", "test-pw", nil, nil)

	var got string
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "JAVA_TOOL_OPTIONS" {
			got = v
			break
		}
	}
	if got == "" {
		t.Fatal("JAVA_TOOL_OPTIONS not set in child env")
	}
	want := `-Djavax.net.ssl.trustStore="/tmp/ts.p12" -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword="test-pw"`
	if got != want {
		t.Fatalf("JAVA_TOOL_OPTIONS = %q, want %q", got, want)
	}
}

// TestBuildChildEnv_MergesJavaToolOptions verifies that a pre-existing
// JAVA_TOOL_OPTIONS value is preserved, with Veil's flags appended AFTER the
// user's. Later -D flags win for the same Java system property, so Veil's
// truststore override is effective even if the user set their own.
func TestBuildChildEnv_MergesJavaToolOptions(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"JAVA_TOOL_OPTIONS=-Xmx2g -Dfoo=bar",
	}
	env, _, _ := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/bundle.pem", "/tmp/ts.p12", "test-pw", nil, nil)

	var got string
	count := 0
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "JAVA_TOOL_OPTIONS" {
			got = v
			count++
		}
	}
	if count != 1 {
		t.Fatalf("JAVA_TOOL_OPTIONS set %d times, want exactly 1", count)
	}
	want := `-Xmx2g -Dfoo=bar -Djavax.net.ssl.trustStore="/tmp/ts.p12" -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword="test-pw"`
	if got != want {
		t.Fatalf("JAVA_TOOL_OPTIONS = %q, want %q", got, want)
	}
}

// TestBuildChildEnv_EmptyJavaToolOptionsTreatedAsUnset verifies that an
// environment with JAVA_TOOL_OPTIONS set to the empty string is treated
// identically to one with the var unset — no leading whitespace, no
// pathological concatenation.
func TestBuildChildEnv_EmptyJavaToolOptionsTreatedAsUnset(t *testing.T) {
	base := []string{"JAVA_TOOL_OPTIONS="}
	env, _, _ := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/bundle.pem", "/tmp/ts.p12", "test-pw", nil, nil)

	var got string
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "JAVA_TOOL_OPTIONS" {
			got = v
			break
		}
	}
	want := `-Djavax.net.ssl.trustStore="/tmp/ts.p12" -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword="test-pw"`
	if got != want {
		t.Fatalf("JAVA_TOOL_OPTIONS = %q, want %q (no leading space)", got, want)
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

// TestRun_FailsClosedOnUnvaultedShellSecrets verifies that in non-interactive
// mode, a shell-exported secret-like env var that is not in the vault causes
// veil to refuse to launch the child.
func TestRun_FailsClosedOnUnvaultedShellSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Setenv("FAKE_PROVIDER_API_KEY", "sk-fake-highentropy-1234567890abcdef")

	root, ks := testutil.SetupVaultProject(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := Run(ctx, Config{
		Root:     root,
		Command:  "echo",
		Args:     []string{"hello"},
		Keystore: ks,
	})
	if err == nil {
		t.Fatal("Run succeeded with unvaulted shell secret; expected fail-closed error")
	}
	if !strings.Contains(err.Error(), "FAKE_PROVIDER_API_KEY") {
		t.Errorf("err = %v, want message naming FAKE_PROVIDER_API_KEY", err)
	}
}

// TestRun_AllowEnvSecretBypass verifies that --allow-env-secret permits a
// secret-like shell export to pass through.
func TestRun_AllowEnvSecretBypass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Setenv("FAKE_PROVIDER_API_KEY", "sk-fake-highentropy-1234567890abcdef")

	root, ks := testutil.SetupVaultProject(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := Run(ctx, Config{
		Root:            root,
		Command:         "echo",
		Args:            []string{"hello"},
		Keystore:        ks,
		AllowEnvSecrets: append(allowAllAmbientSecretLikes(), "FAKE_PROVIDER_API_KEY"),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
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

// fakeAuditFooterSource implements auditFooterSource for footer-rendering
// tests. It records whether Flush was called before Summary so the F-9
// regression test can assert the ordering invariant directly.
type fakeAuditFooterSource struct {
	total       int
	blocked     int
	leaked      int
	hosts       []string
	err         error
	flushed     bool
	summaryCall bool
	flushedAt   int // call counter when Flush ran (1 = first call)
	summaryAt   int // call counter when Summary ran
	calls       int
}

func (f *fakeAuditFooterSource) Flush() {
	f.calls++
	f.flushed = true
	f.flushedAt = f.calls
}

func (f *fakeAuditFooterSource) Summary(_ time.Time) (int, int, int, []string, *audit.Row, error) {
	f.calls++
	f.summaryCall = true
	f.summaryAt = f.calls
	return f.total, f.blocked, f.leaked, f.hosts, nil, f.err
}

// TestPrintSessionFooter_F9_RendersInjectionCount is the F-9 regression test:
// when N (>0) injections occurred and the audit source returns them, the
// footer must report `Injections: N across M host(s)` with both > 0 — not
// `0 across 0 hosts`.
func TestPrintSessionFooter_F9_RendersInjectionCount(t *testing.T) {
	src := &fakeAuditFooterSource{
		total:   3,
		blocked: 0,
		hosts:   []string{"api.example.com", "api.other.com"},
	}
	var buf bytes.Buffer
	printSessionFooter(&buf, src, time.Now(), 5*time.Second, 0)

	out := buf.String()
	want := "Injections:  3 across 2 host(s)"
	if !strings.Contains(out, want) {
		t.Fatalf("footer should contain %q, got:\n%s", want, out)
	}
	if strings.Contains(out, "0 across 0 hosts") {
		t.Errorf("footer regressed to F-9 zeros despite N=3 rows: %s", out)
	}
}

// TestPrintSessionFooter_F9_FlushesBeforeQuery enforces the fix: Flush must
// run before Summary, otherwise short sessions whose audit buffer never
// reached the 50-row auto-flush threshold see SELECT COUNT(*) return 0.
func TestPrintSessionFooter_F9_FlushesBeforeQuery(t *testing.T) {
	src := &fakeAuditFooterSource{total: 1, hosts: []string{"api.example.com"}}
	var buf bytes.Buffer
	printSessionFooter(&buf, src, time.Now(), time.Second, 0)

	if !src.flushed {
		t.Fatal("printSessionFooter must call Flush() so buffered rows reach the DB before Summary")
	}
	if !src.summaryCall {
		t.Fatal("printSessionFooter must call Summary()")
	}
	if src.flushedAt >= src.summaryAt {
		t.Fatalf("Flush must run BEFORE Summary; got flushedAt=%d summaryAt=%d", src.flushedAt, src.summaryAt)
	}
}

// TestPrintSessionFooter_LeaksRenderedSeparately verifies the footer
// distinguishes leaked rows from successful injections. A placeholder leak
// is a refused request — not a swap — so it must not increment the
// "Injections" counter. Instead, when N leaks occurred the footer shows a
// dedicated "Leaks: N" line.
func TestPrintSessionFooter_LeaksRenderedSeparately(t *testing.T) {
	src := &fakeAuditFooterSource{
		total:   1,
		blocked: 0,
		leaked:  2,
		hosts:   []string{"api.example.com"},
	}
	var buf bytes.Buffer
	printSessionFooter(&buf, src, time.Now(), 5*time.Second, 0)

	out := buf.String()
	if !strings.Contains(out, "Injections:  1 across 1 host(s)") {
		t.Errorf("footer should show only the 1 real injection, got:\n%s", out)
	}
	if !strings.Contains(out, "Leaks:       2") {
		t.Errorf("footer should show separate leak count of 2, got:\n%s", out)
	}
	if strings.Contains(out, "Injections:  3") {
		t.Errorf("footer must not roll leaks into injections, got:\n%s", out)
	}
}

// TestPrintSessionFooter_NoLeaksHidesLine verifies the "Leaks" line is
// omitted when no leaks occurred, keeping the common-case banner clean.
func TestPrintSessionFooter_NoLeaksHidesLine(t *testing.T) {
	src := &fakeAuditFooterSource{
		total:   1,
		blocked: 0,
		leaked:  0,
		hosts:   []string{"api.example.com"},
	}
	var buf bytes.Buffer
	printSessionFooter(&buf, src, time.Now(), time.Second, 0)
	if strings.Contains(buf.String(), "Leaks:") {
		t.Errorf("footer must not show 'Leaks:' line when leak count is zero, got:\n%s", buf.String())
	}
}

// TestPrintSessionFooter_SummaryError_ShowsUnavailable verifies the fallback
// path: if the audit query fails the user sees `(unavailable)` rather than
// silently zeroed counts.
func TestPrintSessionFooter_SummaryError_ShowsUnavailable(t *testing.T) {
	src := &fakeAuditFooterSource{err: errors.New("disk gone")}
	var buf bytes.Buffer
	printSessionFooter(&buf, src, time.Now(), time.Second, 0)

	out := buf.String()
	if !strings.Contains(out, "(unavailable)") {
		t.Errorf("footer should contain '(unavailable)' when Summary errs, got:\n%s", out)
	}
	if strings.Contains(out, "Injections:  0 across") {
		t.Errorf("footer must not silently print zeros on Summary error: %s", out)
	}
}

// TestPrintSessionFooter_F9_RealStoreShortSession is the integration form of
// the F-9 regression: drive the real audit.Store with a small number of
// recorded injections (well under the 50-row auto-flush threshold) and
// assert the footer renders the recorded count. Without Store.Flush() the
// rows would still be in the in-memory buffer when Summary runs.
func TestPrintSessionFooter_F9_RealStoreShortSession(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.sqlite")
	store, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	sessionStart := time.Now().UTC().Add(-time.Second)

	// Record N=4 successful injections across 2 distinct hosts. Far below
	// the 50-row auto-flush threshold, so they MUST still be in the buffer
	// at the moment printSessionFooter runs.
	hosts := []string{"api.openai.com", "api.openai.com", "api.anthropic.com", "api.anthropic.com"}
	for i, h := range hosts {
		store.Record(audit.Injection{
			Timestamp:      time.Now().UTC(),
			RequestID:      ulid.Make().String(),
			Host:           h,
			Method:         "POST",
			URLPath:        "/v1/test",
			CredentialID:   ulid.Make().String(),
			CredentialName: fmt.Sprintf("CRED_%d", i),
			AgentPID:       os.Getpid(),
			AgentCmd:       "test",
			BytesBefore:    16,
			BytesAfter:     32,
			Location:       "header",
		})
	}

	var buf bytes.Buffer
	printSessionFooter(&buf, store, sessionStart, time.Second, 0)

	out := buf.String()
	wantCount := "Injections:  4 across 2 host(s)"
	if !strings.Contains(out, wantCount) {
		t.Fatalf("F-9 regression: footer should report %q for 4 buffered rows, got:\n%s", wantCount, out)
	}
}
