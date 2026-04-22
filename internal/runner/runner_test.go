package runner

import (
	"bytes"
	"context"
	"errors"
	"os"
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

	result := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/fake-bundle.pem", nil)

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
	env := buildChildEnv([]string{"HOME=/home/user"}, "http://127.0.0.1:8080", "/tmp/bundle.pem", []string{"staging.internal.com", "*.metrics.corp"})

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
	env := buildChildEnv([]string{"HOME=/home/user"}, "http://127.0.0.1:8080", "/tmp/bundle.pem", nil)

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

func TestSweepStaleSessionDirs(t *testing.T) {
	root := os.TempDir()
	stale, err := os.MkdirTemp(root, "veil-session-*")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stale) })

	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(stale, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	SweepStaleSessionDirsForTest()

	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected stale dir removed, got err=%v", err)
	}
}

func TestSweepStaleSessionDirsLeavesFresh(t *testing.T) {
	root := os.TempDir()
	fresh, err := os.MkdirTemp(root, "veil-session-*")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(fresh) })

	SweepStaleSessionDirsForTest()

	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh dir should survive, got err=%v", err)
	}
}
