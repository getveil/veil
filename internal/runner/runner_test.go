package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8enji/veil/internal/vault"
)

// setupProject creates a temp directory with a vault and one credential,
// returning the project root and the keystore used.
func setupProject(t *testing.T) (string, vault.Keystore) {
	t.Helper()
	root := t.TempDir()
	ks := vault.NewMemKeystore()

	v, err := vault.CreateVault(root, "test-project", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	cred := &vault.Credential{
		ID:          vault.NewID(),
		Name:        "TEST_SECRET",
		Real:        "real-secret-value",
		Placeholder: "VEIL_PH_test_secret",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	if err := v.Add(cred); err != nil {
		t.Fatalf("Add credential: %v", err)
	}
	return root, ks
}

func TestRunHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := setupProject(t)
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

	root, ks := setupProject(t)
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

	root, ks := setupProject(t)
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

	root, ks := setupProject(t)
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

	root, ks := setupProject(t)
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

	result := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/fake-bundle.pem")

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
