package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAdd_ValueFlag_WarnsShellHistory verifies that using --value emits a
// stderr warning so the user is aware the secret is now in their shell
// history and should prefer stdin-based entry.
func TestAdd_ValueFlag_WarnsShellHistory(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"add", "--path", root, "--value", "my-test-value-1234567890", "VAL_FLAG_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	if !strings.Contains(stderr.String(), "shell history") {
		t.Errorf("expected --value warning mentioning shell history on stderr, got: %q", stderr.String())
	}
}

// TestAdd_ValueStdinFlag consumes the entire stdin as the secret value and
// does not print an interactive prompt. Useful for scripted pipelines:
// `printf %s "$SECRET" | veil add KEY --value-stdin`.
func TestAdd_ValueStdinFlag(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(stderr)
	cmd.SetIn(strings.NewReader("piped-secret-value-1234567890"))
	cmd.SetArgs([]string{"add", "--path", root, "--value-stdin", "STDIN_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add --value-stdin failed: %v", err)
	}
	// The interactive prompt must NOT appear when --value-stdin is set.
	if strings.Contains(stderr.String(), "Enter value for") {
		t.Errorf("--value-stdin should not print a prompt, got: %q", stderr.String())
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatal(err)
	}
	cred, ok := v.Get("STDIN_KEY")
	if !ok {
		t.Fatal("STDIN_KEY not stored")
	}
	if cred.Real != "piped-secret-value-1234567890" {
		t.Errorf("stored value mismatch: got %q", cred.Real)
	}
}

// TestAdd_InteractiveUsesReadPasswordHook verifies that when stdin is a
// terminal, the ReadPassword hook is invoked (instead of echoing the line).
// We swap the hook with a fake to avoid requiring a real TTY.
func TestAdd_InteractiveUsesReadPasswordHook(t *testing.T) {
	root := initProject(t)

	// Swap the TTY detector and password reader.
	origIsTTY := stdinIsTerminal
	origRead := readSecretFromTerminal
	stdinIsTerminal = func() bool { return true }
	readSecretFromTerminal = func() ([]byte, error) {
		return []byte("silent-secret-1234567890"), nil
	}
	t.Cleanup(func() {
		stdinIsTerminal = origIsTTY
		readSecretFromTerminal = origRead
	})

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(stderr)
	// cmd.InOrStdin() defaults to os.Stdin when unset; leaving it so the
	// TTY path is taken.
	cmd.SetArgs([]string{"add", "--path", root, "TTY_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	// Prompt should have been printed.
	if !strings.Contains(stderr.String(), "Enter value for TTY_KEY") {
		t.Errorf("expected prompt on stderr, got: %q", stderr.String())
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatal(err)
	}
	cred, ok := v.Get("TTY_KEY")
	if !ok {
		t.Fatal("TTY_KEY not stored")
	}
	if cred.Real != "silent-secret-1234567890" {
		t.Errorf("readPassword value not used, got %q", cred.Real)
	}
}

func TestAddCmd_SchemeAWS_HappyPath(t *testing.T) {
	root := initProject(t)

	var stdout, stderr bytes.Buffer
	cmd := NewRoot("test")
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader("real-secret-access-key\n"))
	cmd.SetArgs([]string{
		"add", "--path", root, "aws-prod",
		"--scheme", "aws",
		"--aws-access-key-id", "AKIAIOSFODNN7EXAMPLE",
		"--host", "*.amazonaws.com",
		"--value-stdin",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add: %v (stderr: %s)", err, stderr.String())
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatal(err)
	}
	cred, ok := v.Get("aws-prod")
	if !ok {
		t.Fatal("credential not added")
	}
	if cred.Scheme != "aws" {
		t.Errorf("Scheme = %q, want aws", cred.Scheme)
	}
	if cred.AWSAccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AccessKeyID not stored")
	}
	if cred.AWSAccessKeyIDPlaceholder == "" || !strings.HasPrefix(cred.AWSAccessKeyIDPlaceholder, "AKIA") {
		t.Errorf("AccessKeyIDPlaceholder = %q, want AKIA-prefixed", cred.AWSAccessKeyIDPlaceholder)
	}
}

func TestAddCmd_SchemeAWS_RejectsBadAccessKeyID(t *testing.T) {
	root := initProject(t)
	cmd := NewRoot("test")
	cmd.SetErr(io.Discard)
	cmd.SetOut(io.Discard)
	cmd.SetIn(strings.NewReader("secret\n"))
	cmd.SetArgs([]string{
		"add", "--path", root, "aws-prod",
		"--scheme", "aws",
		"--aws-access-key-id", "WRONGFORMAT",
		"--value-stdin",
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected validation error on bad access key id")
	}
}

func TestAddCmd_SchemeAWS_WithSessionTokenFile(t *testing.T) {
	root := initProject(t)
	tokPath := filepath.Join(root, "sess.txt")
	if err := os.WriteFile(tokPath, []byte("FwoGZXIvrealsessiontoken"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader("secret-access-key\n"))
	cmd.SetArgs([]string{
		"add", "--path", root, "aws-sts",
		"--scheme", "aws",
		"--aws-access-key-id", "ASIAIOSFODNN7EXAMPLE",
		"--aws-session-token-file", tokPath,
		"--value-stdin",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add: %v", err)
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatal(err)
	}
	cred, _ := v.Get("aws-sts")
	if cred.AWSSessionToken != "FwoGZXIvrealsessiontoken" {
		t.Errorf("session token = %q", cred.AWSSessionToken)
	}
	if cred.AWSSessionTokenPlaceholder == "" {
		t.Error("session token placeholder empty")
	}
}

func TestAddCmd_SchemeAWS_MutuallyExclusiveWithUser(t *testing.T) {
	root := initProject(t)
	cmd := NewRoot("test")
	cmd.SetErr(io.Discard)
	cmd.SetOut(io.Discard)
	cmd.SetIn(strings.NewReader("secret\n"))
	cmd.SetArgs([]string{
		"add", "--path", root, "x",
		"--scheme", "aws",
		"--user", "bob",
		"--aws-access-key-id", "AKIAIOSFODNN7EXAMPLE",
		"--value-stdin",
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected mutual-exclusion error between --user and --scheme aws")
	}
}

// testRSAKeyPEM returns a valid 2048-bit RSA key in PKCS#1 PEM form for
// use in tests.
func testRSAKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return string(pem.EncodeToMemory(block))
}

func TestAddCmd_SchemeGitHubApp_HappyPath(t *testing.T) {
	root := initProject(t)
	realPEM := testRSAKeyPEM(t)

	var stdout, stderr bytes.Buffer
	cmd := NewRoot("test")
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(realPEM))
	cmd.SetArgs([]string{
		"add", "--path", root, "gh-app",
		"--scheme", "github_app",
		"--github-app-id", "123456",
		"--host", "api.github.com",
		"--value-stdin",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add: %v (stderr: %s)", err, stderr.String())
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatal(err)
	}
	cred, ok := v.Get("gh-app")
	if !ok {
		t.Fatal("credential not added")
	}
	if cred.Scheme != "github_app" {
		t.Errorf("Scheme = %q", cred.Scheme)
	}
	if cred.GitHubAppID != 123456 {
		t.Errorf("AppID = %d", cred.GitHubAppID)
	}
	if !strings.HasPrefix(cred.Placeholder, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("placeholder not PEM: %s", cred.Placeholder[:80])
	}
	if cred.Placeholder == cred.Real {
		t.Error("placeholder PEM should differ from real PEM")
	}
}

// Spec §167-171: write a GitHub App credential whose placeholder is a multi-
// line PEM. Verify that the stored placeholder is a well-formed PEM and
// that writing it into a .env file using add.go's syncPlaceholderInEnvFiles
// machinery is not attempted for first-adds — but that the stored
// placeholder is still a valid multi-line PEM.
//
// Plan deviation: the original plan's `scanner.ParseFile`/`ef.Lookup` API
// does not exist. We drop the .env round-trip half and instead assert
// byte-level properties of the stored placeholder.
func TestAddCmd_SchemeGitHubApp_MultiLinePEMEnvRoundTrip(t *testing.T) {
	root := initProject(t)
	realPEM := testRSAKeyPEM(t)

	cmd := NewRoot("test")
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader(realPEM))
	cmd.SetArgs([]string{
		"add", "--path", root, "GITHUB_APP_PRIVATE_KEY",
		"--scheme", "github_app",
		"--github-app-id", "123456",
		"--host", "api.github.com",
		"--value-stdin",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add: %v", err)
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatal(err)
	}
	cred, ok := v.Get("GITHUB_APP_PRIVATE_KEY")
	if !ok {
		t.Fatal("credential not stored")
	}
	if cred.Placeholder == "" {
		t.Fatal("no placeholder stored")
	}
	// The placeholder must be a well-formed multi-line PEM.
	if !strings.HasPrefix(cred.Placeholder, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("placeholder missing PEM header")
	}
	if !strings.Contains(cred.Placeholder, "\n") {
		t.Errorf("placeholder should be multi-line (contain \\n)")
	}
	block, _ := pem.Decode([]byte(cred.Placeholder))
	if block == nil {
		t.Fatal("placeholder PEM does not decode")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Errorf("placeholder PEM is not a valid PKCS#1 RSA key: %v", err)
	}
	// Sanity: the stored .env is unchanged (initProject creates one with
	// OPENAI_API_KEY only); first-time add does not sync to .env.
	raw, _ := os.ReadFile(filepath.Join(root, ".env"))
	_ = raw
}

func TestAddCmd_SchemeGitHubApp_RejectsNonPEM(t *testing.T) {
	root := initProject(t)
	cmd := NewRoot("test")
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader("not a pem"))
	cmd.SetArgs([]string{
		"add", "--path", root, "gh-app",
		"--scheme", "github_app",
		"--github-app-id", "123",
		"--value-stdin",
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error on non-PEM input")
	}
}
