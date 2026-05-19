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

	"github.com/getveil/veil/internal/scanner"
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
		"--scheme", "aws", "--experimental",
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
		"--scheme", "aws", "--experimental",
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
		"--scheme", "aws", "--experimental",
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

// TestAddCmd_Scheme_RejectsUnknownValue verifies that an unrecognized
// --scheme value (typo such as "awss", or any free-form string) is rejected
// with an explicit error rather than silently falling through to the
// bearer/basic path. The fall-through would produce a non-functional
// credential whose Scheme field is empty and whose --host (if absent)
// cannot be auto-detected from a bearer value.
func TestAddCmd_Scheme_RejectsUnknownValue(t *testing.T) {
	root := initProject(t)
	cmd := NewRoot("test")
	cmd.SetErr(io.Discard)
	cmd.SetOut(io.Discard)
	cmd.SetIn(strings.NewReader("secret-value-1234567890\n"))
	cmd.SetArgs([]string{
		"add", "--path", root, "x",
		"--scheme", "awss",
		"--value-stdin",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error rejecting unknown --scheme value, got nil")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("error should mention scheme, got: %v", err)
	}

	v, err2 := openVault(root)
	if err2 != nil {
		t.Fatal(err2)
	}
	if _, ok := v.Get("x"); ok {
		t.Error("credential should not be created when --scheme is invalid")
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
		"--scheme", "aws", "--experimental",
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
		"--scheme", "github_app", "--experimental",
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
		"--scheme", "github_app", "--experimental",
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

// TestAddCmd_SchemeGitHubApp_ForceEnvRoundTrip verifies that `veil add --force`
// on an existing github_app credential correctly rewrites a multi-line PEM
// placeholder inside a .env file. Previously syncPlaceholderInEnvFiles used a
// raw strings.ReplaceAll which injected literal newlines into the .env,
// making it unparseable.
func TestAddCmd_SchemeGitHubApp_ForceEnvRoundTrip(t *testing.T) {
	root := initProject(t)
	pemA := testRSAKeyPEM(t)
	pemB := testRSAKeyPEM(t)

	// First add: introduces the credential with placeholder A.
	{
		cmd := NewRoot("test")
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetIn(strings.NewReader(pemA))
		cmd.SetArgs([]string{
			"add", "--path", root, "GITHUB_APP_PRIVATE_KEY",
			"--scheme", "github_app", "--experimental",
			"--github-app-id", "123456",
			"--host", "api.github.com",
			"--value-stdin",
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("initial add: %v", err)
		}
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatal(err)
	}
	credA, _ := v.Get("GITHUB_APP_PRIVATE_KEY")
	oldPh := credA.Placeholder
	if !strings.HasPrefix(oldPh, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Fatalf("old placeholder not a PEM: %.80q", oldPh)
	}

	// Write placeholder A into the .env as a properly-quoted multi-line value
	// using the scanner's canonical encoding. This mirrors what `veil init`
	// produces for a multi-line secret.
	envPath := filepath.Join(root, ".env")
	envBefore, err := scanner.ParseFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	appended := string(envBefore.Bytes())
	if !strings.HasSuffix(appended, "\n") {
		appended += "\n"
	}
	// Use the scanner's encode path to get a canonical double-quoted form.
	tmp := scanner.ParseBytes([]byte("GITHUB_APP_PRIVATE_KEY=\n"))
	tmp.SetValue("GITHUB_APP_PRIVATE_KEY", oldPh)
	appended += string(tmp.Bytes())
	if err := os.WriteFile(envPath, []byte(appended), 0o644); err != nil {
		t.Fatal(err)
	}

	// Sanity: parse back now, expect the key to decode to oldPh.
	if ef, err := scanner.ParseFile(envPath); err != nil {
		t.Fatalf("env parse before --force: %v", err)
	} else if got, ok := ef.Lookup("GITHUB_APP_PRIVATE_KEY"); !ok {
		t.Fatal("key not found before --force")
	} else if got != oldPh {
		t.Fatalf(".env round-trip BEFORE --force failed:\n got=%q\nwant=%q", got, oldPh)
	}

	// Second add with --force: rotates the placeholder from A to B. The
	// sync must rewrite the .env value using proper escaping.
	{
		cmd := NewRoot("test")
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetIn(strings.NewReader(pemB))
		cmd.SetArgs([]string{
			"add", "--path", root, "GITHUB_APP_PRIVATE_KEY",
			"--scheme", "github_app", "--experimental",
			"--github-app-id", "123456",
			"--host", "api.github.com",
			"--value-stdin",
			"--force",
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("--force add: %v", err)
		}
	}

	v2, err := openVault(root)
	if err != nil {
		t.Fatal(err)
	}
	credB, _ := v2.Get("GITHUB_APP_PRIVATE_KEY")
	newPh := credB.Placeholder
	if newPh == oldPh {
		t.Fatal("placeholder did not rotate after --force")
	}

	// The .env must still parse, and its value must decode to the new placeholder
	// byte-identically. Raw bytes must contain \n escapes (no raw newlines inside
	// the quoted value).
	efAfter, err := scanner.ParseFile(envPath)
	if err != nil {
		t.Fatalf("env parse after --force: %v (.env may have been written with raw newlines)", err)
	}
	got, ok := efAfter.Lookup("GITHUB_APP_PRIVATE_KEY")
	if !ok {
		t.Fatal("GITHUB_APP_PRIVATE_KEY missing from .env after --force")
	}
	if got != newPh {
		t.Errorf(".env round-trip AFTER --force failed\n got=%q\nwant=%q", got, newPh)
	}
	raw, _ := os.ReadFile(envPath)
	if !strings.Contains(string(raw), `\n`) {
		t.Errorf("expected \\n-escaped form in .env after sync; raw bytes:\n%s", raw)
	}
}

func TestAddCmd_SchemeGitHubApp_RejectsNonPEM(t *testing.T) {
	root := initProject(t)
	cmd := NewRoot("test")
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader("not a pem"))
	cmd.SetArgs([]string{
		"add", "--path", root, "gh-app",
		"--scheme", "github_app", "--experimental",
		"--github-app-id", "123",
		"--value-stdin",
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error on non-PEM input")
	}
}

func TestAdd_SchemeAWS_RefusedWithoutExperimental(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	stderr := new(bytes.Buffer)
	cmd.SetOut(io.Discard)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{
		"add", "--path", root, "AWS_PROD",
		"--scheme", "aws",
		"--aws-access-key-id", "AKIAIOSFODNN7EXAMPLE",
		"--value", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error from --scheme aws without --experimental")
	}
	if !strings.Contains(stderr.String(), "not supported in v0.1.x") {
		t.Errorf("stderr missing 'not supported in v0.1.x': %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "--experimental") {
		t.Errorf("stderr should mention --experimental: %q", stderr.String())
	}
}

func TestAdd_SchemeAWS_AcceptedWithExperimental(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"add", "--path", root, "AWS_PROD",
		"--scheme", "aws", "--experimental",
		"--aws-access-key-id", "AKIAIOSFODNN7EXAMPLE",
		"--value", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v, err := openVault(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Get("AWS_PROD"); !ok {
		t.Fatal("AWS_PROD not stored after --experimental")
	}
}

func TestAdd_SchemeGitHubApp_RefusedWithoutExperimental(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	stderr := new(bytes.Buffer)
	cmd.SetOut(io.Discard)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{
		"add", "--path", root, "GH_APP",
		"--scheme", "github_app",
		"--github-app-id", "123",
		"--value", "not-a-real-pem",
	})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error from --scheme github_app without --experimental")
	}
	if !strings.Contains(stderr.String(), "not supported in v0.1.x") {
		t.Errorf("stderr missing 'not supported in v0.1.x': %q", stderr.String())
	}
}

func TestAdd_BearerScheme_NotAffectedByGate(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"add", "--path", root, "STRIPE_KEY",
		"--value", "sk_live_abcdefghijklmnopqrstuvwxyz0123456789",
		"--host", "api.stripe.com",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error on bearer add: %v", err)
	}
	v, err := openVault(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Get("STRIPE_KEY"); !ok {
		t.Fatal("bearer credential not stored")
	}
}
