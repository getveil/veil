package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/vault"
)

// TestListCmd_TagsSchemes verifies that `veil list` renders scheme tags
// next to credential names: "(aws)", "(github app)", "(basic)".
func TestListCmd_TagsSchemes(t *testing.T) {
	root := initProject(t)

	v, err := openVault(root)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	if err := v.Add(&vault.Credential{
		ID: vault.NewID(), Name: "bearer-cred", Real: "r-bearer-1234567890",
		Placeholder:  "p-bearer",
		AllowedHosts: []string{"api.openai.com"},
		CreatedAt:    time.Now(),
	}); err != nil {
		t.Fatalf("add bearer: %v", err)
	}
	if err := v.Add(&vault.Credential{
		ID: vault.NewID(), Name: "aws-prod",
		Real: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", Placeholder: "p-aws",
		Scheme:                    "aws",
		AWSAccessKeyID:            "AKIAREAL000000000000",
		AWSAccessKeyIDPlaceholder: "AKIAPH00000000000000",
		AllowedHosts:              []string{"*.amazonaws.com"},
		CreatedAt:                 time.Now(),
	}); err != nil {
		t.Fatalf("add aws: %v", err)
	}
	if err := v.Add(&vault.Credential{
		ID: vault.NewID(), Name: "gh-app",
		Real:         "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n",
		Placeholder:  "-----BEGIN RSA PRIVATE KEY-----\nxyz\n-----END RSA PRIVATE KEY-----\n",
		Scheme:       "github_app",
		GitHubAppID:  111,
		AllowedHosts: []string{"api.github.com"},
		CreatedAt:    time.Now(),
	}); err != nil {
		t.Fatalf("add gh-app: %v", err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"list", "--path", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("list: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "bearer-cred") {
		t.Errorf("missing bearer-cred in:\n%s", s)
	}
	if !strings.Contains(s, "(aws)") {
		t.Errorf("missing (aws) tag in:\n%s", s)
	}
	if !strings.Contains(s, "(github app)") {
		t.Errorf("missing (github app) tag in:\n%s", s)
	}
}

// TestList_RevealRefusesWhenStdoutNotTTY guards against accidental pipes
// and redirects that would write real secrets to a file.
func TestList_RevealRefusesWhenStdoutNotTTY(t *testing.T) {
	root := initProject(t)

	// bytes.Buffer is never a TTY, and the default detector checks the
	// underlying file. Force the test path by disabling the override.
	origIsTTY := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdoutIsTerminal = origIsTTY })

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"list", "--path", root, "--reveal"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when stdout is not a TTY")
	}
	if !strings.Contains(err.Error(), "refusing") && !strings.Contains(err.Error(), "TTY") {
		t.Errorf("expected refusal message, got: %v", err)
	}
}

// TestList_RevealAllowedWithYes lets scripted callers override the TTY
// guard via --yes (same convention the init command uses).
func TestList_RevealAllowedWithYes(t *testing.T) {
	root := initProject(t)

	origIsTTY := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdoutIsTerminal = origIsTTY })

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"list", "--path", root, "--reveal", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("list --reveal --yes failed: %v", err)
	}
	if !strings.Contains(out.String(), "VALUE") {
		t.Errorf("expected VALUE column in output, got: %s", out.String())
	}
}

// TestList_RevealEmitsStderrWarning always prints a warning (regardless of
// TTY path) so piped output captures the notice.
func TestList_RevealEmitsStderrWarning(t *testing.T) {
	root := initProject(t)

	origIsTTY := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = origIsTTY })

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	stderr := new(bytes.Buffer)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"list", "--path", root, "--reveal"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("list --reveal failed: %v", err)
	}
	if !strings.Contains(stderr.String(), "warning") {
		t.Errorf("expected stderr warning, got: %q", stderr.String())
	}
}

// TestList_RevealLogsAudit records a single row per --reveal invocation so
// the action is visible in `veil log`.
func TestList_RevealLogsAudit(t *testing.T) {
	root := initProject(t)

	origIsTTY := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = origIsTTY })

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"list", "--path", root, "--reveal"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("list --reveal failed: %v", err)
	}

	store, err := audit.Open(config.AuditDBFile(root))
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	defer func() { _ = store.Close() }()

	rows, err := store.Query(audit.Filter{Limit: 100})
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	var found int
	for _, r := range rows {
		if r.Location == "reveal" {
			found++
		}
	}
	if found != 1 {
		t.Errorf("expected 1 reveal row, found %d", found)
	}
}

// TestList_AWSCredentialMultiRow verifies that an AWS-scheme credential
// renders as separate rows for AKID, secret, and (optional) session token,
// each labeled with the canonical AWS env-var name and paired with the
// corresponding value (or placeholder). Regression for F-5.
func TestList_AWSCredentialMultiRow(t *testing.T) {
	root := initProject(t)

	const (
		akid     = "AKIAREAL000000000000"
		akidPh   = "AKIAPH00000000000000"
		secret   = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
		secretPh = "wJaPHX00000000000000000000000000PLACEHO"
		sessTok  = "FwoGZXIvYXdzEJrSESSIONTOKEN1234567890"
		sessPh   = "FwoGZXPHESSIONTOKEN0000000000000000000"
	)

	v, err := openVault(root)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	if err := v.Add(&vault.Credential{
		ID: vault.NewID(), Name: "aws-with-token",
		Real: secret, Placeholder: secretPh,
		Scheme:                     "aws",
		AWSAccessKeyID:             akid,
		AWSAccessKeyIDPlaceholder:  akidPh,
		AWSSessionToken:            sessTok,
		AWSSessionTokenPlaceholder: sessPh,
		AllowedHosts:               []string{"*.amazonaws.com"},
		CreatedAt:                  time.Now(),
	}); err != nil {
		t.Fatalf("add aws: %v", err)
	}

	// Helper: locate the row containing label and assert value is also present
	// in the same line. This catches the F-5 bug where the AKID label was
	// paired with the secret access key value.
	findRowWith := func(t *testing.T, output, label, value string) {
		t.Helper()
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, label) && strings.Contains(line, value) {
				return
			}
		}
		t.Errorf("no row found with label %q and value %q in output:\n%s", label, value, output)
	}

	// Helper: assert that label does NOT appear paired with wrongValue
	// (e.g. AWS_ACCESS_KEY_ID line must not contain the secret access key).
	assertNotPaired := func(t *testing.T, output, label, wrongValue string) {
		t.Helper()
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, label) && strings.Contains(line, wrongValue) {
				t.Errorf("label %q must not appear with value %q on same line:\n%s", label, wrongValue, line)
			}
		}
	}

	// --reveal mode: real values should be paired with correct labels.
	origIsTTY := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = origIsTTY })

	revealCmd := NewRoot("test")
	revealOut := new(bytes.Buffer)
	revealCmd.SetOut(revealOut)
	revealCmd.SetErr(new(bytes.Buffer))
	revealCmd.SetArgs([]string{"list", "--path", root, "--reveal"})
	if err := revealCmd.Execute(); err != nil {
		t.Fatalf("list --reveal: %v", err)
	}
	revealStr := revealOut.String()

	findRowWith(t, revealStr, "AWS_ACCESS_KEY_ID", akid)
	findRowWith(t, revealStr, "AWS_SECRET_ACCESS_KEY", secret)
	findRowWith(t, revealStr, "AWS_SESSION_TOKEN", sessTok)
	// The buggy behavior pairs AWS_ACCESS_KEY_ID with the secret.
	assertNotPaired(t, revealStr, "AWS_ACCESS_KEY_ID", secret)

	// --placeholder mode: same row count and labels, placeholder values instead.
	phCmd := NewRoot("test")
	phOut := new(bytes.Buffer)
	phCmd.SetOut(phOut)
	phCmd.SetErr(new(bytes.Buffer))
	phCmd.SetArgs([]string{"list", "--path", root, "--placeholder"})
	if err := phCmd.Execute(); err != nil {
		t.Fatalf("list --placeholder: %v", err)
	}
	phStr := phOut.String()

	findRowWith(t, phStr, "AWS_ACCESS_KEY_ID", akidPh)
	findRowWith(t, phStr, "AWS_SECRET_ACCESS_KEY", secretPh)
	findRowWith(t, phStr, "AWS_SESSION_TOKEN", sessPh)
	assertNotPaired(t, phStr, "AWS_ACCESS_KEY_ID", secretPh)
}

// TestList_AWSCredentialNoSessionToken verifies that an AWS credential
// without a session token only emits AKID and secret rows (no session
// token row), in both --reveal and --placeholder modes.
func TestList_AWSCredentialNoSessionToken(t *testing.T) {
	root := initProject(t)

	const (
		akid     = "AKIANOSESSIONTOKEN00"
		akidPh   = "AKIAPHNOSESSION00000"
		secret   = "secretWithoutSessionToken1234567890ABCD"
		secretPh = "secretPHWithoutSessionToken0000000000PH"
	)

	v, err := openVault(root)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	if err := v.Add(&vault.Credential{
		ID: vault.NewID(), Name: "aws-no-token",
		Real: secret, Placeholder: secretPh,
		Scheme:                    "aws",
		AWSAccessKeyID:            akid,
		AWSAccessKeyIDPlaceholder: akidPh,
		AllowedHosts:              []string{"*.amazonaws.com"},
		CreatedAt:                 time.Now(),
	}); err != nil {
		t.Fatalf("add aws: %v", err)
	}

	origIsTTY := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = origIsTTY })

	for _, mode := range []string{"--reveal", "--placeholder"} {
		cmd := NewRoot("test")
		out := new(bytes.Buffer)
		cmd.SetOut(out)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"list", "--path", root, mode})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("list %s: %v", mode, err)
		}
		s := out.String()
		if !strings.Contains(s, "AWS_ACCESS_KEY_ID") {
			t.Errorf("%s: missing AWS_ACCESS_KEY_ID label:\n%s", mode, s)
		}
		if !strings.Contains(s, "AWS_SECRET_ACCESS_KEY") {
			t.Errorf("%s: missing AWS_SECRET_ACCESS_KEY label:\n%s", mode, s)
		}
		if strings.Contains(s, "AWS_SESSION_TOKEN") {
			t.Errorf("%s: should not emit AWS_SESSION_TOKEN row when no token present:\n%s", mode, s)
		}
	}
}

// TestList_AWSDetectionByAccessKeyID locks in the second branch of
// isAWSCred: a credential with AWSAccessKeyID set but Scheme == ""
// must still be tagged "(aws)" and expanded into per-secret rows.
func TestList_AWSDetectionByAccessKeyID(t *testing.T) {
	root := initProject(t)

	const (
		akid     = "AKIANOSCHEME00000000"
		akidPh   = "AKIAPHNOSCHEME000000"
		secret   = "secretWithoutSchemeField1234567890ABCDE"
		secretPh = "secretPHWithoutSchemeField00000000000PH"
	)

	v, err := openVault(root)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	if err := v.Add(&vault.Credential{
		ID: vault.NewID(), Name: "aws-no-scheme",
		Real: secret, Placeholder: secretPh,
		// Scheme intentionally left empty.
		AWSAccessKeyID:            akid,
		AWSAccessKeyIDPlaceholder: akidPh,
		AllowedHosts:              []string{"*.amazonaws.com"},
		CreatedAt:                 time.Now(),
	}); err != nil {
		t.Fatalf("add aws: %v", err)
	}

	origIsTTY := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = origIsTTY })

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"list", "--path", root, "--reveal"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("list --reveal: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "(aws)") {
		t.Errorf("expected (aws) tag for credential detected via AWSAccessKeyID:\n%s", s)
	}
	if !strings.Contains(s, "AWS_ACCESS_KEY_ID") || !strings.Contains(s, akid) {
		t.Errorf("expected AKID row with value %q:\n%s", akid, s)
	}
	if !strings.Contains(s, "AWS_SECRET_ACCESS_KEY") || !strings.Contains(s, secret) {
		t.Errorf("expected secret-key row with value %q:\n%s", secret, s)
	}
}
