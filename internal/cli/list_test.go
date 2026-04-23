package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/vault"
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
		Real: "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n",
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
