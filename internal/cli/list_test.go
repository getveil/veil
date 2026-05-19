package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/config"
)

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
