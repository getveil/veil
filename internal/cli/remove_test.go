package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestRemove_YesFlagAlias is F5: `veil remove` must accept --yes as an alias
// for --force so the flag has the same meaning across `init`, `uninstall`,
// and `remove`. Pre-fix removeCmd only defined --force; the cross-command
// inconsistency burned users who learned --yes from `veil init`.
func TestRemove_YesFlagAlias(t *testing.T) {
	root := initProject(t)

	addCmd := NewRoot("test")
	addCmd.SetOut(new(bytes.Buffer))
	addCmd.SetErr(new(bytes.Buffer))
	addCmd.SetIn(strings.NewReader("alias-yes-value-1234567890\n"))
	addCmd.SetArgs([]string{"add", "--path", root, "ALIAS_YES"})
	if err := addCmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	rmCmd := NewRoot("test")
	rmOut := new(bytes.Buffer)
	rmCmd.SetOut(rmOut)
	rmCmd.SetErr(new(bytes.Buffer))
	rmCmd.SetArgs([]string{"remove", "--path", root, "--yes", "ALIAS_YES"})
	if err := rmCmd.Execute(); err != nil {
		t.Fatalf("remove --yes failed: %v", err)
	}
	if !strings.Contains(rmOut.String(), "Removed ALIAS_YES") {
		t.Errorf("expected removal confirmation with --yes, got: %s", rmOut.String())
	}
}

// TestRemove_NonTTYRefuses is F6: when stdin is not a TTY and neither --yes
// nor --force is passed, `veil remove NAME` must refuse with a non-zero exit
// and a clear error rather than silently "cancel" and remove nothing. The
// previous behavior left scripts piping into the command with no signal that
// nothing happened.
func TestRemove_NonTTYRefuses(t *testing.T) {
	root := initProject(t)

	addCmd := NewRoot("test")
	addCmd.SetOut(new(bytes.Buffer))
	addCmd.SetErr(new(bytes.Buffer))
	addCmd.SetIn(strings.NewReader("nontty-value-1234567890\n"))
	addCmd.SetArgs([]string{"add", "--path", root, "NONTTY"})
	if err := addCmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// A pipe read end is a real *os.File whose fd is not a TTY — this matches
	// the production scenario (`echo "" | veil remove NAME`). bytes.Buffer
	// would not work: detectInteractive falls back to "interactive" for any
	// non-*os.File reader, since tests in this package commonly inject one.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	defer func() { _ = pr.Close() }()

	rmCmd := NewRoot("test")
	rmCmd.SetOut(new(bytes.Buffer))
	rmCmd.SetErr(new(bytes.Buffer))
	rmCmd.SetIn(pr)
	rmCmd.SetArgs([]string{"remove", "--path", root, "NONTTY"})
	err = rmCmd.Execute()
	if err == nil {
		t.Fatal("expected error when stdin is non-TTY without --yes/--force")
	}
	if !strings.Contains(err.Error(), "no TTY") {
		t.Errorf("error should mention 'no TTY', got: %v", err)
	}
	if !strings.Contains(err.Error(), "--force") || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("error should mention both --force and --yes remedies, got: %v", err)
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := v.Get("NONTTY"); !found {
		t.Error("NONTTY should still exist after non-TTY refusal; silent cancel must not delete")
	}
}

// TestRemove_NonTTYWithForceRemoves verifies the escape hatch advertised by
// the F6 error message: --force (and --yes) must work over a non-TTY pipe.
func TestRemove_NonTTYWithForceRemoves(t *testing.T) {
	root := initProject(t)

	addCmd := NewRoot("test")
	addCmd.SetOut(new(bytes.Buffer))
	addCmd.SetErr(new(bytes.Buffer))
	addCmd.SetIn(strings.NewReader("force-pipe-value-1234567890\n"))
	addCmd.SetArgs([]string{"add", "--path", root, "PIPED_FORCE"})
	if err := addCmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	defer func() { _ = pr.Close() }()

	rmCmd := NewRoot("test")
	rmOut := new(bytes.Buffer)
	rmCmd.SetOut(rmOut)
	rmCmd.SetErr(new(bytes.Buffer))
	rmCmd.SetIn(pr)
	rmCmd.SetArgs([]string{"remove", "--path", root, "--force", "PIPED_FORCE"})
	if err := rmCmd.Execute(); err != nil {
		t.Fatalf("remove --force over pipe failed: %v", err)
	}
	if !strings.Contains(rmOut.String(), "Removed PIPED_FORCE") {
		t.Errorf("expected removal confirmation, got: %s", rmOut.String())
	}
}
