package cli

import (
	"bytes"
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
