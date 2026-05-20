package cli

import (
	"bytes"
	"io"
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

// TestAdd_DuplicateWithoutForce_PrintsOverwriteHint covers C2: the duplicate-
// detection branch in runAddInVault did `strings.Contains(err.Error(), "already
// exists")` but the actual vault error string is "vault: duplicate credential
// name: <name>" — so the hint never fired and the user saw a raw "adding
// credential: vault: duplicate credential name" leak. With
// errors.Is(vault.ErrDuplicateCredential) the user gets the actionable
// "already exists" message and the cliError carries the "--force to overwrite"
// hint.
func TestAdd_DuplicateWithoutForce_PrintsOverwriteHint(t *testing.T) {
	root := initProject(t)

	// First add succeeds.
	cmd := NewRoot("test")
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"add", "--path", root, "DUP_KEY",
		"--value", "first-value-1234567890abcdef",
		"--host", "api.example.com",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("first add failed: %v", err)
	}

	// Second add for the same name (no --force) must surface the
	// "already exists" message instead of a raw vault-package error string.
	cmd2 := NewRoot("test")
	cmd2.SetOut(io.Discard)
	cmd2.SetErr(io.Discard)
	cmd2.SetArgs([]string{
		"add", "--path", root, "DUP_KEY",
		"--value", "second-value-abcdef1234567890",
		"--host", "api.example.com",
	})
	err := cmd2.Execute()
	if err == nil {
		t.Fatal("expected duplicate add to fail without --force")
	}
	msg := err.Error()
	if !strings.Contains(msg, `credential "DUP_KEY" already exists`) {
		t.Errorf("expected friendly already-exists message, got: %q", msg)
	}
	if strings.Contains(msg, "duplicate credential name") {
		t.Errorf("user-facing message must not leak the raw vault error string, got: %q", msg)
	}
}

// TestAdd_RejectsURLShapedHost covers C4: --host accepted URL/scheme/path
// garbage, so `veil add NAME --host "https://api.com/"` landed a credential
// with an unreachable host pattern (proxy matches against bare hostnames).
// Validation must fail loud at input rather than silently store a dead
// credential.
func TestAdd_RejectsURLShapedHost(t *testing.T) {
	root := initProject(t)

	cases := []struct {
		name string
		host string
	}{
		{"https URL", "https://api.mycompany.com/"},
		{"http URL", "http://api.mycompany.com"},
		{"trailing slash", "api.com/"},
		{"with path", "api.com/v1/things"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewRoot("test")
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{
				"add", "--path", root, "INTERNAL_TOKEN",
				"--value", "real-value-1234567890abcdef",
				"--host", tc.host,
			})
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected --host %q to be rejected", tc.host)
			}
			msg := err.Error()
			if !strings.Contains(msg, "--host") {
				t.Errorf("error should mention --host, got: %q", msg)
			}
			if !strings.Contains(msg, tc.host) {
				t.Errorf("error should echo the bad value %q, got: %q", tc.host, msg)
			}
			// Make sure the credential did not land in the vault despite
			// validation failing.
			v, openErr := openVault(root)
			if openErr != nil {
				t.Fatalf("openVault: %v", openErr)
			}
			if _, found := v.Get("INTERNAL_TOKEN"); found {
				t.Errorf("credential must not be added when --host validation fails")
			}
		})
	}
}

// TestAdd_AcceptsHostPlainAndWildcard guards the happy path: bare hostnames,
// host:port, and *.suffix wildcards must still pass through unchanged so the
// hardened validator doesn't break existing scoping flows.
func TestAdd_AcceptsHostPlainAndWildcard(t *testing.T) {
	cases := []struct {
		credName string
		host     string
	}{
		{"PLAIN_TOKEN", "api.example.com"},
		{"WILDCARD_TOKEN", "*.internal.example.com"},
		{"PORT_TOKEN", "api.example.com:8443"},
	}
	for _, tc := range cases {
		t.Run(tc.credName, func(t *testing.T) {
			root := initProject(t)
			cmd := NewRoot("test")
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{
				"add", "--path", root, tc.credName,
				"--value", "ok-value-1234567890abcdef",
				"--host", tc.host,
			})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("expected --host %q to be accepted, got: %v", tc.host, err)
			}
			v, openErr := openVault(root)
			if openErr != nil {
				t.Fatalf("openVault: %v", openErr)
			}
			cred, ok := v.Get(tc.credName)
			if !ok {
				t.Fatalf("credential %s not stored", tc.credName)
			}
			if len(cred.AllowedHosts) != 1 || cred.AllowedHosts[0] != tc.host {
				t.Errorf("AllowedHosts = %v, want exactly [%q]", cred.AllowedHosts, tc.host)
			}
		})
	}
}

// TestAdd_NoHost_WarnsAllOutbound verifies that adding a credential without
// --host warns the user that the secret will be injected into every outbound
// request — not just a generic "no hosts detected" message.
func TestAdd_NoHost_WarnsAllOutbound(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader("unscoped-secret-1234567890ab"))
	cmd.SetArgs([]string{"add", "--path", root, "--value-stdin", "UNSCOPED_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "ALL outbound requests") {
		t.Errorf("expected warning about ALL outbound requests, got: %q", output)
	}
	if !strings.Contains(output, "--host") {
		t.Errorf("expected remediation hint mentioning --host, got: %q", output)
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
