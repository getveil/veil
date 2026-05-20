package cli_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/cli"
	"github.com/getveil/veil/internal/proxy"
	"github.com/getveil/veil/internal/vault"
)

func TestMapRunError(t *testing.T) {
	cases := []struct {
		name           string
		in             error
		expectMsg      string
		notExpectMsg   string
		expectSentinel error
	}{
		// vault.meta missing — must NOT recommend `init --force` (the user has
		// no vault to lose, and the message would imply one existed).
		{
			name:           "vault meta missing",
			in:             fmt.Errorf("open vault: %w: read meta file: %w", vault.ErrOpen, fs.ErrNotExist),
			expectMsg:      "not initialized",
			notExpectMsg:   "--force",
			expectSentinel: cli.ErrNotInitialized,
		},
		// Keystore unavailable — most commonly VEIL_PASSPHRASE unset on a Linux
		// box without a system keyring. The previous "keychain may have
		// changed, run init --force" hint was actively wrong here: --force
		// would destroy the vault without solving the actual problem (missing
		// passphrase). The fix routes this case through a dedicated arm that
		// names VEIL_PASSPHRASE explicitly and does NOT recommend --force.
		{
			name:         "keystore passphrase missing",
			in:           fmt.Errorf("open vault: %w: %w: %s is not set", vault.ErrOpen, vault.ErrPassphraseMissing, "VEIL_PASSPHRASE"),
			expectMsg:    "VEIL_PASSPHRASE is not set",
			notExpectMsg: "--force",
		},
		// Wrong/corrupt passphrase — decryption fails. Must NOT say "is not
		// set" because the env var IS set, just wrong. Must mention
		// `veil init --force` as the recovery option.
		{
			name:         "keystore wrong passphrase",
			in:           fmt.Errorf("open vault: %w: %w: decrypt: invalid", vault.ErrOpen, vault.ErrKeystoreUnavailable),
			expectMsg:    "veil init --force",
			notExpectMsg: "is not set",
		},
		{name: "vault open", in: fmt.Errorf("wrap: %w", vault.ErrOpen), expectMsg: "Cannot decrypt vault"},
		{name: "master key", in: fmt.Errorf("wrap: %w", vault.ErrMasterKey), expectMsg: "Cannot decrypt vault"},
		{name: "ca load", in: fmt.Errorf("wrap: %w", proxy.ErrCALoad), expectMsg: "CA certificate"},
		{name: "listen", in: fmt.Errorf("wrap: %w", proxy.ErrListen), expectMsg: "Another instance"},
		{name: "default", in: errors.New("random failure"), expectMsg: "run failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, sentinel := cli.MapRunErrorForTest(tc.in)
			if !strings.Contains(got, tc.expectMsg) {
				t.Fatalf("expected %q in %q", tc.expectMsg, got)
			}
			if tc.notExpectMsg != "" && strings.Contains(got, tc.notExpectMsg) {
				t.Errorf("message must not contain %q, got %q", tc.notExpectMsg, got)
			}
			if !errors.Is(sentinel, tc.expectSentinel) {
				t.Errorf("expected sentinel %v, got %v", tc.expectSentinel, sentinel)
			}
		})
	}
}

// runHelpOutput executes `veil run --help` against a fresh root command and
// returns its rendered stdout. Centralized so help-output assertions share
// one invocation path and stay aligned with how cobra dispatches help.
func runHelpOutput(t *testing.T) string {
	t.Helper()
	cmd := cli.NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"run", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("run --help failed: %v", err)
	}
	return out.String()
}

// TestRun_LongDescriptionNamesInjectedEnvAndFailClosed verifies that
// `veil run --help` exposes the Long: paragraph that names the env vars
// veil actually injects into the child, the NO_PROXY merge sources, and
// the --allow-env-secret fail-closed gate. Without this gate, `veil help
// run` falls back to the one-sentence Short:, leaving users to guess at
// the env contract — exactly what the polish pass was meant to fix.
func TestRun_LongDescriptionNamesInjectedEnvAndFailClosed(t *testing.T) {
	output := runHelpOutput(t)

	// Each substring corresponds to a concrete promise the Long: makes
	// (proxy URL injection, CA bundle injection, NO_PROXY merge, the
	// fail-closed flag). If any goes missing the description has drifted
	// from what the runner actually does — exactly the regression the
	// polish item was logged against.
	for _, want := range []string{
		"HTTP_PROXY",
		"SSL_CERT_FILE",
		"NODE_EXTRA_CA_CERTS",
		"NO_PROXY",
		"--allow-env-secret",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("run --help output must mention %q to document the env contract, got:\n%s", want, output)
		}
	}
}
