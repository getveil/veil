package cli_test

import (
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
			name:         "keystore unavailable passphrase missing",
			in:           fmt.Errorf("open vault: %w: %w: %s is not set", vault.ErrOpen, vault.ErrKeystoreUnavailable, "VEIL_PASSPHRASE"),
			expectMsg:    "VEIL_PASSPHRASE",
			notExpectMsg: "--force",
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
