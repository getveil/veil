package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/proxy"
	"github.com/getveil/veil/internal/runner"
	"github.com/getveil/veil/internal/skiphost"
	"github.com/getveil/veil/internal/vault"
	"github.com/spf13/cobra"
)

func runCmd() *cobra.Command {
	var ephemeralSkip []string
	var allowEnvSecrets []string
	cmd := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Run a command with secrets injected via proxy",
		Long: `Start a local HTTPS proxy and launch <command> with HTTP_PROXY,
HTTPS_PROXY, and ALL_PROXY (plus their lowercase variants) pointed at
the loopback proxy, and per-session CA-bundle env vars
(SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE,
HTTPLIB2_CA_CERTS, CARGO_HTTP_CAINFO) pointed at a temp-dir bundle that
trusts Veil's local root. These vars are injected into the child process
only; the parent shell is not modified. Outbound Authorization: Bearer
requests from <command> are matched against the vault and rewritten with
real credentials at the network boundary.

NO_PROXY is composed of localhost,127.0.0.1,::1 plus any hosts listed in
.veil/skip_hosts plus each --skip flag passed at this invocation.

veil run refuses to launch when shell env vars look like unvaulted
secrets; pass --allow-env-secret NAME to allow a specific var through.

The proxy and its audit logging are torn down when <command> exits.`,
		Example: `  # Run a command with vault secrets injected
  veil run npm test

  # Bypass the proxy for a specific host (e.g. IMDS, internal services)
  veil run --skip 169.254.169.254 aws s3 ls`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(cmd, args, ephemeralSkip, allowEnvSecrets)
		},
	}
	cmd.Flags().SetInterspersed(false)
	cmd.Flags().StringArrayVar(&ephemeralSkip, "skip", nil, "host to pass through without proxying (non-persistent, repeatable)")
	cmd.Flags().StringArrayVar(&allowEnvSecrets, "allow-env-secret", nil, "env var name to pass through even if it looks secret-like and is not in the vault (repeatable)")
	return cmd
}

func runRun(cmd *cobra.Command, args []string, ephemeralSkip []string, allowEnvSecrets []string) error {
	root, err := requireInitializedProject(cmd)
	if err != nil {
		return err
	}

	// Load persistent skip hosts.
	skipHosts, err := skiphost.Load(config.SkipHostsFile(root))
	if err != nil {
		return wrapErr("reading skip hosts", err)
	}

	// Merge ephemeral --skip flags, validating each so a stray "*" cannot
	// disable proxying via NO_PROXY.
	for _, h := range ephemeralSkip {
		if err := skiphost.Validate(h); err != nil {
			return cliError(fmt.Sprintf("invalid --skip value: %v", err), "")
		}
		skipHosts = append(skipHosts, h)
	}

	result, err := runner.Run(cmd.Context(), runner.Config{
		Root:            root,
		Command:         args[0],
		Args:            args[1:],
		Verbose:         flagVerbose,
		SkipHosts:       skipHosts,
		AllowEnvSecrets: allowEnvSecrets,
	})
	if err != nil {
		msg, sentinel := mapRunError(err)
		if sentinel != nil {
			return cliErrorWith(sentinel, msg, "")
		}
		return cliError(msg, "")
	}

	os.Exit(result.ExitCode)
	return nil // unreachable
}

// mapRunError converts internal runner errors to a user-facing message and an
// optional sentinel that callers wrap so the exit-code classifier picks up the
// right code. The sentinel is non-nil only for conditions that have a more
// specific exit code than ExitGeneric.
func mapRunError(err error) (string, error) {
	switch {
	case errors.Is(err, vault.ErrOpen) && errors.Is(err, fs.ErrNotExist):
		// vault.meta (or vault.bin) is missing — the project is not
		// initialized, or its state was wiped. --force is the wrong remedy
		// here: there is no vault to lose, and the message implies one
		// existed. Route the user to plain `veil init` instead.
		return "Veil is not initialized in this project. Run `veil init` to get started.", ErrNotInitialized
	case errors.Is(err, vault.ErrPassphraseMissing):
		// On Linux without a working Secret Service (no system keyring) the
		// keystore falls back to an age-encrypted key file gated by
		// VEIL_PASSPHRASE. If that env var is unset, the previous "keychain
		// may have changed" hint sent users down a destructive `init --force`
		// path that would not fix anything. Keep this arm BEFORE the generic
		// ErrMasterKey / ErrOpen arms so it wins when both match.
		return "Cannot open vault: VEIL_PASSPHRASE is not set. On Linux without a system keyring, Veil falls back to an age-encrypted key file. Set VEIL_PASSPHRASE in your environment before running veil. See docs.", nil
	case errors.Is(err, vault.ErrKeystoreUnavailable):
		// Keystore reachable but the file could not be decrypted or parsed —
		// most commonly a wrong VEIL_PASSPHRASE. The user-facing message must
		// NOT say "is not set" (the env var IS set, just wrong) and must
		// surface `veil init --force` as the explicit recovery path.
		return "Cannot open vault. Check VEIL_PASSPHRASE matches the passphrase used at `veil init`.\n  If you've forgotten it, run `veil init --force` to start over (existing credentials will be lost).", nil
	case errors.Is(err, vault.ErrOpen), errors.Is(err, vault.ErrMasterKey), errors.Is(err, vault.ErrCorrupt):
		return "Cannot decrypt vault. Your keychain may have changed. Run veil init --force to reinitialize.", nil
	case errors.Is(err, proxy.ErrCALoad), errors.Is(err, proxy.ErrCAGenerate):
		return "CA certificate not found or corrupt. Run veil init to regenerate.", nil
	case errors.Is(err, proxy.ErrListen):
		return "Cannot start proxy. Another instance may be running.", nil
	default:
		return fmt.Sprintf("run failed: %v", err), nil
	}
}

// MapRunErrorForTest is exported for tests that assert error-to-message mapping.
var MapRunErrorForTest = mapRunError
