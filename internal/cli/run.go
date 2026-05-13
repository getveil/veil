package cli

import (
	"errors"
	"fmt"
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
		Args:  cobra.MinimumNArgs(1),
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
		return cliError(mapRunError(err), "")
	}

	os.Exit(result.ExitCode)
	return nil // unreachable
}

// mapRunError converts internal runner errors to user-friendly messages.
func mapRunError(err error) string {
	switch {
	case errors.Is(err, vault.ErrOpen), errors.Is(err, vault.ErrMasterKey), errors.Is(err, vault.ErrCorrupt):
		return "Cannot decrypt vault. Your keychain may have changed. Run veil init --force to reinitialize."
	case errors.Is(err, proxy.ErrCALoad), errors.Is(err, proxy.ErrCAGenerate):
		return "CA certificate not found or corrupt. Run veil init to regenerate."
	case errors.Is(err, proxy.ErrListen):
		return "Cannot start proxy. Another instance may be running."
	default:
		return fmt.Sprintf("run failed: %v", err)
	}
}

// MapRunErrorForTest is exported for tests that assert error-to-message mapping.
var MapRunErrorForTest = mapRunError
