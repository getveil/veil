package cli

import (
	"fmt"
	"strings"

	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
	"github.com/spf13/cobra"
)

func removeCmd() *cobra.Command {
	var force, yes bool
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a credential from the vault",
		Example: `  # Remove a credential (prompts for confirmation)
  veil remove STRIPE_KEY

  # Non-interactive removal for scripts/CI
  veil remove STRIPE_KEY --yes`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemove(cmd, args[0], force || yes)
		},
	}
	// --force is the original spelling; --yes is the alias added so all three
	// destructive/idempotent commands (init, uninstall, remove) accept the
	// same skip-confirm flag. They are siblings, not opposites.
	cmd.Flags().BoolVar(&force, "force", false, "skip confirmation prompt")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip confirmation prompt (alias for --force)")
	return cmd
}

func runRemove(cmd *cobra.Command, name string, skipConfirm bool) error {
	return withVault(cmd, func(_ string, v *vault.Vault) error {
		return runRemoveInVault(cmd, v, name, skipConfirm)
	})
}

func runRemoveInVault(cmd *cobra.Command, v *vault.Vault, name string, skipConfirm bool) error {
	// Check the credential exists before prompting.
	cred, found := v.Get(name)
	if !found {
		return cliErrorWith(ErrNotFound, fmt.Sprintf("credential %q not found", name), "Run veil list to see available credentials")
	}

	// Confirm unless skipped. detectInteractive reuses the same TTY-detection
	// logic as init/uninstall so behavior is consistent: a non-*os.File reader
	// (the bytes.Buffer common in tests) is treated as interactive, a real
	// non-TTY pipe is not. Without this gate, Fscanln returned immediately on
	// EOF and the command exited 0 having done nothing — silent failure.
	if !skipConfirm {
		interactive, _ := detectInteractive(cmd.InOrStdin(), false)
		if !interactive {
			return cliErrorWith(ErrUsage,
				"no TTY for confirm; pass --force (or --yes) to remove non-interactively",
				"Re-run the command with --force (or --yes), or invoke it from a terminal.")
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Remove %s from vault? [y/N] ", name)
		var answer string
		_, _ = fmt.Fscanln(cmd.InOrStdin(), &answer)
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Cancelled.")
			return nil
		}
	}

	w := cmd.OutOrStdout()

	deleted, err := v.Delete(name)
	if err != nil {
		return cliError(fmt.Sprintf("removing credential: %v", err), "")
	}
	if !deleted {
		return cliError(fmt.Sprintf("credential %q not found", name), "")
	}

	ui.Step(w, fmt.Sprintf("Removed %s from vault", name))
	if len(cred.AllowedHosts) > 0 {
		_, _ = fmt.Fprintf(w, "    %s\n", ui.Muted.Sprintf("Hosts: %s", strings.Join(cred.AllowedHosts, ", ")))
	}
	ui.Warn(w, "Placeholder in .env will no longer be injected")

	return nil
}
