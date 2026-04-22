package cli

import (
	"fmt"
	"strings"

	"github.com/8enji/veil/internal/ui"
	"github.com/spf13/cobra"
)

func removeCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a credential from the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemove(cmd, args[0], force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "skip confirmation prompt")
	return cmd
}

func runRemove(cmd *cobra.Command, name string, force bool) error {
	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	v, err := openVault(root)
	if err != nil {
		return cliError(fmt.Sprintf("opening vault: %v", err), "")
	}

	// Check the credential exists before prompting.
	cred, found := v.Get(name)
	if !found {
		return cliErrorWith(ErrNotFound, fmt.Sprintf("credential %q not found", name), "Run veil list to see available credentials")
	}

	// Confirm unless --force.
	if !force {
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
