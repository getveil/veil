package cli

import (
	"fmt"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/skiphost"
	"github.com/getveil/veil/internal/ui"
	"github.com/spf13/cobra"
)

func skipCmd() *cobra.Command {
	var list bool
	var remove string
	cmd := &cobra.Command{
		Use:   "skip [host]",
		Short: "Manage hosts the proxy passes through untouched",
		Long:  "Add, remove, or list hosts that the proxy should not intercept.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSkip(cmd, args, list, remove)
		},
	}
	cmd.Flags().BoolVar(&list, "list", false, "list all skip hosts")
	cmd.Flags().StringVar(&remove, "remove", "", "remove a host from the skip list")
	return cmd
}

func runSkip(cmd *cobra.Command, args []string, list bool, remove string) error {
	w := cmd.OutOrStdout()

	root, err := requireInitializedProject(cmd)
	if err != nil {
		return err
	}

	path := config.SkipHostsFile(root)

	if list {
		hosts, err := skiphost.Load(path)
		if err != nil {
			return cliError(fmt.Sprintf("reading skip hosts: %v", err), "")
		}
		if len(hosts) == 0 {
			_, _ = fmt.Fprintln(w, ui.Muted.Sprint("No skip hosts configured."))
			_, _ = fmt.Fprintf(w, "  %s\n", ui.Muted.Sprint("Add one with: veil skip <host>"))
			return nil
		}
		for _, h := range hosts {
			_, _ = fmt.Fprintf(w, "  %s\n", h)
		}
		return nil
	}

	if remove != "" {
		removed, err := skiphost.Remove(path, remove)
		if err != nil {
			return cliError(fmt.Sprintf("removing skip host: %v", err), "")
		}
		if !removed {
			return cliError(fmt.Sprintf("%s is not in the skip list", remove), "")
		}
		ui.Step(w, fmt.Sprintf("Removed %s from skip list", remove))
		return nil
	}

	if len(args) == 0 {
		return cliError("no host provided", "Usage: veil skip <host>")
	}
	host := args[0]

	added, err := skiphost.Add(path, host)
	if err != nil {
		return cliError(fmt.Sprintf("adding skip host: %v", err), "")
	}
	if !added {
		_, _ = fmt.Fprintf(w, "  %s %s is already in the skip list\n", ui.Muted.Sprint("·"), host)
		return nil
	}
	ui.Step(w, fmt.Sprintf("Added %s to skip list", host))
	return nil
}
