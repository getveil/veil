package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/ui"
	"github.com/spf13/cobra"
)

func listCmd() *cobra.Command {
	var reveal bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all credentials in the vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(cmd, reveal)
		},
	}
	cmd.Flags().BoolVar(&reveal, "reveal", false, "show real secret values (debug only)")
	return cmd
}

func runList(cmd *cobra.Command, reveal bool) error {
	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	v, err := openVault(root)
	if err != nil {
		return cliError(fmt.Sprintf("opening vault: %v", err), "")
	}

	creds := v.List()
	if len(creds) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No credentials in vault.")
		return nil
	}

	// Build a map of credential name -> most recent injection timestamp.
	lastInjected := make(map[string]time.Time)
	auditDBPath := config.AuditDBFile(root)
	store, err := audit.Open(auditDBPath)
	if err == nil {
		defer func() { _ = store.Close() }()
		for _, c := range creds {
			rows, qErr := store.Query(audit.Filter{
				CredentialName: c.Name,
				Limit:          1,
			})
			if qErr == nil && len(rows) > 0 {
				lastInjected[c.Name] = rows[0].Timestamp
			}
		}
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 4, ' ', 0)
	if reveal {
		ui.TableHeader(w, "NAME", "HOSTS", "VALUE", "SOURCE", "LAST INJECTED")
	} else {
		ui.TableHeader(w, "NAME", "HOSTS", "SOURCE", "LAST INJECTED")
	}
	for _, c := range creds {
		last := "never"
		if t, ok := lastInjected[c.Name]; ok {
			last = ui.RelativeTime(t)
		}
		hostsStr := ui.Warning.Sprint("(none)")
		if len(c.AllowedHosts) > 0 {
			hostsStr = strings.Join(c.AllowedHosts, ", ")
		}
		if reveal {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				c.Name,
				hostsStr,
				c.Real,
				c.Source,
				last,
			)
		} else {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				c.Name,
				hostsStr,
				c.Source,
				last,
			)
		}
	}
	_ = w.Flush()
	ui.Footer(cmd.OutOrStdout(), fmt.Sprintf("%d credentials", len(creds)))
	return nil
}
