package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/config"
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
	lastInjected := make(map[string]string)
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
				lastInjected[c.Name] = rows[0].Timestamp.Format("2006-01-02 15:04")
			}
		}
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 4, ' ', 0)
	if reveal {
		_, _ = fmt.Fprintln(w, "NAME\tHOSTS\tVALUE\tSOURCE\tCREATED\tLAST INJECTED")
	} else {
		_, _ = fmt.Fprintln(w, "NAME\tHOSTS\tSOURCE\tCREATED\tLAST INJECTED")
	}
	for _, c := range creds {
		last := "never"
		if t, ok := lastInjected[c.Name]; ok {
			last = t
		}
		hostsStr := "(none)"
		if len(c.AllowedHosts) > 0 {
			hostsStr = strings.Join(c.AllowedHosts, ", ")
		}
		if reveal {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				c.Name,
				hostsStr,
				c.Real,
				c.Source,
				c.CreatedAt.Format("2006-01-02 15:04"),
				last,
			)
		} else {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				c.Name,
				hostsStr,
				c.Source,
				c.CreatedAt.Format("2006-01-02 15:04"),
				last,
			)
		}
	}
	_ = w.Flush()
	return nil
}
