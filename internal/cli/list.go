package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/ui"
	"github.com/spf13/cobra"
)

func listCmd() *cobra.Command {
	var reveal, showPlaceholder bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all credentials in the vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(cmd, reveal, showPlaceholder)
		},
	}
	cmd.Flags().BoolVar(&reveal, "reveal", false, "show real secret values (debug only)")
	cmd.Flags().BoolVar(&showPlaceholder, "placeholder", false, "show placeholder values")
	cmd.MarkFlagsMutuallyExclusive("reveal", "placeholder")
	return cmd
}

func runList(cmd *cobra.Command, reveal, showPlaceholder bool) error {
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

	// Collect plain-text row data for column width calculation.
	type row struct {
		name, hosts, value, placeholder, source, last string
	}
	rows := make([]row, len(creds))
	for i, c := range creds {
		r := row{name: c.Name, source: c.Source, last: "never"}
		if t, ok := lastInjected[c.Name]; ok {
			r.last = ui.RelativeTime(t)
		}
		if len(c.AllowedHosts) > 0 {
			r.hosts = formatHosts(c.AllowedHosts, 1)
		} else {
			r.hosts = "(none)"
		}
		if reveal {
			r.value = c.Real
		}
		if showPlaceholder {
			r.placeholder = c.Placeholder
		}
		rows[i] = r
	}

	// Compute column widths from data and headers.
	nameW, hostsW, sourceW := len("NAME"), len("HOSTS"), len("SOURCE")
	valueW := len("VALUE")
	phW := len("PLACEHOLDER")
	for _, r := range rows {
		nameW = maxInt(nameW, len(r.name))
		hostsW = maxInt(hostsW, len(r.hosts))
		sourceW = maxInt(sourceW, len(r.source))
		if reveal {
			valueW = maxInt(valueW, len(r.value))
		}
		if showPlaceholder {
			phW = maxInt(phW, len(r.placeholder))
		}
	}

	// Print header and rows. Pad plain text first, then apply ANSI styling
	// so escape codes don't break column alignment.
	out := cmd.OutOrStdout()
	gap := "    "
	if reveal {
		fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s\n",
			ui.Muted.Sprint(padRight("NAME", nameW)), gap,
			ui.Muted.Sprint(padRight("HOSTS", hostsW)), gap,
			ui.Muted.Sprint(padRight("VALUE", valueW)), gap,
			ui.Muted.Sprint(padRight("SOURCE", sourceW)), gap,
			ui.Muted.Sprint("LAST INJECTED"))
		for _, r := range rows {
			hosts := styleHosts(r.hosts, hostsW)
			fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s\n",
				padRight(r.name, nameW), gap,
				hosts, gap,
				padRight(r.value, valueW), gap,
				padRight(r.source, sourceW), gap,
				r.last)
		}
	} else if showPlaceholder {
		fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s\n",
			ui.Muted.Sprint(padRight("NAME", nameW)), gap,
			ui.Muted.Sprint(padRight("HOSTS", hostsW)), gap,
			ui.Muted.Sprint(padRight("PLACEHOLDER", phW)), gap,
			ui.Muted.Sprint(padRight("SOURCE", sourceW)), gap,
			ui.Muted.Sprint("LAST INJECTED"))
		for _, r := range rows {
			hosts := styleHosts(r.hosts, hostsW)
			fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s\n",
				padRight(r.name, nameW), gap,
				hosts, gap,
				padRight(r.placeholder, phW), gap,
				padRight(r.source, sourceW), gap,
				r.last)
		}
	} else {
		fmt.Fprintf(out, "%s%s%s%s%s%s%s\n",
			ui.Muted.Sprint(padRight("NAME", nameW)), gap,
			ui.Muted.Sprint(padRight("HOSTS", hostsW)), gap,
			ui.Muted.Sprint(padRight("SOURCE", sourceW)), gap,
			ui.Muted.Sprint("LAST INJECTED"))
		for _, r := range rows {
			hosts := styleHosts(r.hosts, hostsW)
			fmt.Fprintf(out, "%s%s%s%s%s%s%s\n",
				padRight(r.name, nameW), gap,
				hosts, gap,
				padRight(r.source, sourceW), gap,
				r.last)
		}
	}
	ui.Footer(out, fmt.Sprintf("%d credentials", len(creds)))
	return nil
}

// formatHosts returns a compact host string. If the list exceeds maxShow,
// only the first maxShow hosts are shown with a "+N more" suffix.
func formatHosts(hosts []string, maxShow int) string {
	if len(hosts) <= maxShow {
		return strings.Join(hosts, ", ")
	}
	return strings.Join(hosts[:maxShow], ", ") +
		fmt.Sprintf(" +%d more", len(hosts)-maxShow)
}

// styleHosts returns a padded hosts string with ANSI styling applied after
// padding so column alignment is preserved. The "+N more" suffix is dimmed,
// and "(none)" is shown in warning color.
func styleHosts(plain string, width int) string {
	if plain == "(none)" {
		return ui.Warning.Sprint(padRight("(none)", width))
	}
	if idx := strings.Index(plain, " +"); idx != -1 {
		host := plain[:idx]
		suffix := plain[idx:]
		padding := ""
		if extra := width - len(plain); extra > 0 {
			padding = strings.Repeat(" ", extra)
		}
		return host + ui.Muted.Sprint(suffix) + padding
	}
	return padRight(plain, width)
}

// padRight pads s with spaces to width w. s must be plain text (no ANSI).
func padRight(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
