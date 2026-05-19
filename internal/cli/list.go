package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// stdoutIsTerminal is a test seam: tests replace it to simulate a
// pipe/redirect without closing os.Stdout.
var stdoutIsTerminal = func() bool {
	return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
}

func listCmd() *cobra.Command {
	var reveal, showPlaceholder, assumeYes bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all credentials in the vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(cmd, reveal, showPlaceholder, assumeYes)
		},
	}
	cmd.Flags().BoolVar(&reveal, "reveal", false, "show real secret values (debug only; printed with audit log)")
	cmd.Flags().BoolVar(&showPlaceholder, "placeholder", false, "show placeholder values")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "bypass TTY safety check for --reveal (scripted use)")
	cmd.MarkFlagsMutuallyExclusive("reveal", "placeholder")
	return cmd
}

func runList(cmd *cobra.Command, reveal, showPlaceholder, assumeYes bool) error {
	if reveal {
		if !stdoutIsTerminal() && !assumeYes {
			return cliError(
				"refusing to print real secrets to a non-TTY stdout",
				"Pipe or redirect detected. Re-run with --yes to override.")
		}
		ui.FormatWarning(cmd.ErrOrStderr(),
			"--reveal prints plaintext secrets",
			"This action is recorded in the audit log.")
	}

	return withVault(cmd, func(root string, v *vault.Vault) error {
		return runListInVault(cmd, root, v, reveal, showPlaceholder)
	})
}

func runListInVault(cmd *cobra.Command, root string, v *vault.Vault, reveal, showPlaceholder bool) error {
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
		// Record a single "reveal" row per invocation so `veil log` shows
		// the action. One row is sufficient — no per-credential detail is
		// persisted here by design (that would double-store secret metadata).
		if reveal {
			store.Record(audit.Injection{
				Timestamp:      time.Now(),
				RequestID:      "reveal-" + time.Now().UTC().Format("20060102T150405.000"),
				AgentPID:       os.Getpid(),
				AgentCmd:       "veil list --reveal",
				CredentialName: fmt.Sprintf("(%d credentials)", len(creds)),
				Location:       "reveal",
			})
		}
	}

	// Build display rows. Each credential produces one row.
	//
	// nameStyled mirrors name but may carry ANSI styling. Width math uses
	// the plain name to keep alignment correct.
	type row struct {
		name, nameStyled, hosts, value, placeholder, source, last string
	}
	var rows []row
	for _, c := range creds {
		base := row{name: c.Name, nameStyled: c.Name, source: c.Source, last: "never"}
		if t, ok := lastInjected[c.Name]; ok {
			base.last = ui.RelativeTime(t)
		}
		if len(c.AllowedHosts) > 0 {
			base.hosts = formatHosts(c.AllowedHosts, 1)
		} else {
			base.hosts = "(none)"
		}

		if reveal {
			base.value = c.Real
		}
		if showPlaceholder {
			base.placeholder = c.Placeholder
		}
		rows = append(rows, base)
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
	emitName := func(r row) string {
		pad := nameW - len(r.name)
		if pad < 0 {
			pad = 0
		}
		return r.nameStyled + strings.Repeat(" ", pad)
	}
	if reveal {
		_, _ = fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s\n",
			ui.Muted.Sprint(padRight("NAME", nameW)), gap,
			ui.Muted.Sprint(padRight("HOSTS", hostsW)), gap,
			ui.Muted.Sprint(padRight("VALUE", valueW)), gap,
			ui.Muted.Sprint(padRight("SOURCE", sourceW)), gap,
			ui.Muted.Sprint("LAST INJECTED"))
		for _, r := range rows {
			hosts := styleHosts(r.hosts, hostsW)
			_, _ = fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s\n",
				emitName(r), gap,
				hosts, gap,
				padRight(r.value, valueW), gap,
				padRight(r.source, sourceW), gap,
				r.last)
		}
	} else if showPlaceholder {
		_, _ = fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s\n",
			ui.Muted.Sprint(padRight("NAME", nameW)), gap,
			ui.Muted.Sprint(padRight("HOSTS", hostsW)), gap,
			ui.Muted.Sprint(padRight("PLACEHOLDER", phW)), gap,
			ui.Muted.Sprint(padRight("SOURCE", sourceW)), gap,
			ui.Muted.Sprint("LAST INJECTED"))
		for _, r := range rows {
			hosts := styleHosts(r.hosts, hostsW)
			_, _ = fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s\n",
				emitName(r), gap,
				hosts, gap,
				padRight(r.placeholder, phW), gap,
				padRight(r.source, sourceW), gap,
				r.last)
		}
	} else {
		_, _ = fmt.Fprintf(out, "%s%s%s%s%s%s%s\n",
			ui.Muted.Sprint(padRight("NAME", nameW)), gap,
			ui.Muted.Sprint(padRight("HOSTS", hostsW)), gap,
			ui.Muted.Sprint(padRight("SOURCE", sourceW)), gap,
			ui.Muted.Sprint("LAST INJECTED"))
		for _, r := range rows {
			hosts := styleHosts(r.hosts, hostsW)
			_, _ = fmt.Fprintf(out, "%s%s%s%s%s%s%s\n",
				emitName(r), gap,
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

