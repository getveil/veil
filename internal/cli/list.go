package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/ui"
	"github.com/8enji/veil/internal/vault"
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

	// Build display rows. Non-AWS credentials produce one row each. AWS
	// credentials in --reveal/--placeholder modes expand to one row per
	// logical secret (AKID, secret, optional session token), each labeled
	// with the canonical AWS env-var name and paired with the matching
	// value. Sub-rows after the first leave name/hosts/source/last blank
	// to visually group them under the credential.
	//
	// nameStyled mirrors name but may carry ANSI styling (e.g., the "(basic)"
	// tag is dimmed). Width math uses the plain name to keep alignment correct.
	type row struct {
		name, nameStyled, hosts, varName, value, placeholder, source, last string
	}
	expandAWS := reveal || showPlaceholder
	var rows []row
	for _, c := range creds {
		base := row{name: c.Name, nameStyled: c.Name, source: c.Source, last: "never"}
		var tag string
		switch {
		case c.Scheme == "aws" || c.AWSAccessKeyID != "":
			tag = "(aws)"
		case c.Scheme == "github_app" || c.GitHubAppID != 0:
			tag = "(github app)"
		case c.Username != "":
			tag = "(basic)"
		}
		if tag != "" {
			base.name = c.Name + " " + tag
			base.nameStyled = c.Name + " " + ui.Muted.Sprint(tag)
		}
		if t, ok := lastInjected[c.Name]; ok {
			base.last = ui.RelativeTime(t)
		}
		if len(c.AllowedHosts) > 0 {
			base.hosts = formatHosts(c.AllowedHosts, 1)
		} else {
			base.hosts = "(none)"
		}

		isAWS := c.Scheme == "aws" || c.AWSAccessKeyID != ""
		if expandAWS && isAWS {
			// Row 1: AKID (anchors the credential's name/hosts/source/last).
			r1 := base
			r1.varName = "AWS_ACCESS_KEY_ID"
			if reveal {
				r1.value = c.AWSAccessKeyID
			}
			if showPlaceholder {
				r1.placeholder = c.AWSAccessKeyIDPlaceholder
			}
			rows = append(rows, r1)
			// Row 2: secret access key (Real/Placeholder hold the secret).
			r2 := row{varName: "AWS_SECRET_ACCESS_KEY"}
			if reveal {
				r2.value = c.Real
			}
			if showPlaceholder {
				r2.placeholder = c.Placeholder
			}
			rows = append(rows, r2)
			// Row 3: optional session token.
			if c.AWSSessionToken != "" || c.AWSSessionTokenPlaceholder != "" {
				r3 := row{varName: "AWS_SESSION_TOKEN"}
				if reveal {
					r3.value = c.AWSSessionToken
				}
				if showPlaceholder {
					r3.placeholder = c.AWSSessionTokenPlaceholder
				}
				rows = append(rows, r3)
			}
			continue
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
	varW := len("VAR")
	valueW := len("VALUE")
	phW := len("PLACEHOLDER")
	for _, r := range rows {
		nameW = maxInt(nameW, len(r.name))
		hostsW = maxInt(hostsW, len(r.hosts))
		sourceW = maxInt(sourceW, len(r.source))
		if expandAWS {
			varW = maxInt(varW, len(r.varName))
		}
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
		_, _ = fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s%s%s\n",
			ui.Muted.Sprint(padRight("NAME", nameW)), gap,
			ui.Muted.Sprint(padRight("HOSTS", hostsW)), gap,
			ui.Muted.Sprint(padRight("VAR", varW)), gap,
			ui.Muted.Sprint(padRight("VALUE", valueW)), gap,
			ui.Muted.Sprint(padRight("SOURCE", sourceW)), gap,
			ui.Muted.Sprint("LAST INJECTED"))
		for _, r := range rows {
			hosts := styleHosts(r.hosts, hostsW)
			if r.hosts == "" {
				hosts = padRight("", hostsW)
			}
			_, _ = fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s%s%s\n",
				emitName(r), gap,
				hosts, gap,
				padRight(r.varName, varW), gap,
				padRight(r.value, valueW), gap,
				padRight(r.source, sourceW), gap,
				r.last)
		}
	} else if showPlaceholder {
		_, _ = fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s%s%s\n",
			ui.Muted.Sprint(padRight("NAME", nameW)), gap,
			ui.Muted.Sprint(padRight("HOSTS", hostsW)), gap,
			ui.Muted.Sprint(padRight("VAR", varW)), gap,
			ui.Muted.Sprint(padRight("PLACEHOLDER", phW)), gap,
			ui.Muted.Sprint(padRight("SOURCE", sourceW)), gap,
			ui.Muted.Sprint("LAST INJECTED"))
		for _, r := range rows {
			hosts := styleHosts(r.hosts, hostsW)
			if r.hosts == "" {
				hosts = padRight("", hostsW)
			}
			_, _ = fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s%s%s\n",
				emitName(r), gap,
				hosts, gap,
				padRight(r.varName, varW), gap,
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
