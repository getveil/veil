package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/mcpconfig"
	"github.com/getveil/veil/internal/scanner"
	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
	"github.com/spf13/cobra"
)

// activeProxyPIDs returns the list of PIDs from proxy-*.pid files that
// correspond to live processes. Dead PIDs and unreadable files are ignored.
func activeProxyPIDs(root string) ([]int, error) {
	matches, err := filepath.Glob(config.PidFileGlob(root))
	if err != nil {
		return nil, err
	}
	var live []int
	for _, p := range matches {
		pid, ok := readPIDFile(p)
		if !ok {
			continue
		}
		if isProcessAlive(pid) {
			live = append(live, pid)
		}
	}
	return live, nil
}

// readPIDFile reads a pidfile and returns the integer PID. Returns false
// if the file cannot be read or does not contain a parseable integer.
func readPIDFile(path string) (int, bool) {
	data, err := os.ReadFile(path) // #nosec G304 -- pidfile path derived from state dir glob
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// isProcessAlive reports whether a process with the given PID exists.
// Uses signal 0 (no-op signal) to test existence without affecting the
// target. Returns false on permission errors as well — if we can't signal
// it, we can't safely claim it's live.
func isProcessAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// ESRCH (no such process) → dead. Other errors (EPERM) treat as dead too
	// because we can't confirm liveness; conservative for uninstall purposes
	// where a stale pidfile shouldn't block cleanup.
	return false
}

// formatPIDList formats a slice of PIDs for error messages.
func formatPIDList(pids []int) string {
	parts := make([]string, len(pids))
	for i, p := range pids {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ", ")
}

// backupKind classifies a backup pair by the kind of file it covers.
type backupKind int

const (
	backupKindEnv backupKind = iota
	backupKindMCP
)

// backupPair pairs an original file path with its backup. Either may be
// missing on disk at discovery time; classification runs later.
type backupPair struct {
	original string
	backup   string
	kind     backupKind
}

// envCuratedNames mirrors scanner.curatedNames. Kept local to avoid
// exporting scanner internals; the list changes rarely.
var envCuratedNames = []string{
	".env",
	".env.local",
	".env.development",
	".env.production",
}

// discoverBackups returns every (original, backup) pair that uninstall
// should consider.
//
// Source of truth is vault.meta's vaulted-files registry written by init —
// every entry it lists is included if its backup is still on disk, regardless
// of whether the original lives inside or outside the project root. This is
// what lets us restore a Claude Desktop MCP config that lives under
// ~/Library/Application Support/Claude (F-13). The registry also records
// each entry's kind, so an MCP config at a non-canonical path (e.g. set via
// VEIL_MCP_CONFIG_PATH) still routes to classifyMCPPair instead of being
// misclassified by basename.
//
// For backward compatibility with vaults created before the registry existed
// (vault.meta with no vaulted_files field), we also fall back to the legacy
// heuristic: scan curated .env names inside root, plus mcpconfig.Discover().
// Pairs already covered by the registry are not duplicated.
func discoverBackups(root string) ([]backupPair, error) {
	var pairs []backupPair
	seen := make(map[string]bool)

	registered, err := vault.ReadVaultedFiles(root)
	if err != nil {
		return nil, fmt.Errorf("reading vaulted-files registry: %w", err)
	}
	for _, entry := range registered {
		backup := entry.Path + backupSuffix
		if _, err := os.Stat(backup); err != nil {
			continue
		}
		pairs = append(pairs, backupPair{original: entry.Path, backup: backup, kind: kindFromVault(entry.Kind)})
		seen[entry.Path] = true
	}

	for _, name := range envCuratedNames {
		orig := filepath.Join(root, name)
		if seen[orig] {
			continue
		}
		backup := orig + backupSuffix
		if _, err := os.Stat(backup); err != nil {
			continue
		}
		pairs = append(pairs, backupPair{original: orig, backup: backup, kind: backupKindEnv})
		seen[orig] = true
	}

	mcpPath, err := mcpconfigDiscover()
	if err != nil {
		return nil, fmt.Errorf("discovering MCP config: %w", err)
	}
	if mcpPath != "" && !seen[mcpPath] {
		if _, err := os.Stat(mcpPath + backupSuffix); err == nil {
			pairs = append(pairs, backupPair{
				original: mcpPath,
				backup:   mcpPath + backupSuffix,
				kind:     backupKindMCP,
			})
		}
	}
	return pairs, nil
}

// kindFromVault maps a vault.FileKind to the local backupKind. Unknown kinds
// (e.g. registry entries from a future schema) fall back to env so the
// classifier path is at least byte-stable.
func kindFromVault(k vault.FileKind) backupKind {
	if k == vault.KindMCP {
		return backupKindMCP
	}
	return backupKindEnv
}

// mcpconfigDiscover wraps mcpconfig.Discover so tests can observe the seam
// without importing the package into the uninstall_test package.
var mcpconfigDiscover = func() (string, error) { return mcpconfig.Discover() }

// classification enumerates how a (current, backup) pair relates.
type classification int

const (
	classUnmodified classification = iota
	classModified
	classOriginalMissing
)

// placeholderResolver maps a placeholder string to its real value.
// An empty / nil resolver means "we cannot substitute" — classification
// falls back to byte comparison only.
type placeholderResolver map[string]string

// classifyEnvPair compares the current .env file to its backup after
// reverse-substituting placeholders with real values. Returns:
//   - classUnmodified: after substitution, bytes match the backup.
//   - classModified: bytes differ. The returned string is a unified diff
//     of the actual file change that uninstall will apply (current → backup).
//   - classOriginalMissing: current file does not exist on disk.
func classifyEnvPair(original, backup string, resolver placeholderResolver) (classification, string, error) {
	backupBytes, err := os.ReadFile(backup) // #nosec G304
	if err != nil {
		return 0, "", fmt.Errorf("read backup %s: %w", backup, err)
	}
	currentBytes, err := os.ReadFile(original) // #nosec G304
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return classOriginalMissing, "", nil
		}
		return 0, "", fmt.Errorf("read %s: %w", original, err)
	}

	expected := expectedOriginalEnv(currentBytes, resolver)
	if bytes.Equal(expected, backupBytes) {
		return classUnmodified, "", nil
	}
	// Show the user the actual file change uninstall will apply, not the
	// (substitution-applied) reconstruction — otherwise placeholder lines
	// that resolve cleanly are hidden from the preview, under-reporting
	// scope (F-11).
	return classModified, renderUnifiedDiff(currentBytes, backupBytes), nil
}

// expectedOriginalEnv parses current as a .env file and replaces each
// KV-line's value with the real value from resolver when the current value
// is a known placeholder. Returns the reconstructed bytes via
// scanner.EnvFile.Bytes() so formatting is preserved.
func expectedOriginalEnv(current []byte, resolver placeholderResolver) []byte {
	envFile := scanner.ParseBytes(current)
	if resolver != nil {
		for _, line := range envFile.Lines {
			if line.Kind != scanner.KVLine {
				continue
			}
			if real, ok := resolver[line.Value]; ok {
				envFile.SetValue(line.Key, real)
			}
		}
	}
	return envFile.Bytes()
}

// renderUnifiedDiff produces a minimal unified-style diff between a and b.
// The output begins with "--- current" / "+++ backup" headers, reflecting
// what uninstall will do (replace current with backup). Each differing line
// is prefixed with '-' (present in a, missing from b) or '+' (present in b,
// missing from a). Context lines are prefixed with a single space.
// Implementation uses a line-by-line LCS — fine for files of typical
// .env/MCP size (tens to hundreds of lines).
func renderUnifiedDiff(a, b []byte) string {
	if bytes.Equal(a, b) {
		return ""
	}
	aLines := strings.Split(string(a), "\n")
	bLines := strings.Split(string(b), "\n")
	// Trim trailing empty element caused by a terminal newline so we don't
	// diff a phantom blank line.
	if len(aLines) > 0 && aLines[len(aLines)-1] == "" {
		aLines = aLines[:len(aLines)-1]
	}
	if len(bLines) > 0 && bLines[len(bLines)-1] == "" {
		bLines = bLines[:len(bLines)-1]
	}

	lcs := lcsTable(aLines, bLines)
	var sb strings.Builder
	sb.WriteString("--- current\n+++ backup\n")
	emitDiff(&sb, aLines, bLines, lcs, len(aLines), len(bLines))
	return sb.String()
}

// lcsTable builds a longest-common-subsequence DP table for a and b.
func lcsTable(a, b []string) [][]int {
	n, m := len(a), len(b)
	t := make([][]int, n+1)
	for i := range t {
		t[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				t[i][j] = t[i-1][j-1] + 1
			} else if t[i-1][j] >= t[i][j-1] {
				t[i][j] = t[i-1][j]
			} else {
				t[i][j] = t[i][j-1]
			}
		}
	}
	return t
}

// emitDiff walks the LCS table from (i,j) down to (0,0) and emits diff
// lines in forward order using a recursive preorder traversal.
func emitDiff(sb *strings.Builder, a, b []string, t [][]int, i, j int) {
	switch {
	case i > 0 && j > 0 && a[i-1] == b[j-1]:
		emitDiff(sb, a, b, t, i-1, j-1)
		sb.WriteString(" ")
		sb.WriteString(a[i-1])
		sb.WriteString("\n")
	case j > 0 && (i == 0 || t[i][j-1] >= t[i-1][j]):
		emitDiff(sb, a, b, t, i, j-1)
		sb.WriteString("+")
		sb.WriteString(b[j-1])
		sb.WriteString("\n")
	case i > 0 && (j == 0 || t[i][j-1] < t[i-1][j]):
		emitDiff(sb, a, b, t, i-1, j)
		sb.WriteString("-")
		sb.WriteString(a[i-1])
		sb.WriteString("\n")
	}
}

// classifyMCPPair compares the current MCP config file to its backup after
// reverse-substituting placeholders with real values. Semantics mirror
// classifyEnvPair but operate on the MCP JSON shape via mcpconfig.
func classifyMCPPair(original, backup string, resolver placeholderResolver) (classification, string, error) {
	backupBytes, err := os.ReadFile(backup) // #nosec G304
	if err != nil {
		return 0, "", fmt.Errorf("read backup %s: %w", backup, err)
	}
	currentBytes, err := os.ReadFile(original) // #nosec G304
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return classOriginalMissing, "", nil
		}
		return 0, "", fmt.Errorf("read %s: %w", original, err)
	}

	expected, err := expectedOriginalMCP(currentBytes, resolver)
	if err != nil {
		return classModified, renderUnifiedDiff(currentBytes, backupBytes), nil
	}

	if bytes.Equal(expected, backupBytes) {
		return classUnmodified, "", nil
	}
	// Show the actual file change, not the substitution-applied reconstruction
	// (F-11): reconstructions hide cleanly-resolving placeholder lines.
	return classModified, renderUnifiedDiff(currentBytes, backupBytes), nil
}

// expectedOriginalMCP parses the current MCP config bytes, substitutes
// placeholders with real values in every server's env map and args slice,
// and re-serializes using mcpconfig's canonical formatting. Args are
// substituted alongside env so a config that was vaulted with secrets in
// either location classifies as classUnmodified against its backup.
func expectedOriginalMCP(current []byte, resolver placeholderResolver) ([]byte, error) {
	cfg, err := mcpconfig.ParseBytes(current)
	if err != nil {
		return nil, err
	}
	if resolver != nil {
		for serverName, server := range cfg.Servers() {
			for key, value := range server.Env {
				if real, ok := resolver[value]; ok {
					cfg.SetEnvValue(serverName, key, real)
				}
			}
			for i, value := range server.Args {
				if real, ok := resolver[value]; ok {
					cfg.SetArg(serverName, i, real)
				}
			}
		}
	}
	return cfg.Bytes()
}

// resolverFromVault returns a placeholderResolver mapping each credential's
// placeholder → real value. If a credential has a Basic-auth username
// placeholder, that mapping is included too.
func resolverFromVault(v *vault.Vault) placeholderResolver {
	resolver := make(placeholderResolver)
	for _, cred := range v.List() {
		if cred.Placeholder != "" {
			resolver[cred.Placeholder] = cred.Real
		}
		if cred.UsernamePlaceholder != "" {
			resolver[cred.UsernamePlaceholder] = cred.Username
		}
	}
	return resolver
}

func uninstallCmd() *cobra.Command {
	var dryRun, yes, force bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Revert veil init: restore backups, wipe vault and state",
		Long: `Restore every file veil init modified from its .veil-backup, remove the
project vault, purge the keystore entry, and delete .veil/.

After a successful uninstall, the project is in its pre-init state
(modulo /.veil/ and *.veil-backup lines that remain in .gitignore).

Flags:
  --dry-run    Print the plan without making changes.
  --yes        Skip the interactive confirmation.
  --force      Proceed past "no backups" and "active proxy" guards.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(cmd, dryRun, yes, force)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the plan without making changes")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the interactive confirmation")
	cmd.Flags().BoolVar(&force, "force", false, "proceed past guards (no-backup, active-proxy)")
	return cmd
}

func runUninstall(cmd *cobra.Command, dryRun, yes, force bool) error {
	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	w := cmd.OutOrStdout()
	ew := cmd.ErrOrStderr()

	// Discover backup pairs and state dir first — a clean project short-
	// circuits with "already uninstalled" and doesn't need the proxy guard.
	pairs, err := discoverBackups(root)
	if err != nil {
		return wrapErr("discovering backups", err)
	}

	stateDir := config.ProjectStateDir(root)
	_, stateErr := os.Stat(stateDir)
	stateExists := stateErr == nil

	if len(pairs) == 0 && !stateExists {
		_, _ = fmt.Fprintln(w, "already uninstalled")
		return nil
	}

	// Active-proxy guard: only meaningful when there is something to uninstall.
	live, err := activeProxyPIDs(root)
	if err != nil {
		return wrapErr("checking active proxies", err)
	}
	if len(live) > 0 && !force {
		return formatCLIError(ew,
			fmt.Sprintf("active proxy processes found (PIDs: %s); stop them or pass --force", formatPIDList(live)),
			"Run `veil status` to identify, then `kill <pid>`.",
		)
	}

	if len(pairs) == 0 && !force {
		return formatCLIError(ew,
			"no .veil-backup files found, but .veil/ exists",
			"Use --force to wipe state without restoring any files, or run `veil list` to inspect the vault manually.",
		)
	}

	// Build placeholder resolver from the vault (best-effort).
	var resolver placeholderResolver
	if stateExists {
		if v, err := openVault(root); err == nil {
			resolver = resolverFromVault(v)
		} else {
			ui.Warnf(ew, "could not open vault for placeholder resolution: %v", err)
		}
	}

	// Classify each pair.
	type planned struct {
		pair   backupPair
		status classification
		diff   string
	}
	plan := make([]planned, 0, len(pairs))
	for _, p := range pairs {
		var (
			status classification
			diff   string
			cerr   error
		)
		if p.kind == backupKindMCP {
			status, diff, cerr = classifyMCPPair(p.original, p.backup, resolver)
		} else {
			status, diff, cerr = classifyEnvPair(p.original, p.backup, resolver)
		}
		if cerr != nil {
			return wrapErr(fmt.Sprintf("classifying %s", p.original), cerr)
		}
		plan = append(plan, planned{pair: p, status: status, diff: diff})
	}

	// Print plan.
	_, _ = fmt.Fprintln(w, "Uninstall plan:")
	for _, pl := range plan {
		label := classLabel(pl.status)
		_, _ = fmt.Fprintf(w, "  [%s] %s\n", label, pl.pair.original)
		if pl.status == classModified && pl.diff != "" {
			_, _ = fmt.Fprintln(w, pl.diff)
		}
	}
	if stateExists {
		_, _ = fmt.Fprintf(w, "  [wipe]     %s\n", stateDir)
	}

	if dryRun {
		return nil
	}

	if !yes && !promptYN(newLineReader(cmd.InOrStdin()), w, "Proceed with uninstall?", false) {
		_, _ = fmt.Fprintln(w, "Aborted.")
		return nil
	}

	// Execute restoration. moved counts backup→original renames regardless of
	// whether the original existed; materialized tracks the subset where no
	// original was present (so users see that those files were newly placed).
	moved, materialized := 0, 0
	for _, pl := range plan {
		if err := os.Rename(pl.pair.backup, pl.pair.original); err != nil {
			return wrapErr(fmt.Sprintf("restoring %s", pl.pair.original), err)
		}
		moved++
		if pl.status == classOriginalMissing {
			materialized++
		}
	}

	// Purge keystore entry (best-effort).
	if stateExists {
		if pid, err := vault.ReadProjectID(root); err == nil {
			if ks, err := buildKeystore(); err == nil {
				if delErr := ks.Delete(pid); delErr != nil {
					ui.Warnf(ew, "could not purge keystore entry: %v", delErr)
				}
			} else {
				ui.Warnf(ew, "keystore purge skipped: %v", err)
			}
		} else {
			ui.Warnf(ew, "keystore purge skipped: %v", err)
		}

		if err := os.RemoveAll(stateDir); err != nil {
			return wrapErr(fmt.Sprintf("removing %s", stateDir), err)
		}
	}

	if materialized > 0 {
		_, _ = fmt.Fprintf(w, "\nMoved %d %s into place (%d newly materialized).\n",
			moved, plural(moved, "backup", "backups"), materialized)
	} else {
		_, _ = fmt.Fprintf(w, "\nRestored %d %s from backup.\n",
			moved, plural(moved, "file", "files"))
	}
	if stateExists {
		_, _ = fmt.Fprintln(w, "State directory removed; keystore entry purged.")
	}
	return nil
}

// classLabel returns a short label for display in the plan table.
func classLabel(c classification) string {
	switch c {
	case classUnmodified:
		return "restore "
	case classModified:
		return "modified"
	case classOriginalMissing:
		return "restore*"
	default:
		return "?       "
	}
}
