package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/getveil/veil/internal/config"
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
// Uses signal 0 to test existence. EPERM is treated as dead too — we can't
// confirm liveness, so a stale pidfile shouldn't block cleanup.
func isProcessAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// formatPIDList formats a slice of PIDs for error messages.
func formatPIDList(pids []int) string {
	parts := make([]string, len(pids))
	for i, p := range pids {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ", ")
}

// backupPair pairs an original .env file path with its backup sidecar.
// Either may be missing on disk at discovery time; classification runs
// later.
type backupPair struct {
	original string
	backup   string
}

// discoverBackups walks the project rooted at root and returns every
// (original, backup) pair uninstall should consider — one per
// `*.veil-backup` sidecar found on disk. The pre-v1 vault.meta vaulted-
// files registry that previously sourced this list was dropped in the
// launch cuts; the walk is its replacement, with one consequence: backups
// for files outside the project root (e.g. an init run with --path
// pointing at a sibling tree) are no longer surfaced and must be removed
// manually. Symlinked directories are skipped to avoid leaking through
// attacker-planted links; symlinked leaf backups are returned so the
// existing symlink-refusal gate produces an explicit error.
func discoverBackups(root string) ([]backupPair, error) {
	var pairs []backupPair
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			// Prune source-tree noise + .veil itself; matches the env-file
			// walker's baselineExcludeDirs so the two scans agree on scope.
			if path != root {
				switch d.Name() {
				case ".git", ".veil", "node_modules", "vendor", "target",
					"dist", "build", ".next", ".nuxt", ".turbo", ".cache",
					".pnpm-store", ".yarn":
					return fs.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), backupSuffix) {
			return nil
		}
		original := strings.TrimSuffix(path, backupSuffix)
		pairs = append(pairs, backupPair{original: original, backup: path})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking for backups: %w", err)
	}
	return pairs, nil
}

// refuseSymlinkedBackupPairs refuses to operate on any pair whose original
// or backup is a symbolic link. os.ReadFile follows symlinks, so without
// this gate `uninstall --dry-run` would render a symlink target's contents
// to stdout via the diff, and restore would replace the symlink itself
// rather than its referent. Aggregates all violators into one error.
func refuseSymlinkedBackupPairs(root string, pairs []backupPair) error {
	var hits []string

	display := func(p string) string { return displayRelOr(root, p, p) }

	for _, p := range pairs {
		hits = appendIfSymlink(hits, p.original, display(p.original))
		hits = appendIfSymlink(hits, p.backup, display(p.backup))
	}

	if len(hits) == 0 {
		return nil
	}
	return cliError(
		fmt.Sprintf(
			"%s a symbolic link: %s. Reading through the symlink would render its target into the uninstall diff (printed to stdout), and replacing it during restore would clobber the link itself rather than its referent.",
			plural(len(hits), "input is", "inputs are"),
			strings.Join(hits, ", "),
		),
		"Remove the symlink (or replace it with a regular file via `cp -L`) and re-run. If you did not create this symlink, investigate before proceeding — it may indicate tampering.",
	)
}

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

// readPairBytes reads the backup and current bytes for a (original, backup)
// pair. Returns classOriginalMissing (with nil err and nil bytes) when the
// original is gone — callers short-circuit on that. Any other read error
// propagates with context.
func readPairBytes(original, backup string) (currentBytes, backupBytes []byte, status classification, err error) {
	backupBytes, err = os.ReadFile(backup) // #nosec G304
	if err != nil {
		return nil, nil, 0, fmt.Errorf("read backup %s: %w", backup, err)
	}
	currentBytes, err = os.ReadFile(original) // #nosec G304
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, classOriginalMissing, nil
		}
		return nil, nil, 0, fmt.Errorf("read %s: %w", original, err)
	}
	return currentBytes, backupBytes, 0, nil
}

// classifyEnvPair compares the current .env file to its backup after
// reverse-substituting placeholders with real values. Returns:
//   - classUnmodified: after substitution, bytes match the backup.
//   - classModified: bytes differ. The returned string is a unified diff
//     of the actual file change that uninstall will apply (current → backup).
//   - classOriginalMissing: current file does not exist on disk.
func classifyEnvPair(original, backup string, resolver placeholderResolver) (classification, string, error) {
	currentBytes, backupBytes, status, err := readPairBytes(original, backup)
	if err != nil || status == classOriginalMissing {
		return status, "", err
	}

	expected := expectedOriginalEnv(currentBytes, resolver)
	if bytes.Equal(expected, backupBytes) {
		return classUnmodified, "", nil
	}
	// Diff the actual current→backup change, not the substitution-applied
	// reconstruction, so cleanly-resolving placeholder lines stay visible.
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
// .env size (tens to hundreds of lines).
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

// resolverFromVault returns a placeholderResolver mapping each credential's
// placeholder → real value.
func resolverFromVault(v *vault.Vault) placeholderResolver {
	resolver := make(placeholderResolver)
	for _, cred := range v.List() {
		if cred.Placeholder != "" {
			resolver[cred.Placeholder] = cred.Real
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

	// Gate symlink refusal BEFORE classification (no reads) and BEFORE
	// confirmation (no destructive rename) so a refused project sees no
	// leak and no state mutation.
	if err := refuseSymlinkedBackupPairs(root, pairs); err != nil {
		return err
	}

	var resolver placeholderResolver
	if stateExists {
		if v, err := openVault(root); err == nil {
			resolver = resolverFromVault(v)
		} else {
			ui.Warnf(ew, "could not open vault for placeholder resolution: %v", err)
		}
	}

	type planned struct {
		pair   backupPair
		status classification
		diff   string
	}
	plan := make([]planned, 0, len(pairs))
	for _, p := range pairs {
		status, diff, cerr := classifyEnvPair(p.original, p.backup, resolver)
		if cerr != nil {
			return wrapErr(fmt.Sprintf("classifying %s", p.original), cerr)
		}
		plan = append(plan, planned{pair: p, status: status, diff: diff})
	}

	_, _ = fmt.Fprintln(w, "Uninstall plan:")
	for _, pl := range plan {
		_, _ = fmt.Fprintf(w, "  [%s] %s\n", classLabel(pl.status), pl.pair.original)
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

	// When --yes is used non-interactively, the user never saw the diff —
	// surface a single warning so scripted runs that clobber post-init edits
	// don't fail silently. We still proceed (the existing --yes contract is
	// "skip the prompt"), but the warning tells the operator to re-run
	// interactively if they want to review the diff first.
	if yes {
		modifiedCount := 0
		for _, pl := range plan {
			if pl.status == classModified {
				modifiedCount++
			}
		}
		if modifiedCount > 0 {
			ui.Warnf(w, "%d %s have user edits that will be overwritten. Re-run without --yes to review the diff.",
				modifiedCount, plural(modifiedCount, "file", "files"))
		}
	}

	if !yes && !promptYN(newLineReader(cmd.InOrStdin()), w, "Proceed with uninstall?", false) {
		_, _ = fmt.Fprintln(w, "Aborted.")
		return nil
	}

	// moved counts every backup→original rename; materialized tracks the
	// subset where the original was absent (newly placed rather than restored).
	moved, materialized := 0, 0
	for _, pl := range plan {
		// Print a per-file dim line BEFORE the rename so a mid-loop crash
		// leaves a trail of which files were restored vs. still pending.
		// Re-running uninstall picks up the unmoved sidecars via
		// discoverBackups, but the user otherwise has no signal about
		// partial progress.
		ui.Dimf(w, "  restoring: %s", displayRelOr(root, pl.pair.original, pl.pair.original))
		if err := os.Rename(pl.pair.backup, pl.pair.original); err != nil {
			return wrapErr(fmt.Sprintf("restoring %s", pl.pair.original), err)
		}
		moved++
		if pl.status == classOriginalMissing {
			materialized++
		}
	}

	if stateExists {
		purgeKeystoreEntry(ew, root)
		if err := os.RemoveAll(stateDir); err != nil {
			return wrapErr(fmt.Sprintf("removing %s", stateDir), err)
		}
	}

	removeVeilOnlyGitignore(w, root)

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

// removeVeilOnlyGitignore deletes .gitignore when its non-empty content is
// exactly the two lines veil init writes (`/.veil/` and `*.veil-backup`).
// If the user added other entries (before or after init), the file is left
// untouched — those entries are theirs. Best-effort: any read or stat
// failure is silent so uninstall completes cleanly.
func removeVeilOnlyGitignore(w io.Writer, root string) {
	gitignorePath := filepath.Join(root, ".gitignore")
	// Reject symlinks: a hostile cloned repo could swing the path at
	// another file (~/.bashrc, etc.). os.Lstat sees the link itself.
	info, err := os.Lstat(gitignorePath)
	if err != nil {
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return
	}
	data, err := os.ReadFile(gitignorePath) // #nosec G304 -- project-local gitignore
	if err != nil {
		return
	}
	if !gitignoreIsVeilOnly(data) {
		return
	}
	if err := os.Remove(gitignorePath); err == nil {
		ui.Step(w, "removed Veil-only .gitignore")
	}
}

// gitignoreIsVeilOnly reports whether the file content is exactly the two
// Veil-added lines (in either order, with blank-line / trailing-whitespace
// tolerance) and nothing else. Comments count as non-Veil content.
func gitignoreIsVeilOnly(data []byte) bool {
	veilLines := map[string]bool{
		"/.veil/":       true,
		"*.veil-backup": true,
	}
	seen := make(map[string]bool, 2)
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !veilLines[line] {
			return false
		}
		seen[line] = true
	}
	return len(seen) == len(veilLines)
}

// purgeKeystoreEntry best-effort deletes the keystore entry tied to this
// project. Any failure is surfaced as a warning; uninstall continues so
// state-dir removal still runs.
func purgeKeystoreEntry(ew io.Writer, root string) {
	pid, err := vault.ReadProjectID(root)
	if err != nil {
		ui.Warnf(ew, "keystore purge skipped: %v", err)
		return
	}
	ks, err := buildKeystore()
	if err != nil {
		ui.Warnf(ew, "keystore purge skipped: %v", err)
		return
	}
	if err := ks.Delete(pid); err != nil {
		ui.Warnf(ew, "could not purge keystore entry: %v", err)
	}
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
