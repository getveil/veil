package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/placeholder"
	"github.com/getveil/veil/internal/proxy"
	"github.com/getveil/veil/internal/scanner"
	"github.com/getveil/veil/internal/skiphost"
	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// detectInteractive reports whether the init flow should prompt the user
// and whether the caller should announce non-interactive mode. announce is
// true only when init fell back to non-interactive mode because stdin is
// not a TTY (not when --yes was passed). Callers should defer printing the
// announcement until after preconditions succeed, so users do not see a
// "proceeding" notice before a precondition failure.
func detectInteractive(stdin io.Reader, yes bool) (interactive, announce bool) {
	if yes {
		return false, false
	}
	f, ok := stdin.(*os.File)
	if !ok {
		return true, false
	}
	if isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()) {
		return true, false
	}
	return false, true
}

// resolveInitRoot returns the project root to initialize. Falls back to
// FindProjectRoot when --path is empty so `veil init` can legally create
// the first project marker in a directory.
func resolveInitRoot() (string, error) {
	if flagPath == "" {
		return config.FindProjectRoot(".")
	}
	return filepath.Abs(flagPath)
}

// detectExistingProject returns (proceed, err). If the project is already
// initialized and --force was not passed, an ErrAlreadyInitialized error is
// returned. With --force in interactive mode, the user is asked to confirm;
// a "no" answer returns proceed=false and no error.
func detectExistingProject(in io.Reader, w io.Writer, stateDir string, force, interactive bool) (bool, error) {
	info, err := os.Stat(stateDir)
	if err != nil || !info.IsDir() {
		return true, nil
	}
	if !force {
		return false, cliErrorWith(ErrAlreadyInitialized, "project already initialized", "Use --force to reinitialize")
	}
	if interactive && !promptYN(in, w, "This will replace your existing vault. Continue?", false) {
		ui.Dim(w, "Cancelled.")
		return false, nil
	}
	return true, nil
}

// displayRelOr renders p relative to root for error messages, or returns
// fallback when Rel fails or is degenerate. Callers that operate on paths
// likely under root (init) pass filepath.Base(p); callers that may operate
// on paths outside root (uninstall) pass the original path.
func displayRelOr(root, p, fallback string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == "" {
		return fallback
	}
	return rel
}

// displayRel is displayRelOr with filepath.Base(p) as the fallback.
func displayRel(root, p string) string {
	return displayRelOr(root, p, filepath.Base(p))
}

// describeSymlink formats "<display> -> <target>" for a known symlink at p,
// or just "<display>" when readlink fails.
func describeSymlink(p, display string) string {
	if target, err := os.Readlink(p); err == nil && target != "" {
		return fmt.Sprintf("%s -> %s", display, target)
	}
	return display
}

// appendIfSymlink appends a "<display> -> <target>" entry to hits when p is a
// symlink, otherwise returns hits unchanged. The caller decides the display
// label (e.g. basename, project-relative, or full path).
func appendIfSymlink(hits []string, p, display string) []string {
	info, err := os.Lstat(p)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return hits
	}
	return append(hits, describeSymlink(p, display))
}

// firstSymlinkInChain walks from anchor down through subpath, Lstating each
// intermediate component. Returns the first component that is a symlink, or
// "" when the chain has none. Using EvalSymlinks would silently follow the
// very attacker-controlled symlink the caller is trying to detect, so each
// component is Lstat'd literally.
func firstSymlinkInChain(anchor string, subpath []string) string {
	current := anchor
	for _, part := range subpath {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return ""
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return current
		}
	}
	return ""
}

// refuseSymlinkedInputs refuses to vault any input that is a symbolic link
// at the leaf OR whose parent chain contains a symlink. Either case would
// redirect the subsequent read/write/rename to an attacker-controlled
// location: the symlink is replaced with a placeholder file inside the
// project while cleartext lands at the link target — strictly worse exposure
// than not running Veil. Aggregates every violation so the user fixes them
// in one pass.
func refuseSymlinkedInputs(root string, envPaths []string) error {
	var hits []string

	for _, p := range envPaths {
		hits = appendIfSymlink(hits, p, displayRel(root, p))
	}

	// .env anchor is the project root. We walk each file's parent chain
	// so a .env discovered in a subdirectory with a symlinked ancestor is
	// refused — not just leaf-symlinked files.
	for _, p := range envPaths {
		rel, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil || rel == "" || rel == "." || strings.HasPrefix(rel, "..") {
			continue
		}
		hit := firstSymlinkInChain(root, strings.Split(filepath.ToSlash(rel), "/"))
		if hit == "" {
			continue
		}
		hits = append(hits, fmt.Sprintf("%s (parent %s)", displayRel(root, p), describeSymlink(hit, hit)))
	}

	if len(hits) == 0 {
		return nil
	}
	return cliError(
		fmt.Sprintf(
			"%s a symbolic link or has a symlinked parent: %s. Vaulting a symlinked input — or one whose parent chain redirects outside the expected location — would replace the symlink with a placeholder file and write cleartext to a sibling .veil-backup that may land outside the project, exposing secrets to an attacker-controlled location.",
			plural(len(hits), "input is", "inputs are"),
			strings.Join(hits, ", "),
		),
		"Replace the symlink with a regular file (e.g. `cp -L` to materialize the target) and re-run, or remove the symlinked parent so Veil operates on the canonical path.",
	)
}

// refusePlaceholderInputs scans the files init is about to vault and refuses
// to proceed if any contains a value bearing the placeholder sentinel. Those
// values were produced by a prior Generate call — re-running init over them
// would overwrite the user's backup and keystore with placeholder strings,
// destroying every copy of the original secret Veil controls. Files with an
// existing sibling .veil-backup are skipped unless --force is set, since the
// downstream "already has a backup" short-circuit makes them safe.
func refusePlaceholderInputs(root string, envPaths []string, force bool) error {
	var hits []string

	for _, p := range envPaths {
		if !force && backupExists(p) {
			continue
		}
		f, err := scanner.ParseFile(p)
		if err != nil {
			continue
		}
		rel := displayRel(root, p)
		for _, line := range f.Lines {
			if line.Kind != scanner.KVLine {
				continue
			}
			if placeholder.IsSecretLike(line.Key, line.Value) && placeholder.ContainsSentinel(line.Value) {
				hits = append(hits, fmt.Sprintf("%s: %s", rel, line.Key))
			}
		}
	}

	if len(hits) == 0 {
		return nil
	}
	return cliError(
		fmt.Sprintf(
			"%s already %s Veil placeholders: %s. Re-vaulting would overwrite the backup and keystore with these placeholders, destroying your original secrets.",
			plural(len(hits), "input", "inputs"),
			plural(len(hits), "contains", "contain"),
			strings.Join(hits, ", "),
		),
		"Run `veil uninstall` to restore the originals from their .veil-backup sidecars, then `veil init` again.",
	)
}

// filterInputs asks the user to narrow the set of .env files to scan when
// more than one was discovered. In non-interactive mode, or when only a
// single input was found, the inputs pass through unchanged. A "Y" answer
// keeps everything; "n" drops everything; "s" lets the user multi-select.
// Per-secret prompts inside each file still run during processing.
func filterInputs(
	in io.Reader,
	w io.Writer,
	root string,
	envPaths []string,
	interactive bool,
) []string {
	if !interactive || len(envPaths) <= 1 {
		return envPaths
	}

	_, _ = fmt.Fprintf(w, "\nFound %d %s to process:\n", len(envPaths), plural(len(envPaths), "input", "inputs"))
	displays := make([]string, len(envPaths))
	for i, p := range envPaths {
		displays[i] = displayRel(root, p)
		_, _ = fmt.Fprintf(w, "  %s\n", displays[i])
	}
	_, _ = fmt.Fprintln(w)

	switch promptYNS(in, w, "Scan all?") {
	case choiceYes:
		return envPaths
	case choiceNo:
		return nil
	case choiceSelect:
		picked := make(map[string]bool, len(envPaths))
		for _, n := range promptMultiSelect(in, w, displays) {
			picked[n] = true
		}
		var selEnvs []string
		for i, p := range envPaths {
			if i < len(displays) && picked[displays[i]] {
				selEnvs = append(selEnvs, p)
			}
		}
		return selEnvs
	}
	return envPaths
}

// secretLine is one vaultable key/value pair discovered in a .env file.
type secretLine struct {
	key   string
	value string
	index int
}

// processEnvFile reads envPath, prompts the user for which keys to vault
// (in interactive mode), adds credentials to v, and rewrites the .env file
// with placeholders. Returns (vaulted, scoped) counts for the file. The seen
// set is shared across files so placeholder generation stays collision-free.
//
// Write order per file (atomicity boundary):
//  1. build creds in memory
//  2. build .env bytes in memory
//  3. writeBackup(envPath)
//  4. v.AddBatch(creds)
//  5. atomicWriteFile(envPath, bytes)
//
// If we crash between 4 and 5 the next run detects the vault-knows-but-
// cleartext-on-disk state via recoverPendingEnvRewrite and replays step 5
// only.
func processEnvFile(cmd *cobra.Command, in io.Reader, v *vault.Vault, seen placeholder.Set, root, envPath string, force, dryRun, interactive bool) (int, int, error) {
	if backupExists(envPath) && !force {
		// Orphan check: a backup whose adjacent .env carries Veil-shaped
		// placeholders that the CURRENT vault doesn't own is the output of
		// a prior install whose state is gone (different vault root, wiped
		// .veil/, etc.) — the backup, not the stale placeholders, is the
		// true pre-Veil state. Replaces the vault.meta vaulted-files
		// registry the launch cuts dropped.
		orphan, oerr := isOrphanByContent(v, envPath)
		if oerr != nil {
			return 0, 0, wrapErr(fmt.Sprintf("checking backup status of %s", envPath), oerr)
		}
		if orphan {
			if err := reclaimOrphanedBackup(envPath); err != nil {
				return 0, 0, wrapErr(fmt.Sprintf("reclaiming orphan backup %s", envPath), err)
			}
			ui.Warnf(cmd.ErrOrStderr(), "%s had an orphaned backup from a prior Veil install — restoring it as the source of truth before re-vaulting", envPath)
		} else {
			recovered, rerr := recoverPendingEnvRewrite(cmd, v, envPath, dryRun)
			if rerr != nil {
				return 0, 0, rerr
			}
			if recovered {
				return 0, 0, nil
			}
			ui.Warnf(cmd.ErrOrStderr(), "%s already has a backup (use --force to re-vault)", envPath)
			return 0, 0, nil
		}
	}

	envFile, err := scanner.ParseFile(envPath)
	if err != nil {
		return 0, 0, wrapErr(fmt.Sprintf("parsing %s", envPath), err)
	}

	var secrets []secretLine
	w := cmd.OutOrStdout()
	for i, line := range envFile.Lines {
		if line.Kind != scanner.KVLine {
			continue
		}
		if !placeholder.IsSecretLike(line.Key, line.Value) {
			if flagVerbose {
				ui.Dimf(w, "  skip (not secret-like): %s", line.Key)
			}
			continue
		}
		secrets = append(secrets, secretLine{key: line.Key, value: line.Value, index: i})
	}
	if len(secrets) == 0 {
		return 0, 0, nil
	}

	selectedSecrets := selectEnvKeys(in, w, root, envPath, secrets, interactive)
	if len(selectedSecrets) == 0 {
		return 0, 0, nil
	}

	res, err := buildEnvFileCredentials(envFile, selectedSecrets, seen)
	if err != nil {
		return 0, 0, err
	}
	if len(res.Creds) == 0 && len(res.Skipped) == 0 {
		return 0, 0, nil
	}

	printVaultSummary(w, res, dryRun)

	if dryRun {
		printDryRunVaultLines(w, selectedSecrets, res.Creds)
		return res.Vaulted, res.Scoped, nil
	}

	if len(res.Creds) == 0 {
		return 0, 0, nil
	}

	// envFile has already been mutated in place; freeze the bytes before any
	// I/O so the on-disk state moves atomically.
	newBytes := envFile.Bytes()

	// --force: clear any existing entries that would otherwise collide. A
	// duplicate at AddBatch time means a prior partial run stranded a cred
	// without a matching backup/rewrite; skipping silently would strand it.
	if force {
		for _, c := range res.Creds {
			if v.HasCredential(c.Name) {
				if _, err := v.Delete(c.Name); err != nil {
					return 0, 0, wrapErr(fmt.Sprintf("clearing existing %s for --force", c.Name), err)
				}
			}
		}
	}

	if err := writeBackup(envPath); err != nil {
		return 0, 0, wrapErr(fmt.Sprintf("writing backup for %s", envPath), err)
	}
	if err := v.AddBatch(res.Creds); err != nil {
		return 0, 0, wrapErr(fmt.Sprintf("vaulting %s", envPath), err)
	}
	if err := atomicWriteFile(envPath, newBytes); err != nil {
		return 0, 0, wrapErr(fmt.Sprintf("writing %s", envPath), err)
	}
	return res.Vaulted, res.Scoped, nil
}

// vaultBuildResult bundles the outputs of buildEnvFileCredentials so
// callers can render the summary without changing the function's
// positional return list every time a new bucket is added.
type vaultBuildResult struct {
	Creds      []*vault.Credential
	Vaulted    int
	Scoped     int
	Skipped    []secretLine     // Bearer-shaped but no registered provider — `veil add` may help
	OutOfScope []outOfScopeLine // known v1 non-Bearer scheme — `veil add` won't help
}

// outOfScopeLine is a secret that init explicitly cannot mediate in v1
// (URL-with-embedded-password, AWS SigV4, HTTP Basic, etc.). The annotation
// explains the scheme so the user understands the `veil add` hint shown for
// the Bearer-shaped Skipped bucket would not actually protect this value.
type outOfScopeLine struct {
	key        string
	annotation string
}

// Compiled name-pattern matchers for the out-of-scope categorizer. Compiled
// once at package init to avoid the per-call compile cost on every init run.
var (
	outOfScopeURLNameRE   = regexp.MustCompile(`(?i)^DATABASE_URL$|^DB_URL$|.*_DSN$|.*_CONNECTION_STRING$|.*POSTGRES.*|.*MYSQL.*|.*MONGO.*`)
	outOfScopeAWSNameRE   = regexp.MustCompile(`(?i)^AWS_.*`)
	outOfScopeBasicNameRE = regexp.MustCompile(`(?i).*BASIC.*`)
	// embeddedPasswordURLRE matches scheme://user:password@host... URLs that
	// look like a TCP-protocol connection string with an inline password.
	// Used as the value-shape leg of the URL-with-embedded-password rule.
	embeddedPasswordURLRE = regexp.MustCompile(`^(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps)://[^/@]*:[^/@]+@`)
)

// categorizeOutOfScope reports whether (name, value) belongs to a v1 out-of-
// scope scheme and, if so, returns the annotation to surface in the summary.
// Returns ("", false) for Bearer-shaped values that should keep the existing
// "Skipped — `veil add`" path.
//
// Rules applied in order (first match wins):
//  1. URL-with-embedded-password: name looks like a connection-string env or
//     value parses as scheme://user:password@... — annotation explains TCP.
//  2. AWS_*: SigV4 is out of scope for v1.
//  3. *BASIC*: HTTP Basic auth is out of scope (see docs/MVP.md §5).
func categorizeOutOfScope(name, value string) (string, bool) {
	if outOfScopeURLNameRE.MatchString(name) || embeddedPasswordURLRE.MatchString(value) {
		return "(URL with embedded password — not a Bearer header)", true
	}
	if outOfScopeAWSNameRE.MatchString(name) {
		return "(looks like an AWS credential — Veil does not handle SigV4 in v1)", true
	}
	if outOfScopeBasicNameRE.MatchString(name) {
		return "(HTTP Basic auth — see docs/MVP.md §5)", true
	}
	return "", false
}

// buildEnvFileCredentials constructs the credentials for one .env file from
// the user's selection. envFile is mutated in place so each selected key
// now holds its placeholder; callers can take envFile.Bytes() once
// buildEnvFileCredentials returns. The seen set is updated with every
// placeholder generated, in caller-visible order.
func buildEnvFileCredentials(
	envFile *scanner.EnvFile,
	secrets []secretLine,
	seen placeholder.Set,
) (vaultBuildResult, error) {
	var res vaultBuildResult

	for _, s := range secrets {
		if !isVaultEligible(s.key, s.value) {
			// Route v1 out-of-scope schemes (URL-with-password, AWS SigV4,
			// HTTP Basic) to a dedicated bucket so the renderer can mark them
			// as "Veil cannot mediate these" rather than implying the user
			// can rescue them with `veil add`.
			if annotation, ok := categorizeOutOfScope(s.key, s.value); ok {
				res.OutOfScope = append(res.OutOfScope, outOfScopeLine{key: s.key, annotation: annotation})
				continue
			}
			res.Skipped = append(res.Skipped, s)
			continue
		}
		ph, gErr := placeholder.Generate(s.key, s.value, seen)
		if gErr != nil {
			return vaultBuildResult{}, wrapErr(fmt.Sprintf("generating placeholder for %s", s.key), gErr)
		}
		credHosts := placeholder.HostsForCredential(s.key, s.value)
		res.Creds = append(res.Creds, &vault.Credential{
			ID:           vault.NewID(),
			Name:         s.key,
			Real:         s.value,
			Placeholder:  ph,
			Source:       "init",
			AllowedHosts: credHosts,
			CreatedAt:    time.Now(),
		})
		envFile.SetValue(s.key, ph)
		seen[ph] = struct{}{}
		res.Vaulted++
		if len(credHosts) > 0 {
			res.Scoped++
		}
	}

	return res, nil
}

// applyEnvFileMutations rewrites envFile in place so each credential's source
// key now holds its placeholder, then returns the resulting bytes. Used only
// by the recovery path; the happy path mutates envFile inside
// buildEnvFileCredentials and just calls envFile.Bytes() there.
func applyEnvFileMutations(envFile *scanner.EnvFile, creds []*vault.Credential) []byte {
	for _, c := range creds {
		envFile.SetValue(c.Name, c.Placeholder)
	}
	return envFile.Bytes()
}

// printDryRunVaultLines emits "would vault: KEY -> PLACEHOLDER" for each
// vault-eligible credential, preserving the file's appearance order.
// Skipped entries in secrets (no provider match) are filtered via name
// lookup so the pairing stays correct when eligible and skipped lines mix.
func printDryRunVaultLines(w io.Writer, secrets []secretLine, creds []*vault.Credential) {
	byName := make(map[string]string, len(creds))
	for _, c := range creds {
		byName[c.Name] = c.Placeholder
	}
	for _, s := range secrets {
		if ph, ok := byName[s.key]; ok {
			ui.Dimf(w, "  would vault: %s -> %s", s.key, ph)
		}
	}
}

// isVaultEligible reports whether `veil init` should move (name, value)
// into the vault. True iff a registered provider claims the pair AND the
// provider declares VaultEligible with a non-empty host scope. The
// charclass fallback (no named provider) is never eligible — a vaulted
// credential without host scope has nowhere to fire on injection.
//
// Replaces the pre-launch three-way bucket discriminator (Unrecognized /
// Not managed / Eligible) the AuthScheme enum used to drive. With only
// Bearer surviving, the gate is binary: vault or skip.
func isVaultEligible(name, value string) bool {
	p := placeholder.DefaultRegistry().Match(name, value)
	if p == nil {
		return false
	}
	if len(p.Hosts) == 0 {
		return false
	}
	return p.VaultEligible
}

// printVaultSummary emits the three-section summary: Vaulted, Skipped, and
// Out of scope. Called on every run (not just --dry-run) after
// buildEnvFileCredentials returns. When dryRun is true the Vaulted section is
// suppressed — printDryRunVaultLines already shows those keys as "would
// vault" lines, so printing them here too would double-print each credential.
//
// Empty sections are omitted. Section order is Vaulted → Skipped (Bearer-no-
// provider, with the `veil add` hint) → Out of scope (with the docs/MVP.md
// footer). The split matters because the `veil add` hint can rescue a Bearer
// value with an unknown provider, but it cannot help with the schemes routed
// to Out of scope (URL-with-password, AWS SigV4, HTTP Basic).
//
// Name columns are padded to the widest name across ALL three sections so the
// value/annotation columns line up when the user scans top-to-bottom.
// Skipped's name-only rows pad to the same width so the visual table reads as
// a single block.
func printVaultSummary(w io.Writer, res vaultBuildResult, dryRun bool) {
	nameW := vaultSummaryNameWidth(res, dryRun)
	if !dryRun && len(res.Creds) > 0 {
		_, _ = fmt.Fprintf(w, "\nVaulted (%d):\n", len(res.Creds))
		for _, c := range res.Creds {
			_, _ = fmt.Fprintf(w, "    %s    %s\n", padRight(c.Name, nameW), c.Placeholder)
		}
	}
	if len(res.Skipped) > 0 {
		_, _ = fmt.Fprintf(w, "\nSkipped — no recognized provider or host scope (%d):\n", len(res.Skipped))
		for _, s := range res.Skipped {
			_, _ = fmt.Fprintf(w, "    %s\n", padRight(s.key, nameW))
		}
		// One hint per Skipped block tells the user how to vault these
		// values manually without forcing them to figure out the right flag
		// names. Printed only once at the bottom so a file with N skipped
		// rows doesn't repeat the line N times.
		ui.Dim(w, "  To vault a custom credential manually: veil add <NAME> --value-stdin --host <host>")
	}
	if len(res.OutOfScope) > 0 {
		_, _ = fmt.Fprintf(w, "\nOut of scope — Veil cannot mediate these in v1 (%d):\n", len(res.OutOfScope))
		for _, s := range res.OutOfScope {
			// Pad the plain name first, then apply ANSI styling — escape codes
			// in the annotation must come after padding so column widths stay
			// based on visible characters.
			_, _ = fmt.Fprintf(w, "    %s    %s\n", padRight(s.key, nameW), ui.Muted.Sprint(s.annotation))
		}
		ui.Dim(w, "  These remain in your .env. See docs/MVP.md for the v1 scope contract.")
	}
}

// vaultSummaryNameWidth returns the widest name across every section
// printVaultSummary will render, so all three sections share the same
// name-column width. Sections suppressed by dryRun (Vaulted) don't contribute
// to the width — otherwise a dry-run with no Skipped/OutOfScope entries
// could pad nothing.
func vaultSummaryNameWidth(res vaultBuildResult, dryRun bool) int {
	width := 0
	if !dryRun {
		for _, c := range res.Creds {
			width = maxInt(width, len(c.Name))
		}
	}
	for _, s := range res.Skipped {
		width = maxInt(width, len(s.key))
	}
	for _, s := range res.OutOfScope {
		width = maxInt(width, len(s.key))
	}
	return width
}

// needsEnvRewrite reports whether envPath still has cleartext for any cred
// in creds — i.e., NONE of the credentials' placeholders appear as a
// substring of the file. True signals a crash between meta-register and
// .env-rewrite that should be replayed.
func needsEnvRewrite(envPath string, creds []*vault.Credential) (bool, error) {
	data, err := os.ReadFile(envPath) // #nosec G304 -- envPath is a vaulted project file
	if err != nil {
		return false, err
	}
	for _, c := range creds {
		if c.Placeholder != "" && bytes.Contains(data, []byte(c.Placeholder)) {
			return false, nil
		}
	}
	return true, nil
}

// recoverPendingEnvRewrite detects the "meta is registered but .env was
// never rewritten" crash state. When that holds it replays only step 6
// (the atomic rewrite) using the credentials already in the vault. Returns
// (true, nil) when recovery ran; (false, nil) means the caller should fall
// through to the existing "already has a backup" warning.
func recoverPendingEnvRewrite(cmd *cobra.Command, v *vault.Vault, envPath string, dryRun bool) (bool, error) {
	if dryRun {
		return false, nil
	}
	envFile, err := scanner.ParseFile(envPath)
	if err != nil {
		return false, wrapErr(fmt.Sprintf("parsing %s", envPath), err)
	}
	var owned []*vault.Credential
	ownedValues := make(map[string]string)
	for _, line := range envFile.Lines {
		if line.Kind != scanner.KVLine {
			continue
		}
		if c, ok := v.Get(line.Key); ok {
			owned = append(owned, c)
			ownedValues[line.Key] = line.Value
		}
	}
	if len(owned) == 0 {
		return false, nil
	}
	rewrite, err := needsEnvRewrite(envPath, owned)
	if err != nil {
		return false, wrapErr(fmt.Sprintf("checking rewrite state of %s", envPath), err)
	}
	if !rewrite {
		return false, nil
	}
	// Before rewriting placeholders over cleartext, confirm each key's
	// current cleartext still equals the credential's stored Real. A
	// mismatch means the user edited the .env between the crash and this
	// run; silently rewriting would discard their edit and point the .env
	// at a stale vault entry. Refuse and surface an actionable error.
	var diverged []string
	for _, c := range owned {
		val, ok := ownedValues[c.Name]
		if !ok {
			continue
		}
		if val != c.Real {
			diverged = append(diverged, c.Name)
		}
	}
	if len(diverged) > 0 {
		msg := fmt.Sprintf(
			"%s has been edited since vaulting was interrupted; values for [%s] no longer match the vault. Re-run `veil init --force` to re-vault from the current .env, or restore the .veil-backup sidecar if you didn't mean to edit",
			envPath,
			strings.Join(diverged, ", "),
		)
		return false, wrapErr("recovering interrupted init", errors.New(msg))
	}
	newBytes := applyEnvFileMutations(envFile, owned)
	if err := atomicWriteFile(envPath, newBytes); err != nil {
		return false, wrapErr(fmt.Sprintf("writing %s", envPath), err)
	}
	ui.Warnf(cmd.ErrOrStderr(), "%s: recovering interrupted init — re-applying placeholders", envPath)
	return true, nil
}

// selectEnvKeys returns the bearer secrets the user chose to vault.
// In non-interactive mode everything is selected. Callers that receive
// an empty slice should skip the file.
func selectEnvKeys(
	in io.Reader, w io.Writer, root, envPath string,
	secrets []secretLine, interactive bool,
) (selectedSecrets []secretLine) {
	if !interactive {
		return secrets
	}

	rel := displayRel(root, envPath)

	total := len(secrets)
	header := fmt.Sprintf("\nDetected %d %s in %s:", total, plural(total, "secret", "secrets"), rel)
	_, _ = fmt.Fprintln(w, header)

	names := make([]string, 0, len(secrets))
	for _, s := range secrets {
		_, _ = fmt.Fprintf(w, "  %-7s %-24s %s\n", "", s.key, ui.Muted.Sprint(redactValue(s.value)))
		names = append(names, s.key)
	}
	_, _ = fmt.Fprintln(w)

	switch promptYNS(in, w, "Vault all?") {
	case choiceYes:
		return secrets
	case choiceNo:
		return nil
	case choiceSelect:
		picked := make(map[string]bool)
		for _, n := range promptMultiSelect(in, w, names) {
			picked[n] = true
		}
		for _, s := range secrets {
			if picked[s.key] {
				selectedSecrets = append(selectedSecrets, s)
			}
		}
		return selectedSecrets
	}
	return nil
}

// promptSkipHostsPhase asks the user to seed the skip-host list after vaulting.
// No-op in non-interactive or dry-run mode.
func promptSkipHostsPhase(in io.Reader, w io.Writer, root string, interactive, dryRun bool) {
	if !interactive || dryRun {
		return
	}
	_, _ = fmt.Fprintln(w, "Skip hosts — any hosts the proxy should pass through untouched?")
	ui.Dim(w, "Common examples: api.anthropic.com, *.internal.company.com")
	ui.Dim(w, "(Pass --skip <host> to veil run for one-off bypass.)")
	_, _ = fmt.Fprintln(w)
	hosts := promptCSV(in, w, "Hosts to skip (comma-separated, or Enter to skip):")
	if len(hosts) == 0 {
		return
	}
	skipPath := config.SkipHostsFile(root)
	for _, h := range hosts {
		if _, err := skiphost.Add(skipPath, h); err != nil {
			ui.Warn(w, fmt.Sprintf("failed to add %s to skip list: %v", h, err))
			continue
		}
		ui.Step(w, fmt.Sprintf("%s added to skip list", h))
	}
	_, _ = fmt.Fprintln(w)
}

// setupProxyCA loads or creates the CA. Prints a success step on completion.
// When dryRun is true, no CA is written to disk — we instead report whether
// the CA already exists ("CA certificate already present") or what would be
// created ("Would create CA certificate at <path>").
func setupProxyCA(w io.Writer, dryRun bool) error {
	if dryRun {
		certPath, exists, err := proxy.CheckCA()
		if err != nil {
			return wrapErr("checking CA", err)
		}
		if exists {
			ui.Step(w, "CA certificate already present")
		} else {
			ui.Step(w, fmt.Sprintf("Would create CA certificate at %s", ui.RedactPath(certPath)))
		}
		_, _ = fmt.Fprintln(w)
		return nil
	}
	if _, err := proxy.LoadOrCreateCA(); err != nil {
		return wrapErr("setting up CA", err)
	}
	ui.Step(w, "CA certificate ready")
	_, _ = fmt.Fprintln(w)
	return nil
}
