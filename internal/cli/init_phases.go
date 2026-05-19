package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/getveil/veil/internal/cli/correlate"
	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/mcpconfig"
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
		ui.Dim(w, "Aborted.")
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
func refuseSymlinkedInputs(root string, envPaths []string, mcpConfigs []mcpconfig.DiscoveredConfig) error {
	var hits []string

	for _, p := range envPaths {
		hits = appendIfSymlink(hits, p, displayRel(root, p))
	}
	for _, cfg := range mcpConfigs {
		hits = appendIfSymlink(hits, cfg.Path, displayRel(root, cfg.Path))
	}

	checkChain := func(anchor string, subpath []string, leafDisplay string) {
		hit := firstSymlinkInChain(anchor, subpath)
		if hit == "" {
			return
		}
		hits = append(hits, fmt.Sprintf("%s (parent %s)", leafDisplay, describeSymlink(hit, hit)))
	}

	// .env anchor is the project root. Scanner only looks at root itself
	// today (no subdirs), so the walk is a no-op for current code; we keep
	// it so a future nested scanner does not silently regress.
	for _, p := range envPaths {
		rel, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil || rel == "" || rel == "." || strings.HasPrefix(rel, "..") {
			continue
		}
		checkChain(root, strings.Split(filepath.ToSlash(rel), "/"), displayRel(root, p))
	}

	anchors, err := mcpconfig.ParentAnchors()
	if err != nil {
		return wrapErr("resolving MCP parent anchors", err)
	}
	for _, pa := range anchors {
		checkChain(pa.Anchor, pa.Subpath, fmt.Sprintf("%s (%s, user)", filepath.Join(append([]string{pa.Anchor}, pa.Subpath...)...), pa.Client))
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

// mcpSentinelHits returns "<rel>: <server>.<key>" entries for every value in
// the MCP config at mcpConfigPath that already carries the placeholder
// sentinel. Both env values and positional args are inspected. Parse errors
// are non-fatal — downstream code surfaces them with better context.
func mcpSentinelHits(root, mcpConfigPath string) []string {
	cfg, err := mcpconfig.Parse(mcpConfigPath)
	if err != nil {
		return nil
	}
	rel := displayRel(root, mcpConfigPath)
	var hits []string
	for serverName, server := range cfg.Servers() {
		for k, v := range server.Env {
			if placeholder.IsSecretLike(k, v) && placeholder.ContainsSentinel(v) {
				hits = append(hits, fmt.Sprintf("%s: %s.%s", rel, serverName, k))
			}
		}
		for i, v := range server.Args {
			if placeholder.IsSecretLike("", v) && placeholder.ContainsSentinel(v) {
				hits = append(hits, fmt.Sprintf("%s: %s.args[%d]", rel, serverName, i))
			}
		}
	}
	return hits
}

// refusePlaceholderInputs scans the files init is about to vault and refuses
// to proceed if any contains a value bearing the placeholder sentinel. Those
// values were produced by a prior Generate call — re-running init over them
// would overwrite the user's backup and keystore with placeholder strings,
// destroying every copy of the original secret Veil controls. Files with an
// existing sibling .veil-backup are skipped unless --force is set, since the
// downstream "already has a backup" short-circuit makes them safe.
func refusePlaceholderInputs(root string, envPaths []string, mcpConfigs []mcpconfig.DiscoveredConfig, force bool) error {
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

	for _, cfg := range mcpConfigs {
		if !force && backupExists(cfg.Path) {
			continue
		}
		hits = append(hits, mcpSentinelHits(root, cfg.Path)...)
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

// filterInputs asks the user to narrow the combined set of .env files and
// MCP configs to scan when there is more than one. In non-interactive mode,
// or when only a single input was discovered, the inputs pass through
// unchanged. A "Y" answer keeps everything; "n" drops everything; "s" lets
// the user multi-select across both kinds in one list. Per-secret prompts
// inside each config still run during processing.
func filterInputs(
	in io.Reader,
	w io.Writer,
	root string,
	envPaths []string,
	mcpConfigs []mcpconfig.DiscoveredConfig,
	interactive bool,
) ([]string, []mcpconfig.DiscoveredConfig) {
	total := len(envPaths) + len(mcpConfigs)
	if !interactive || total <= 1 {
		return envPaths, mcpConfigs
	}

	type entry struct {
		display string
		envIdx  int // >= 0 means index into envPaths
		mcpIdx  int // >= 0 means index into mcpConfigs
	}
	var entries []entry
	_, _ = fmt.Fprintf(w, "\nFound %d %s to process:\n", total, plural(total, "input", "inputs"))
	for i, p := range envPaths {
		rel := displayRel(root, p)
		_, _ = fmt.Fprintf(w, "  %s\n", rel)
		entries = append(entries, entry{display: rel, envIdx: i, mcpIdx: -1})
	}
	for i, cfg := range mcpConfigs {
		display := mcpDisplayLabel(root, cfg)
		_, _ = fmt.Fprintf(w, "  %s\n", display)
		entries = append(entries, entry{display: display, envIdx: -1, mcpIdx: i})
	}
	_, _ = fmt.Fprintln(w)

	switch promptYNS(in, w, "Scan all?") {
	case choiceYes:
		return envPaths, mcpConfigs
	case choiceNo:
		return nil, nil
	case choiceSelect:
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.display
		}
		picked := make(map[string]bool, len(entries))
		for _, n := range promptMultiSelect(in, w, names) {
			picked[n] = true
		}
		var selEnvs []string
		var selMCPs []mcpconfig.DiscoveredConfig
		for _, e := range entries {
			if !picked[e.display] {
				continue
			}
			if e.envIdx >= 0 {
				selEnvs = append(selEnvs, envPaths[e.envIdx])
			} else {
				selMCPs = append(selMCPs, mcpConfigs[e.mcpIdx])
			}
		}
		return selEnvs, selMCPs
	}
	return envPaths, mcpConfigs
}

// mcpDisplayLabel formats an MCP config for user-visible lists. User-scope
// configs under the home dir collapse to "~/..."; project-scope show a
// path relative to root. Both append "[client, scope]" to disambiguate.
func mcpDisplayLabel(root string, cfg mcpconfig.DiscoveredConfig) string {
	if cfg.Scope == mcpconfig.ProjectScope {
		return fmt.Sprintf("%s  [%s, %s]", displayRel(root, cfg.Path), cfg.Client, cfg.Scope)
	}
	display := cfg.Path
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(cfg.Path, home+string(os.PathSeparator)) {
		display = "~" + strings.TrimPrefix(cfg.Path, home)
	}
	return fmt.Sprintf("%s  [%s, %s]", display, cfg.Client, cfg.Scope)
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
//  5. registerVaultedFile(root, envPath, KindEnv)
//  6. atomicWriteFile(envPath, bytes)
//
// If we crash between 5 and 6 the next run detects the registered-but-
// cleartext .env via needsEnvRewrite and replays step 6 only.
func processEnvFile(cmd *cobra.Command, in io.Reader, v *vault.Vault, seen placeholder.Set, root, envPath string, force, dryRun, interactive bool) (int, int, error) {
	if backupExists(envPath) && !force {
		// An orphaned backup (one not in the current vault's registry)
		// indicates a prior Veil install whose state is gone — the backup is
		// the source of truth, not the placeholder-filled .env on disk.
		orphan, oerr := isOrphanedBackup(root, envPath)
		if oerr != nil {
			return 0, 0, wrapErr(fmt.Sprintf("checking backup status of %s", envPath), oerr)
		}
		if orphan {
			if err := reclaimOrphanedBackup(envPath); err != nil {
				return 0, 0, wrapErr(fmt.Sprintf("reclaiming orphan backup %s", envPath), err)
			}
			ui.Warnf(cmd.ErrOrStderr(), "%s had an orphaned backup from a prior Veil install — restoring it as the source of truth before re-vaulting", envPath)
			// A crashed run may have committed credentials between AddBatch
			// and registerVaultedFile. Wipe them before re-vaulting so the
			// imminent AddBatch doesn't hit ErrDuplicateCredential.
			if err := cleanupStaleVaultedCreds(cmd, v, envPath); err != nil {
				return 0, 0, wrapErr(fmt.Sprintf("cleaning stale vault credentials for %s", envPath), err)
			}
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
	var allCandidates []correlate.Candidate
	w := cmd.OutOrStdout()
	for i, line := range envFile.Lines {
		if line.Kind != scanner.KVLine {
			continue
		}
		// Feed every KV line into the correlator pool so basicCorrelator
		// can see USER/USERNAME halves whose values (typical identifiers
		// like "alice") would not pass IsSecretLike on their own.
		allCandidates = append(allCandidates, correlate.Candidate{Key: line.Key, Value: line.Value})
		if !placeholder.IsSecretLike(line.Key, line.Value) {
			if flagVerbose {
				ui.Dimf(w, "  skip (not secret-like): %s", line.Key)
			}
			continue
		}
		secrets = append(secrets, secretLine{key: line.Key, value: line.Value, index: i})
	}
	groups, remaining := correlate.DetectAll(allCandidates)
	// filterSecretsByRemaining keeps only entries that were both in the
	// original secret-like-filtered list AND not consumed by a correlator,
	// so non-secret-shaped candidates that fell through stay out of the
	// loose-bearer path.
	remainingSecrets := filterSecretsByRemaining(secrets, remaining)
	if len(groups) == 0 && len(remainingSecrets) == 0 {
		return 0, 0, nil
	}

	selectedGroups, selectedSecrets := selectEnvKeys(in, w, root, envPath, groups, remainingSecrets, interactive)
	if len(selectedGroups) == 0 && len(selectedSecrets) == 0 {
		return 0, 0, nil
	}

	res, err := buildEnvFileCredentials(envFile, selectedGroups, selectedSecrets, seen)
	if err != nil {
		return 0, 0, err
	}
	if len(res.Creds) == 0 && len(res.NotManaged) == 0 && len(res.Unrecognized) == 0 {
		return 0, 0, nil
	}

	printVaultSummary(w, res, dryRun)

	if dryRun {
		printDryRunVaultLines(w, selectedGroups, selectedSecrets, res.Creds)
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
	if err := registerVaultedFile(root, envPath, vault.KindEnv); err != nil {
		return 0, 0, wrapErr(fmt.Sprintf("registering %s", envPath), err)
	}
	if err := atomicWriteFile(envPath, newBytes); err != nil {
		return 0, 0, wrapErr(fmt.Sprintf("writing %s", envPath), err)
	}
	return res.Vaulted, res.Scoped, nil
}

// skippedEntry is a secret that `veil init` decided not to vault.
// Reason is the human-readable label shown in the summary.
type skippedEntry struct {
	key    string
	value  string
	reason string
}

// vaultBuildResult bundles the outputs of buildEnvFileCredentials so
// callers can render the three-section summary without changing the
// function's positional return list every time a new bucket is added.
type vaultBuildResult struct {
	Creds        []*vault.Credential
	CredReasons  []placeholder.Reason // parallel to Creds; describes which detection gate fired
	Vaulted      int
	Scoped       int
	NotManaged   []skippedEntry // recognized provider but not vault-eligible
	Unrecognized []secretLine   // no provider matched (charclass fallback)
}

// buildEnvFileCredentials constructs the credentials for one .env file from
// the user's selection, resolving AWS groups inline. envFile is mutated in
// place so each selected key now holds its placeholder; callers can take
// envFile.Bytes() once buildEnvFileCredentials returns. The seen set is
// updated with every placeholder generated, in caller-visible order.
func buildEnvFileCredentials(
	envFile *scanner.EnvFile,
	groups []correlate.Group,
	secrets []secretLine,
	seen placeholder.Set,
) (vaultBuildResult, error) {
	var res vaultBuildResult
	for _, g := range groups {
		switch g.Scheme {
		case "aws":
			res.NotManaged = append(res.NotManaged,
				skippedEntry{
					key:    g.AWS.AccessKeyIDVar,
					value:  g.AWS.AccessKeyID,
					reason: placeholder.AuthSchemeReason(placeholder.AuthSigV4),
				},
				skippedEntry{
					key:    g.AWS.SecretKeyVar,
					value:  g.AWS.SecretKey,
					reason: placeholder.AuthSchemeReason(placeholder.AuthSigV4),
				})
			if g.AWS.SessionTokenVar != "" {
				res.NotManaged = append(res.NotManaged, skippedEntry{
					key:    g.AWS.SessionTokenVar,
					value:  g.AWS.SessionToken,
					reason: placeholder.AuthSchemeReason(placeholder.AuthSigV4),
				})
			}
			continue

		case "basic":
			userPh, gErr := placeholder.Generate(g.Basic.UsernameVar, g.Basic.Username, seen)
			if gErr != nil {
				return vaultBuildResult{}, wrapErr(fmt.Sprintf("generating placeholder for %s", g.Basic.UsernameVar), gErr)
			}
			seen[userPh] = struct{}{}
			passPh, gErr := placeholder.Generate(g.Basic.PasswordVar, g.Basic.Password, seen)
			if gErr != nil {
				return vaultBuildResult{}, wrapErr(fmt.Sprintf("generating placeholder for %s", g.Basic.PasswordVar), gErr)
			}
			seen[passPh] = struct{}{}

			credHosts := placeholder.HostsForCredential(g.Basic.PasswordVar, g.Basic.Password)
			res.Creds = append(res.Creds, &vault.Credential{
				ID:                  vault.NewID(),
				Name:                g.Name, // password var's key
				Real:                g.Basic.Password,
				Placeholder:         passPh,
				Source:              "init",
				AllowedHosts:        credHosts,
				CreatedAt:           time.Now(),
				Username:            g.Basic.Username,
				UsernamePlaceholder: userPh,
				UsernameVar:         g.Basic.UsernameVar,
			})
			// Basic pairs are produced by the correlator's name-pattern
			// pairing, so the most honest reason is the name-gate
			// applied to the password var.
			_, reason := placeholder.DetectWithReason(g.Basic.PasswordVar, g.Basic.Password)
			res.CredReasons = append(res.CredReasons, reason)
			envFile.SetValue(g.Basic.UsernameVar, userPh)
			envFile.SetValue(g.Basic.PasswordVar, passPh)
			res.Vaulted++
			if len(credHosts) > 0 {
				res.Scoped++
			}
		}
	}

	for _, s := range secrets {
		bucket, reason, scheme := classifyCredential(s.key, s.value)
		switch bucket {
		case bucketUnrecognized:
			res.Unrecognized = append(res.Unrecognized, s)
			continue
		case bucketNotManaged:
			res.NotManaged = append(res.NotManaged, skippedEntry{
				key:    s.key,
				value:  s.value,
				reason: placeholder.AuthSchemeReason(scheme),
			})
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
		res.CredReasons = append(res.CredReasons, reason)
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
		switch c.Scheme {
		case "aws":
			// AWS creds rewrite up to three vars. Name (= AccessKeyIDVar)
			// is the only var name on the credential; for the other two
			// (secret access key, optional session token), value-match the
			// remaining KV lines since their original var names aren't stored.
			envFile.SetValue(c.Name, c.AWSAccessKeyIDPlaceholder)
			replaceValueIfMatches(envFile, c.Real, c.Placeholder)
			if c.AWSSessionToken != "" {
				replaceValueIfMatches(envFile, c.AWSSessionToken, c.AWSSessionTokenPlaceholder)
			}
		default:
			// For basic credentials, also rewrite the username var using a
			// value-match since the original username var name isn't stored
			// separately (only Username and UsernamePlaceholder are).
			if c.UsernamePlaceholder != "" && c.Username != "" {
				replaceValueIfMatches(envFile, c.Username, c.UsernamePlaceholder)
			}
			envFile.SetValue(c.Name, c.Placeholder)
		}
	}
	return envFile.Bytes()
}

// replaceValueIfMatches scans envFile and, for the first KV line whose
// decoded value equals oldVal, swaps it to newVal.
func replaceValueIfMatches(envFile *scanner.EnvFile, oldVal, newVal string) {
	for _, line := range envFile.Lines {
		if line.Kind == scanner.KVLine && line.Value == oldVal {
			envFile.SetValue(line.Key, newVal)
			return
		}
	}
}

// printDryRunVaultLines emits the same "would vault" lines the legacy code
// path produced, derived from the prepared credentials. Group lines list
// each member var. Both groups and creds[] share appearance order.
// AWS groups are skipped here because they are no longer vault-eligible
// and appear instead in the "Not managed" section via printVaultSummary.
func printDryRunVaultLines(w io.Writer, groups []correlate.Group, secrets []secretLine, creds []*vault.Credential) {
	ci := 0
	for _, g := range groups {
		if g.Scheme == "aws" {
			continue // AWS is not vault-eligible; shown in Not-managed summary
		}
		if ci >= len(creds) {
			break
		}
		c := creds[ci]
		ci++
		switch g.Scheme {
		case "basic":
			ui.Dimf(w, "  would vault (basic): %s", g.Name)
			ui.Dimf(w, "    %-24s -> %s", g.Basic.UsernameVar, c.UsernamePlaceholder)
			ui.Dimf(w, "    %-24s -> %s", g.Basic.PasswordVar, c.Placeholder)
		}
	}
	for _, s := range secrets {
		if ci >= len(creds) {
			break
		}
		c := creds[ci]
		ci++
		ui.Dimf(w, "  would vault: %s -> %s", s.key, c.Placeholder)
	}
}

// credBucket is the disposition classifyCredential returns: which of the
// three summary sections (Unrecognized / Not managed / Managed) a
// (name, value) pair lands in.
type credBucket int

const (
	bucketUnrecognized credBucket = iota
	bucketNotManaged
	bucketEligible
)

// classifyCredential mirrors the provider / URL / not-managed gate order
// used by both buildEnvFileCredentials and processMCPConfig so the two
// paths bucket a (name, value) pair identically AND produce the same
// (provider:X) annotation on the Managed-by-Veil line. Without this
// helper the two paths drifted: env emitted annotations, MCP did not.
//
// Returns the bucket plus, for bucketEligible, the Reason that should
// annotate the Managed line; for bucketNotManaged, the AuthScheme the
// caller renders via placeholder.AuthSchemeReason. The Reason / scheme
// values are zero for buckets that don't use them.
func classifyCredential(name, value string) (credBucket, placeholder.Reason, placeholder.AuthScheme) {
	p := placeholder.DefaultRegistry().Match(name, value)
	if p == nil {
		// A nil match means no named provider claimed this secret.
		// URL-with-password values (postgres://, mysql://, etc.) are
		// vault-eligible via the URL rewrite path even without a named
		// provider. Pure charclass fallbacks are unrecognized.
		if placeholder.IsURLWithPassword(value) {
			return bucketEligible, placeholder.Reason{Kind: placeholder.ReasonURLUserinfo}, 0
		}
		return bucketUnrecognized, placeholder.Reason{}, 0
	}
	if !placeholder.VaultEligible(p) {
		return bucketNotManaged, placeholder.Reason{}, p.AuthScheme
	}
	return bucketEligible, placeholder.Reason{Kind: placeholder.ReasonProvider, Detail: p.Name}, 0
}

// printVaultSummary emits the three-section summary: Managed, Not managed,
// and Unrecognized. Called on every run (not just --dry-run) after
// buildEnvFileCredentials returns. When dryRun is true the Managed section is
// suppressed — printDryRunVaultLines already shows those keys as "would vault"
// lines, so printing them here too would double-print each credential.
func printVaultSummary(w io.Writer, res vaultBuildResult, dryRun bool) {
	if !dryRun && len(res.Creds) > 0 {
		_, _ = fmt.Fprintf(w, "\nManaged by Veil (%d):\n", len(res.Creds))
		for i, c := range res.Creds {
			ann := ""
			if i < len(res.CredReasons) {
				ann = res.CredReasons[i].Annotation()
			}
			if ann == "" {
				_, _ = fmt.Fprintf(w, "    %s    %s\n", c.Name, c.Placeholder)
			} else {
				_, _ = fmt.Fprintf(w, "    %s    %s  %s\n", c.Name, c.Placeholder, ann)
			}
		}
	}
	if len(res.NotManaged) > 0 {
		_, _ = fmt.Fprintf(w, "\nNot managed — Veil v0.1.x doesn't mediate these yet (%d):\n", len(res.NotManaged))
		for _, s := range res.NotManaged {
			_, _ = fmt.Fprintf(w, "    %-30s %s\n", s.key, s.reason)
		}
	}
	if len(res.Unrecognized) > 0 {
		_, _ = fmt.Fprintf(w, "\nUnrecognized — left as-is (%d):\n", len(res.Unrecognized))
		for _, s := range res.Unrecognized {
			_, _ = fmt.Fprintf(w, "    %-30s %s\n", s.key, "no known format")
		}
	}
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
		if c.UsernamePlaceholder != "" && bytes.Contains(data, []byte(c.UsernamePlaceholder)) {
			return false, nil
		}
		if c.AWSAccessKeyIDPlaceholder != "" && bytes.Contains(data, []byte(c.AWSAccessKeyIDPlaceholder)) {
			return false, nil
		}
		if c.AWSSessionTokenPlaceholder != "" && bytes.Contains(data, []byte(c.AWSSessionTokenPlaceholder)) {
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
	linesByKey := make(map[string]string)
	for _, line := range envFile.Lines {
		if line.Kind != scanner.KVLine {
			continue
		}
		linesByKey[line.Key] = line.Value
		if c, ok := v.Get(line.Key); ok {
			owned = append(owned, c)
			ownedValues[line.Key] = line.Value
		}
	}
	if len(owned) == 0 {
		return false, nil
	}
	// Capture the cleartext value of the username half for any basic cred
	// we own. The vault entry is keyed by the password var (c.Name), so
	// v.Get(usernameVar) above won't surface it — without this second pass
	// the divergence check below would miss a user edit to the username
	// line and silently overwrite it.
	for _, c := range owned {
		if c.UsernameVar == "" {
			continue
		}
		if val, ok := linesByKey[c.UsernameVar]; ok {
			ownedValues[c.UsernameVar] = val
		}
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
		if c.Scheme == "aws" {
			// AWS credentials store the access key id on Name (compared
			// here) and the secret separately. The stored Real holds the
			// secret value, not the access key id, so direct Name->Real
			// comparison would always diverge. Skip the divergence check
			// for aws-scheme entries — they take the existing recovery
			// path unchanged.
			continue
		}
		if val != c.Real {
			diverged = append(diverged, c.Name)
		}
		// For basic creds, also check the username half (kept in
		// c.Username, not c.Real). UsernameVar is empty for bearer creds
		// and for manually-added basic creds (`veil add --user ...`),
		// which is correct — only init-detected pairs carry the source
		// var name needed to detect an edit.
		if c.UsernameVar != "" {
			if userVal, userOK := ownedValues[c.UsernameVar]; userOK && userVal != c.Username {
				diverged = append(diverged, c.UsernameVar)
			}
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

// cleanupStaleVaultedCreds removes any credential in v whose name matches a
// secret-like key in the just-reclaimed .env at envPath. Called from the
// orphan-recovery path after reclaimOrphanedBackup restores the cleartext
// .env: those credentials were committed to the vault by a crashed run
// before registerVaultedFile fired, so they're now orphaned and would
// trigger ErrDuplicateCredential on the imminent AddBatch. "Not found"
// (the credential isn't actually present) is non-fatal; only true persist
// errors surface.
func cleanupStaleVaultedCreds(cmd *cobra.Command, v *vault.Vault, envPath string) error {
	envFile, err := scanner.ParseFile(envPath)
	if err != nil {
		return wrapErr(fmt.Sprintf("parsing %s", envPath), err)
	}
	w := cmd.ErrOrStderr()
	for _, line := range envFile.Lines {
		if line.Kind != scanner.KVLine {
			continue
		}
		if !placeholder.IsSecretLike(line.Key, line.Value) {
			continue
		}
		removed, derr := v.Delete(line.Key)
		if derr != nil {
			return wrapErr(fmt.Sprintf("removing stale credential %s", line.Key), derr)
		}
		if removed {
			ui.Dimf(w, "  removed stale vault entry %s from crashed run", line.Key)
		}
	}
	return nil
}

// selectEnvKeys returns the groups and bearer secrets the user chose to
// vault. In non-interactive mode everything is selected. Callers that
// receive two empty slices should skip the file.
func selectEnvKeys(
	in io.Reader, w io.Writer, root, envPath string,
	groups []correlate.Group, secrets []secretLine, interactive bool,
) (selectedGroups []correlate.Group, selectedSecrets []secretLine) {
	if !interactive {
		return groups, secrets
	}

	rel := displayRel(root, envPath)

	total := len(secrets)
	for _, g := range groups {
		total += len(g.Members)
	}
	header := fmt.Sprintf("\nDetected %d %s in %s", total, plural(total, "secret", "secrets"), rel)
	awsCount, basicCount := 0, 0
	for _, g := range groups {
		switch g.Scheme {
		case "aws":
			awsCount++
		case "basic":
			basicCount++
		}
	}
	switch {
	case awsCount == 0 && basicCount == 0:
		header += ":"
	case awsCount > 0 && basicCount == 0:
		if awsCount == 1 {
			header += fmt.Sprintf(" (%d correlated as AWS):", len(groups[0].Members))
		} else {
			header += fmt.Sprintf(" (%d AWS credentials):", awsCount)
		}
	case awsCount == 0 && basicCount > 0:
		if basicCount == 1 {
			header += " (1 correlated as HTTP Basic):"
		} else {
			header += fmt.Sprintf(" (%d HTTP Basic credentials):", basicCount)
		}
	default:
		header += fmt.Sprintf(" (%d AWS, %d HTTP Basic):", awsCount, basicCount)
	}
	_, _ = fmt.Fprintln(w, header)

	var names []string
	for _, g := range groups {
		var tag string
		switch g.Scheme {
		case "aws":
			tag = "[aws]"
		case "basic":
			tag = "[basic]"
		}
		label := fmt.Sprintf("%s %s", tag, g.Name)
		for i, m := range g.Members {
			if i == 0 {
				_, _ = fmt.Fprintf(w, "  %-7s %-24s %s\n", tag, m.Key, ui.Muted.Sprint(redactValue(m.Value)))
			} else {
				_, _ = fmt.Fprintf(w, "  %-7s %-24s %s\n", "", m.Key, ui.Muted.Sprint(redactValue(m.Value)))
			}
		}
		names = append(names, label)
	}
	for _, s := range secrets {
		_, _ = fmt.Fprintf(w, "  %-7s %-24s %s\n", "", s.key, ui.Muted.Sprint(redactValue(s.value)))
		names = append(names, s.key)
	}
	_, _ = fmt.Fprintln(w)

	switch promptYNS(in, w, "Vault all?") {
	case choiceYes:
		return groups, secrets
	case choiceNo:
		return nil, nil
	case choiceSelect:
		picked := make(map[string]bool)
		for _, n := range promptMultiSelect(in, w, names) {
			picked[n] = true
		}
		for _, g := range groups {
			var tag string
			switch g.Scheme {
			case "aws":
				tag = "[aws]"
			case "basic":
				tag = "[basic]"
			}
			if picked[fmt.Sprintf("%s %s", tag, g.Name)] {
				selectedGroups = append(selectedGroups, g)
			}
		}
		for _, s := range secrets {
			if picked[s.key] {
				selectedSecrets = append(selectedSecrets, s)
			}
		}
		return selectedGroups, selectedSecrets
	}
	return nil, nil
}

// filterSecretsByRemaining keeps secretLine entries whose key is still in
// the remaining (un-correlated) candidate set, preserving the original
// file-order of secrets so dry-run and prompt output stay stable.
func filterSecretsByRemaining(secrets []secretLine, remaining []correlate.Candidate) []secretLine {
	keep := make(map[string]struct{}, len(remaining))
	for _, c := range remaining {
		keep[c.Key] = struct{}{}
	}
	out := secrets[:0:0]
	for _, s := range secrets {
		if _, ok := keep[s.key]; ok {
			out = append(out, s)
		}
	}
	return out
}

// promptSkipHostsPhase asks the user to seed the skip-host list after vaulting.
// No-op in non-interactive or dry-run mode.
func promptSkipHostsPhase(in io.Reader, w io.Writer, root string, interactive, dryRun bool) {
	if !interactive || dryRun {
		return
	}
	_, _ = fmt.Fprintln(w, "Skip hosts — any hosts the proxy should pass through untouched?")
	ui.Dim(w, "Common examples: api.anthropic.com, *.internal.company.com")
	ui.Dim(w, "(You can manage these later with: veil skip)")
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
func setupProxyCA(w io.Writer) error {
	if _, err := proxy.LoadOrCreateCA(); err != nil {
		return wrapErr("setting up CA", err)
	}
	ui.Step(w, "CA certificate ready")
	_, _ = fmt.Fprintln(w)
	return nil
}
