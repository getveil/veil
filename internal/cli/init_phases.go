package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/8enji/veil/internal/cli/correlate"
	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/proxy"
	"github.com/8enji/veil/internal/scanner"
	"github.com/8enji/veil/internal/skiphost"
	"github.com/8enji/veil/internal/ui"
	"github.com/8enji/veil/internal/vault"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// detectInteractive reports whether the init flow should prompt the user.
// Returns false if --yes was passed or if stdin is not a TTY (in which case
// a notice is printed to w).
func detectInteractive(w io.Writer, stdin io.Reader, yes bool) bool {
	if yes {
		return false
	}
	f, ok := stdin.(*os.File)
	if !ok {
		return true
	}
	if isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()) {
		return true
	}
	ui.Dim(w, "Non-interactive mode: vaulting all detected secrets")
	return false
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

// filterEnvPaths asks the user to narrow the set of .env files to scan when
// there is more than one. In non-interactive mode or with a single file the
// input is returned unchanged.
func filterEnvPaths(in io.Reader, w io.Writer, root string, envPaths []string, interactive bool) []string {
	if !interactive || len(envPaths) <= 1 {
		return envPaths
	}
	_, _ = fmt.Fprintf(w, "\nFound %d .env files:\n", len(envPaths))
	names := make([]string, len(envPaths))
	for i, p := range envPaths {
		rel, _ := filepath.Rel(root, p)
		if rel == "" {
			rel = filepath.Base(p)
		}
		names[i] = rel
		_, _ = fmt.Fprintf(w, "  %s\n", rel)
	}
	_, _ = fmt.Fprintln(w)
	switch promptYNS(in, w, "Scan all?") {
	case choiceNo:
		return nil
	case choiceSelect:
		selected := promptMultiSelect(in, w, names)
		selectedSet := make(map[string]bool, len(selected))
		for _, s := range selected {
			selectedSet[s] = true
		}
		var filtered []string
		for i, p := range envPaths {
			if selectedSet[names[i]] {
				filtered = append(filtered, p)
			}
		}
		return filtered
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
func processEnvFile(cmd *cobra.Command, in io.Reader, v *vault.Vault, seen placeholder.Set, root, envPath string, force, dryRun, interactive bool) (int, int, error) {
	if backupExists(envPath) && !force {
		// An orphaned backup (one not in the current vault's registry) means
		// this file was vaulted by a prior Veil instance whose state was wiped
		// — the backup IS the source of truth, so use it instead of the
		// current (placeholder-filled) .env. Without this, F-12 would silently
		// capture fewer secrets than the previous init.
		orphan, oerr := isOrphanedBackup(root, envPath)
		if oerr != nil {
			return 0, 0, wrapErr(fmt.Sprintf("checking backup status of %s", envPath), oerr)
		}
		if orphan {
			if err := reclaimOrphanedBackup(envPath); err != nil {
				return 0, 0, wrapErr(fmt.Sprintf("reclaiming orphan backup %s", envPath), err)
			}
			ui.Warnf(cmd.ErrOrStderr(), "%s had an orphaned backup from a prior Veil install — restoring it as the source of truth before re-vaulting", envPath)
		} else {
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

	// Correlate multi-value schemes (e.g., AWS triples) before prompting so
	// the user sees grouped rows and members cannot be split individually.
	cands := make([]correlate.Candidate, len(secrets))
	for i, s := range secrets {
		cands[i] = correlate.Candidate{Key: s.key, Value: s.value}
	}
	groups, remaining := correlate.DetectAll(cands)
	remainingSecrets := filterSecretsByRemaining(secrets, remaining)

	selectedGroups, selectedSecrets := selectEnvKeys(in, w, root, envPath, groups, remainingSecrets, interactive)
	if len(selectedGroups) == 0 && len(selectedSecrets) == 0 {
		return 0, 0, nil
	}

	var vaulted, scoped int
	fileChanged := false

	for _, g := range selectedGroups {
		n, s, changed, err := vaultAWSGroup(cmd, v, seen, envFile, g, dryRun)
		if err != nil {
			return vaulted, scoped, err
		}
		vaulted += n
		scoped += s
		if changed {
			fileChanged = true
		}
	}

	for _, s := range selectedSecrets {
		ph, err := placeholder.Generate(s.key, s.value, seen)
		if err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("generating placeholder for %s", s.key), err)
		}

		credHosts := placeholder.HostsForCredential(s.key, s.value)

		cred := &vault.Credential{
			ID:           vault.NewID(),
			Name:         s.key,
			Real:         s.value,
			Placeholder:  ph,
			Source:       "init",
			AllowedHosts: credHosts,
			CreatedAt:    time.Now(),
		}
		if err := v.Add(cred); err != nil {
			if errors.Is(err, vault.ErrDuplicateCredential) {
				ui.Warnf(cmd.ErrOrStderr(), "duplicate key %q, skipping", s.key)
				continue
			}
			return vaulted, scoped, wrapErr(fmt.Sprintf("vaulting %s", s.key), err)
		}
		seen[ph] = struct{}{}

		vaulted++
		if len(credHosts) > 0 {
			scoped++
		}

		if dryRun {
			ui.Dimf(w, "  would vault: %s -> %s", s.key, ph)
		} else {
			envFile.SetValue(s.key, ph)
			fileChanged = true
		}
	}

	if !dryRun && fileChanged {
		if err := recordVaultedBackup(root, envPath, vault.KindEnv); err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("writing backup for %s", envPath), err)
		}
		if err := atomicWriteFile(envPath, envFile.Bytes()); err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("writing %s", envPath), err)
		}
	}
	return vaulted, scoped, nil
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

	rel, _ := filepath.Rel(root, envPath)
	if rel == "" {
		rel = filepath.Base(envPath)
	}

	total := len(secrets)
	for _, g := range groups {
		total += len(g.Members)
	}
	header := fmt.Sprintf("\nDetected %d %s in %s", total, plural(total, "secret", "secrets"), rel)
	switch len(groups) {
	case 0:
		header += ":"
	case 1:
		header += fmt.Sprintf(" (%d correlated as AWS):", len(groups[0].Members))
	default:
		header += fmt.Sprintf(" (%d AWS credentials):", len(groups))
	}
	_, _ = fmt.Fprintln(w, header)

	var names []string
	for _, g := range groups {
		label := fmt.Sprintf("[aws] %s", g.Name)
		for i, m := range g.Members {
			key := m.Key
			if i == 0 {
				_, _ = fmt.Fprintf(w, "  %-7s %-24s %s\n", "[aws]", key, ui.Muted.Sprint(redactValue(m.Value)))
			} else {
				_, _ = fmt.Fprintf(w, "  %-7s %-24s %s\n", "", key, ui.Muted.Sprint(redactValue(m.Value)))
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
			if picked[fmt.Sprintf("[aws] %s", g.Name)] {
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

// vaultAWSGroup writes one Scheme:"aws" credential for g, rewrites the
// three (or two) source env-var placeholders in envFile, and reports
// (vaulted, scoped, fileChanged). An AWS group counts as one credential
// regardless of member count, matching what the user sees in `veil list`.
func vaultAWSGroup(
	cmd *cobra.Command, v *vault.Vault, seen placeholder.Set,
	envFile *scanner.EnvFile, g correlate.Group, dryRun bool,
) (vaulted, scoped int, fileChanged bool, err error) {
	w := cmd.OutOrStdout()

	secretPh, err := placeholder.Generate(g.Name, g.AWS.SecretKey, seen)
	if err != nil {
		return 0, 0, false, wrapErr(fmt.Sprintf("generating placeholder for %s", g.AWS.SecretKeyVar), err)
	}
	seen[secretPh] = struct{}{}

	akIDPh := generateAWSAccessKeyIDPlaceholder(g.AWS.AccessKeyID, seen)
	seen[akIDPh] = struct{}{}

	var sessPh string
	if g.AWS.SessionToken != "" {
		sessPh, err = placeholder.GenerateAWSSessionToken(g.AWS.SessionToken, seen)
		if err != nil {
			return 0, 0, false, wrapErr(fmt.Sprintf("generating placeholder for %s", g.AWS.SessionTokenVar), err)
		}
		seen[sessPh] = struct{}{}
	}

	cred := &vault.Credential{
		ID:                         vault.NewID(),
		Name:                       g.Name,
		Real:                       g.AWS.SecretKey,
		Placeholder:                secretPh,
		Source:                     "init",
		AllowedHosts:               []string{"*.amazonaws.com"},
		CreatedAt:                  time.Now(),
		Scheme:                     "aws",
		AWSAccessKeyID:             g.AWS.AccessKeyID,
		AWSAccessKeyIDPlaceholder:  akIDPh,
		AWSSessionToken:            g.AWS.SessionToken,
		AWSSessionTokenPlaceholder: sessPh,
	}
	if err := v.Add(cred); err != nil {
		if errors.Is(err, vault.ErrDuplicateCredential) {
			ui.Warnf(cmd.ErrOrStderr(), "duplicate key %q, skipping", g.Name)
			return 0, 0, false, nil
		}
		return 0, 0, false, wrapErr(fmt.Sprintf("vaulting %s", g.Name), err)
	}

	if dryRun {
		ui.Dimf(w, "  would vault (aws): %s", g.Name)
		ui.Dimf(w, "    %-24s -> %s", g.AWS.AccessKeyIDVar, akIDPh)
		ui.Dimf(w, "    %-24s -> %s", g.AWS.SecretKeyVar, secretPh)
		if g.AWS.SessionToken != "" {
			ui.Dimf(w, "    %-24s -> %s", g.AWS.SessionTokenVar, sessPh)
		}
	} else {
		envFile.SetValue(g.AWS.AccessKeyIDVar, akIDPh)
		envFile.SetValue(g.AWS.SecretKeyVar, secretPh)
		if g.AWS.SessionTokenVar != "" {
			envFile.SetValue(g.AWS.SessionTokenVar, sessPh)
		}
		fileChanged = true
	}

	return 1, 1, fileChanged, nil
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
