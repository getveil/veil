package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

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
		ui.Warnf(cmd.ErrOrStderr(), "%s already has a backup (use --force to re-vault)", envPath)
		return 0, 0, nil
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

	selectedKeys := selectEnvKeys(in, w, root, envPath, secrets, interactive)
	if len(selectedKeys) == 0 {
		return 0, 0, nil
	}

	var vaulted, scoped int
	fileChanged := false
	for _, s := range secrets {
		if !selectedKeys[s.key] {
			continue
		}

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
		if err := atomicWriteFile(envPath, envFile.Bytes()); err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("writing %s", envPath), err)
		}
	}
	return vaulted, scoped, nil
}

// selectEnvKeys returns the set of secret keys the user chose to vault. In
// non-interactive mode all keys are selected. Callers that receive an empty
// map should skip the file.
func selectEnvKeys(in io.Reader, w io.Writer, root, envPath string, secrets []secretLine, interactive bool) map[string]bool {
	selected := make(map[string]bool, len(secrets))
	if !interactive {
		for _, s := range secrets {
			selected[s.key] = true
		}
		return selected
	}

	rel, _ := filepath.Rel(root, envPath)
	if rel == "" {
		rel = filepath.Base(envPath)
	}
	_, _ = fmt.Fprintf(w, "\nDetected %d %s in %s:\n", len(secrets), plural(len(secrets), "secret", "secrets"), rel)
	names := make([]string, len(secrets))
	for i, s := range secrets {
		_, _ = fmt.Fprintf(w, "  %-24s %s\n", s.key, ui.Muted.Sprint(redactValue(s.value)))
		names[i] = s.key
	}
	_, _ = fmt.Fprintln(w)
	switch promptYNS(in, w, "Vault all?") {
	case choiceYes:
		for _, s := range secrets {
			selected[s.key] = true
		}
	case choiceNo:
		return nil
	case choiceSelect:
		for _, name := range promptMultiSelect(in, w, names) {
			selected[name] = true
		}
	}
	return selected
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
