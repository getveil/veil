package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/mcpconfig"
	"github.com/getveil/veil/internal/placeholder"
	"github.com/getveil/veil/internal/scanner"
	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
	"github.com/spf13/cobra"
)

// lineReader wraps an io.Reader so that each Read call returns at most one
// line (up to and including the next '\n'). This prevents bufio.Scanner
// instances in the prompt helpers from consuming more than one line of input
// via read-ahead buffering, enabling multiple sequential prompts against the
// same underlying reader.
type lineReader struct {
	br       *bufio.Reader
	overflow []byte
}

func newLineReader(r io.Reader) *lineReader {
	if br, ok := r.(*bufio.Reader); ok {
		return &lineReader{br: br}
	}
	return &lineReader{br: bufio.NewReader(r)}
}

func (l *lineReader) Read(p []byte) (int, error) {
	// Drain any leftover bytes from a previous oversized line first.
	if len(l.overflow) > 0 {
		n := copy(p, l.overflow)
		l.overflow = l.overflow[n:]
		if len(l.overflow) == 0 {
			l.overflow = nil
		}
		return n, nil
	}
	line, err := l.br.ReadString('\n')
	if len(line) > 0 {
		n := copy(p, line)
		if n < len(line) {
			// Stash the bytes that didn't fit; return what did.
			l.overflow = []byte(line[n:])
		}
		return n, nil
	}
	return 0, err
}

func initCmd() *cobra.Command {
	var force, dryRun, yes bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Veil for the current project",
		Long:  "Scan .env files, vault secrets, and replace them with placeholders.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(cmd, force, dryRun, yes)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "reinitialize even if .veil/ exists")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be vaulted without making changes")
	cmd.Flags().BoolVar(&yes, "yes", false, "accept all defaults non-interactively")
	return cmd
}

func runInit(cmd *cobra.Command, force, dryRun, yes bool) error {
	w := cmd.OutOrStdout()
	stdin := cmd.InOrStdin()
	interactive, announce := detectInteractive(stdin, yes)
	// Wrap stdin so each prompt reads exactly one line, avoiding read-ahead
	// that would consume input intended for later prompts.
	in := newLineReader(stdin)

	root, err := resolveInitRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}
	if announce {
		ui.Dim(w, "Non-interactive mode: vaulting all detected secrets")
	}

	stateDir := config.ProjectStateDir(root)
	proceed, err := detectExistingProject(in, w, stateDir, force, interactive)
	if err != nil {
		return err
	}
	if !proceed {
		return nil
	}

	ui.Phase(w, "Scanning project...")

	envPaths, err := scanner.Scan(root)
	if err != nil {
		return wrapErr("scanning .env files", err)
	}
	mcpConfigPath, err := mcpconfig.Discover()
	if err != nil {
		return wrapErr("discovering MCP config", err)
	}
	// Precompute shell-env candidates so the early-exit gate considers all three
	// sources (SEC-1 covers shell-only projects that have no .env or MCP config).
	// Empty-valued candidates (name-match only, no actual secret to capture) are
	// discarded here because processShellEnv would drop them anyway, and they
	// would otherwise wrongly bypass the early-exit gate for projects with no
	// real sources.
	shellCandidates := scanner.ScanEnviron(os.Environ())
	shellCandidates = nonEmptyShellCandidates(shellCandidates)
	if len(envPaths) == 0 && mcpConfigPath == "" && len(shellCandidates) == 0 {
		_, _ = fmt.Fprintf(w, "no .env files, MCP configs, or shell-exported secrets found in %s\n", root)
		return nil
	}

	envPaths = filterEnvPaths(in, w, root, envPaths, interactive)

	if len(envPaths) > 0 {
		ui.Step(w, fmt.Sprintf("Found %d .env %s", len(envPaths), plural(len(envPaths), "file", "files")))
	}
	if mcpConfigPath != "" {
		ui.Step(w, "Found 1 MCP config")
	}
	_, _ = fmt.Fprintln(w)

	ks, err := buildKeystore()
	if err != nil {
		return wrapErr("keystore", err)
	}

	var v *vault.Vault
	if dryRun {
		// Dry-run must not touch .veil/ or the keystore; build a transient
		// in-memory vault so placeholder generation and duplicate checks
		// still work but no state is persisted.
		v = vault.NewInMemoryVault(root, vault.NewID())
	} else {
		// On --force, the existing project's master key would otherwise be
		// orphaned in the keystore (each CreateVault generates a new
		// projectID). Best-effort delete the prior entry first.
		if force {
			if priorID, err := vault.ReadProjectID(root); err == nil {
				_ = ks.Delete(priorID)
			}
		}
		v, err = vault.CreateVault(root, vault.NewID(), ks)
		if err != nil {
			return wrapErr("creating vault", err)
		}
	}

	ui.Phase(w, "Vaulting secrets...")

	secretsVaulted, secretsScoped := 0, 0
	seen := make(placeholder.Set)
	for _, envPath := range envPaths {
		n, s, err := processEnvFile(cmd, in, v, seen, root, envPath, force, dryRun, interactive)
		if err != nil {
			return err
		}
		secretsVaulted += n
		secretsScoped += s
	}

	mcpConfigsProcessed := 0
	if mcpConfigPath != "" {
		n, s, err := processMCPConfig(cmd, in, v, root, mcpConfigPath, force, dryRun, interactive)
		if err != nil {
			return err
		}
		secretsVaulted += n
		secretsScoped += s
		if n > 0 {
			mcpConfigsProcessed = 1
		}
	}

	// Scan shell environment for secret-like exports that never made it into
	// a .env file. Closes SEC-1 residual gap: shell-exported secrets would
	// otherwise never enter the vault and would pass through to the agent.
	// processShellEnv re-filters candidates against the vault (to skip names
	// already captured by an earlier phase) and drops empty values, so the
	// raw candidate count from ScanEnviron is only used as a fast-path check
	// for "was there anything at all to look at." Candidates were precomputed
	// above so the early-exit gate could see them.
	if len(shellCandidates) > 0 {
		ui.Phase(w, "Scanning shell environment...")
		n, s, err := processShellEnv(w, in, v, shellCandidates, dryRun, interactive)
		if err != nil {
			return err
		}
		secretsVaulted += n
		secretsScoped += s
		_, _ = fmt.Fprintln(w)
	}

	unscoped := secretsVaulted - secretsScoped
	if dryRun {
		ui.Step(w, fmt.Sprintf("would store %d %s in keychain", secretsVaulted, plural(secretsVaulted, "secret", "secrets")))
		if secretsScoped > 0 {
			ui.Step(w, fmt.Sprintf("%d would be auto-scoped to hosts", secretsScoped))
		}
		if unscoped > 0 {
			ui.Warn(w, fmt.Sprintf("%d would be unscoped (use veil add --host to scope)", unscoped))
		}
	} else {
		ui.Step(w, fmt.Sprintf("%d %s stored in keychain", secretsVaulted, plural(secretsVaulted, "secret", "secrets")))
		if secretsScoped > 0 {
			ui.Step(w, fmt.Sprintf("%d auto-scoped to hosts", secretsScoped))
		}
		if unscoped > 0 {
			ui.Warn(w, fmt.Sprintf("%d unscoped (use veil add --host to scope)", unscoped))
		}
	}
	_, _ = fmt.Fprintln(w)

	promptSkipHostsPhase(in, w, root, interactive, dryRun)

	ui.Phase(w, "Setting up proxy...")
	if err := setupProxyCA(w); err != nil {
		return err
	}

	if !dryRun {
		appendGitignore(root)
	}

	if dryRun {
		_, _ = fmt.Fprintf(w, "%s\n", ui.Success.Sprintf("Dry-run preview for %s — no changes made", root))
		_, _ = fmt.Fprintf(w, "  .env files that would be processed:  %d\n", len(envPaths))
		if mcpConfigsProcessed > 0 {
			_, _ = fmt.Fprintf(w, "  MCP configs that would be processed: %d\n", mcpConfigsProcessed)
		}
		_, _ = fmt.Fprintf(w, "  Secrets that would be vaulted:       %d\n", secretsVaulted)
		_, _ = fmt.Fprintln(w)
		ui.Dim(w, "Re-run without --dry-run to apply these changes.")
		_, _ = fmt.Fprintln(w)
	} else {
		_, _ = fmt.Fprintf(w, "%s\n", ui.Success.Sprintf("Veil initialized for %s", root))
		_, _ = fmt.Fprintf(w, "  .env files processed:  %d\n", len(envPaths))
		if mcpConfigsProcessed > 0 {
			_, _ = fmt.Fprintf(w, "  MCP configs processed: %d\n", mcpConfigsProcessed)
		}
		_, _ = fmt.Fprintf(w, "  Secrets vaulted:       %d\n", secretsVaulted)
		_, _ = fmt.Fprintln(w)
	}
	return nil
}

// redactValue returns a redacted display of a secret value. For values shorter
// than 12 characters the full value is masked (****) to avoid leaking most of
// a short secret. For longer values the first 4 characters are shown followed
// by **** to aid visual identification without materially reducing security.
func redactValue(value string) string {
	if len(value) < 12 {
		return "****"
	}
	return value[:4] + "****"
}

// plural returns singular if n == 1, otherwise plural.
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}

// processMCPConfig extracts secrets from an MCP config file, vaults them, and
// rewrites the config with placeholders. Returns the number of secrets vaulted
// and the number auto-scoped to hosts.
func processMCPConfig(cmd *cobra.Command, in io.Reader, v *vault.Vault, root, configPath string, force, dryRun, interactive bool) (int, int, error) {
	// Check for existing backup. An orphaned backup (one not in the current
	// vault's registry) means this file was vaulted by a prior Veil instance
	// whose state is gone — the backup IS the source of truth, so use it
	// instead of the current (placeholder-filled) config. Without this, F-12
	// would silently capture fewer secrets than the previous init.
	if backupExists(configPath) && !force {
		orphan, oerr := isOrphanedBackup(root, configPath)
		if oerr != nil {
			return 0, 0, wrapErr(fmt.Sprintf("checking backup status of %s", configPath), oerr)
		}
		if orphan {
			if err := reclaimOrphanedBackup(configPath); err != nil {
				return 0, 0, wrapErr(fmt.Sprintf("reclaiming orphan backup %s", configPath), err)
			}
			ui.Warnf(cmd.ErrOrStderr(), "%s had an orphaned backup from a prior Veil install — restoring it as the source of truth before re-vaulting", configPath)
		} else {
			ui.Warnf(cmd.ErrOrStderr(), "%s already has a backup (use --force to re-migrate)", configPath)
			return 0, 0, nil
		}
	}

	mcpCfg, err := mcpconfig.Parse(configPath)
	if err != nil {
		return 0, 0, cliError(fmt.Sprintf("parsing MCP config: %v", err), "")
	}

	w := cmd.OutOrStdout()

	// Collect secret-like entries per server.
	type mcpSecret struct {
		server string
		key    string
		value  string
	}
	var allSecrets []mcpSecret
	for serverName, server := range mcpCfg.Servers() {
		for key, value := range server.Env {
			if !placeholder.IsSecretLike(key, value) {
				if flagVerbose {
					_, _ = fmt.Fprintf(w, "%s\n", ui.Muted.Sprintf("  skip (not secret-like): mcp:%s:%s", serverName, key))
				}
				continue
			}
			allSecrets = append(allSecrets, mcpSecret{server: serverName, key: key, value: value})
		}
	}

	if len(allSecrets) == 0 {
		_, _ = fmt.Fprintf(w, "\n%s\n", ui.Muted.Sprint("No secrets found in MCP config."))
		return 0, 0, nil
	}

	// Interactive MCP selection.
	// keyOf uses a NUL byte separator to avoid collisions with colons that
	// may legitimately appear in server names derived from JSON keys.
	selectedKeys := make(map[string]bool) // key = "server\x00key"
	keyOf := func(s mcpSecret) string { return s.server + "\x00" + s.key }
	if interactive {
		_, _ = fmt.Fprintf(w, "\nDetected %d MCP %s:\n", len(allSecrets), plural(len(allSecrets), "secret", "secrets"))
		names := make([]string, len(allSecrets))
		for i, s := range allSecrets {
			redacted := redactValue(s.value)
			label := fmt.Sprintf("mcp:%s:%s", s.server, s.key)
			_, _ = fmt.Fprintf(w, "  %-32s %s\n", label, ui.Muted.Sprint(redacted))
			names[i] = label
		}
		_, _ = fmt.Fprintln(w)
		choice := promptYNS(in, w, "Vault all MCP secrets?")
		switch choice {
		case choiceYes:
			for _, s := range allSecrets {
				selectedKeys[keyOf(s)] = true
			}
		case choiceNo:
			return 0, 0, nil
		case choiceSelect:
			selected := promptMultiSelect(in, w, names)
			selectedSet := make(map[string]bool)
			for _, name := range selected {
				selectedSet[name] = true
			}
			for _, s := range allSecrets {
				label := fmt.Sprintf("mcp:%s:%s", s.server, s.key)
				if selectedSet[label] {
					selectedKeys[keyOf(s)] = true
				}
			}
		}
	} else {
		for _, s := range allSecrets {
			selectedKeys[keyOf(s)] = true
		}
	}

	var count int
	var scoped int
	configChanged := false
	seen := make(placeholder.Set)

	for _, s := range allSecrets {
		if !selectedKeys[keyOf(s)] {
			continue
		}
		serverName, key, value := s.server, s.key, s.value

		ph, err := placeholder.Generate(key, value, seen)
		if err != nil {
			return 0, 0, cliError(fmt.Sprintf("generating placeholder for mcp:%s:%s: %v", serverName, key, err), "")
		}

		credName := fmt.Sprintf("mcp:%s:%s", serverName, key)

		credHosts := placeholder.HostsForCredential(key, value)
		cred := &vault.Credential{
			ID:           vault.NewID(),
			Name:         credName,
			Real:         value,
			Placeholder:  ph,
			Source:       "init",
			AllowedHosts: credHosts,
			CreatedAt:    time.Now(),
		}
		if err := v.Add(cred); err != nil {
			if errors.Is(err, vault.ErrDuplicateCredential) {
				ui.Warnf(cmd.ErrOrStderr(), "duplicate key %q, skipping", credName)
				continue
			}
			return 0, 0, cliError(fmt.Sprintf("vaulting %s: %v", credName, err), "")
		}
		seen[ph] = struct{}{}

		count++
		if len(credHosts) > 0 {
			scoped++
		}

		if dryRun {
			_, _ = fmt.Fprintf(w, "%s\n", ui.Muted.Sprintf("  would vault: %s -> %s", credName, ph))
		} else {
			mcpCfg.SetEnvValue(serverName, key, ph)
			configChanged = true
		}
	}

	if !dryRun && configChanged {
		if err := recordVaultedBackup(root, configPath, vault.KindMCP); err != nil {
			return 0, 0, cliErrorf("writing MCP config backup: %v", err)
		}

		// Write updated config.
		newData, err := mcpCfg.Bytes()
		if err != nil {
			return 0, 0, cliError(fmt.Sprintf("serializing MCP config: %v", err), "")
		}
		if err := atomicWriteFile(configPath, newData); err != nil {
			return 0, 0, cliError(fmt.Sprintf("writing MCP config: %v", err), "")
		}
	}

	return count, scoped, nil
}

// atomicWriteFile writes data to path via a temporary file and rename.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".veil-env-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// appendGitignore adds /.veil/ and *.veil-backup to the project .gitignore
// if not already present. No-op when .gitignore doesn't exist.
func appendGitignore(root string) {
	gitignorePath := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		// No .gitignore — nothing to do.
		return
	}

	content := string(data)
	changed := false
	for _, line := range []string{"/.veil/", "*.veil-backup"} {
		if strings.Contains(content, line) {
			continue
		}
		if len(content) > 0 && content[len(content)-1] != '\n' {
			content += "\n"
		}
		content += line + "\n"
		changed = true
	}
	if !changed {
		return
	}

	_ = os.WriteFile(gitignorePath, []byte(content), 0600) //nolint:gosec // .gitignore is not sensitive
}
