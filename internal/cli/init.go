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
	var force, dryRun, yes, scanShellEnv, scanMCP bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Veil for the current project",
		Long:  "Scan .env files, vault secrets, and replace them with placeholders.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(cmd, force, dryRun, yes, scanShellEnv, scanMCP)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "reinitialize even if .veil/ exists")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be vaulted without making changes")
	cmd.Flags().BoolVar(&yes, "yes", false, "accept all defaults non-interactively")
	cmd.Flags().BoolVar(&scanShellEnv, "scan-shell-env", false, "scan os.Environ() for secret-like shell exports")
	cmd.Flags().BoolVar(&scanMCP, "scan-mcp", false, "scan for MCP configs (user-global and project-scope)")
	return cmd
}

func runInit(cmd *cobra.Command, force, dryRun, yes, scanShellEnv, scanMCP bool) error {
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

	scanRes, err := scanner.ScanAll(root)
	if err != nil {
		return wrapErr("scanning project", err)
	}
	envPaths := scanRes.EnvPaths

	// --scan-mcp gates BOTH user-scope discovery (mcpconfig.Discover) and
	// project-scope configs returned by scanner.ScanAll. When off, no MCP
	// path emits output, prompts, or processing work — the loops below
	// iterate over an empty slice.
	var mcpConfigs []mcpconfig.DiscoveredConfig
	if scanMCP {
		userMCP, err := mcpconfig.Discover()
		if err != nil {
			return wrapErr("discovering MCP config", err)
		}
		// User-scope first (typically external paths), then project-scope (inside
		// root). Order shapes the summary print and prompt list — predictable.
		mcpConfigs = append(mcpConfigs, userMCP...)
		mcpConfigs = append(mcpConfigs, scanRes.MCPConfigs...)
	}
	// --scan-shell-env gates scanner.ScanEnviron(os.Environ()). When off,
	// the candidate list stays empty so the early-exit gate, the shell-env
	// phase header, and processShellEnv are all skipped silently.
	var shellCandidates []scanner.EnvironCandidate
	if scanShellEnv {
		shellCandidates = scanner.ScanEnviron(os.Environ())
		shellCandidates = nonEmptyShellCandidates(shellCandidates)
	}
	if len(envPaths) == 0 && len(mcpConfigs) == 0 && len(shellCandidates) == 0 {
		_, _ = fmt.Fprintf(w, "no .env files, MCP configs, or shell-exported secrets found in %s\n", root)
		return nil
	}

	envPaths, mcpConfigs = filterInputs(in, w, root, envPaths, mcpConfigs, interactive)

	if len(envPaths) > 0 {
		ui.Step(w, fmt.Sprintf("Found %d .env %s:", len(envPaths), plural(len(envPaths), "file", "files")))
		for _, p := range envPaths {
			ui.Dim(w, "  "+displayRel(root, p))
		}
	}
	if len(mcpConfigs) > 0 {
		ui.Step(w, fmt.Sprintf("Found %d MCP %s:", len(mcpConfigs), plural(len(mcpConfigs), "config", "configs")))
		for _, c := range mcpConfigs {
			ui.Dim(w, "  "+mcpDisplayLabel(root, c))
		}
	}
	_, _ = fmt.Fprintln(w)

	// Both gates run BEFORE buildKeystore / CreateVault so a refused project
	// never reaches the destructive keystore-delete / vault-recreate path
	// that --force would otherwise trigger.
	if err := refuseSymlinkedInputs(root, envPaths, mcpConfigs); err != nil {
		return err
	}
	if err := refusePlaceholderInputs(root, envPaths, mcpConfigs, force); err != nil {
		return err
	}

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
	for _, cfg := range mcpConfigs {
		n, s, err := processMCPConfig(cmd, in, v, root, cfg.Path, force, dryRun, interactive)
		if err != nil {
			return err
		}
		secretsVaulted += n
		secretsScoped += s
		if n > 0 {
			mcpConfigsProcessed++
		}
	}

	// Shell-exported secrets that never made it into a .env file would
	// otherwise pass through to the agent. processShellEnv re-filters
	// candidates against the vault (skipping names captured in an earlier
	// phase) and drops empty values.
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
		appendGitignore(w, root)
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
		_, _ = fmt.Fprintf(w, "%s\n", ui.Bold.Sprint("Next:"))
		_, _ = fmt.Fprintf(w, "  veil run claude     %s\n", ui.Muted.Sprint("# or your agent of choice"))
		_, _ = fmt.Fprintf(w, "  veil status         %s\n", ui.Muted.Sprint("# see what's protected"))
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
	// An orphaned backup (one not in the current vault's registry) means
	// this file was vaulted by a prior Veil install whose state is gone, so
	// the backup is the source of truth — reclaim it before re-vaulting.
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

	// Both env values and positional args are scanned: real MCP configs
	// commonly pass credentials via args (e.g. `["--token", "ghp_..."]` or a
	// DSN). Args carry no key name, so detection passes "" — using the
	// preceding flag as a synthetic name would falsely vault values like
	// `--token-expiry 3600` since the key-name heuristic has no length floor.
	// argIndex < 0 marks an env entry; >= 0 is the position in server.Args.
	type mcpSecret struct {
		server   string
		key      string // env key, or "args[i]" label for display/credname
		argIndex int
		value    string
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
			allSecrets = append(allSecrets, mcpSecret{server: serverName, key: key, argIndex: -1, value: value})
		}
		for i, value := range server.Args {
			if !placeholder.IsSecretLike("", value) {
				if flagVerbose {
					_, _ = fmt.Fprintf(w, "%s\n", ui.Muted.Sprintf("  skip (not secret-like): mcp:%s:args[%d]", serverName, i))
				}
				continue
			}
			allSecrets = append(allSecrets, mcpSecret{
				server:   serverName,
				key:      fmt.Sprintf("args[%d]", i),
				argIndex: i,
				value:    value,
			})
		}
	}

	if len(allSecrets) == 0 {
		_, _ = fmt.Fprintf(w, "\n%s\n", ui.Muted.Sprint("No secrets found in MCP config."))
		return 0, 0, nil
	}

	// Selection identity uses NUL separators to avoid colliding with colons
	// in server names, and includes a kind tag so an arg labeled "args[0]"
	// cannot collide with an env var of the same string.
	idOf := func(s mcpSecret) string {
		kind := "env"
		if s.argIndex >= 0 {
			kind = "arg"
		}
		return s.server + "\x00" + kind + "\x00" + s.key
	}
	selectedIDs := make(map[string]bool)
	if interactive {
		_, _ = fmt.Fprintf(w, "\nDetected %d MCP %s:\n", len(allSecrets), plural(len(allSecrets), "secret", "secrets"))
		names := make([]string, len(allSecrets))
		for i, s := range allSecrets {
			label := fmt.Sprintf("mcp:%s:%s", s.server, s.key)
			_, _ = fmt.Fprintf(w, "  %-32s %s\n", label, ui.Muted.Sprint(redactValue(s.value)))
			names[i] = label
		}
		_, _ = fmt.Fprintln(w)
		switch promptYNS(in, w, "Vault all MCP secrets?") {
		case choiceYes:
			for _, s := range allSecrets {
				selectedIDs[idOf(s)] = true
			}
		case choiceNo:
			return 0, 0, nil
		case choiceSelect:
			picked := make(map[string]bool)
			for _, n := range promptMultiSelect(in, w, names) {
				picked[n] = true
			}
			for _, s := range allSecrets {
				if picked[fmt.Sprintf("mcp:%s:%s", s.server, s.key)] {
					selectedIDs[idOf(s)] = true
				}
			}
		}
	} else {
		for _, s := range allSecrets {
			selectedIDs[idOf(s)] = true
		}
	}

	var count, scoped int
	configChanged := false
	seen := make(placeholder.Set)

	for _, s := range allSecrets {
		if !selectedIDs[idOf(s)] {
			continue
		}
		ph, err := placeholder.Generate(s.key, s.value, seen)
		if err != nil {
			return 0, 0, cliError(fmt.Sprintf("generating placeholder for mcp:%s:%s: %v", s.server, s.key, err), "")
		}

		credName := fmt.Sprintf("mcp:%s:%s", s.server, s.key)
		credHosts := placeholder.HostsForCredential(s.key, s.value)
		cred := &vault.Credential{
			ID:           vault.NewID(),
			Name:         credName,
			Real:         s.value,
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
			if s.argIndex >= 0 {
				mcpCfg.SetArg(s.server, s.argIndex, ph)
			} else {
				mcpCfg.SetEnvValue(s.server, s.key, ph)
			}
			configChanged = true
		}
	}

	if !dryRun && configChanged {
		if err := recordVaultedBackup(root, configPath, vault.KindMCP); err != nil {
			return 0, 0, cliErrorf("writing MCP config backup: %v", err)
		}

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
//
// Intentionally NOT migrated to vault.WriteFileNoFollow — this helper
// rewrites user .env files and MCP configs where Sync+Rename gives
// torn-write crash safety that WriteFileNoFollow does not. The H9 holes
// don't apply: CreateTemp uses a random suffix so the tmp path can't be
// symlink-pre-planted, POSIX rename(2) replaces a symlink at path with
// the renamed file itself rather than following it, and the new file
// inherits the tmp's 0600 mode so any pre-existing widened perms on
// path are discarded with the old inode.
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

// appendGitignore adds /.veil/ and *.veil-backup to the project .gitignore.
// When .gitignore is missing it is created with those entries, since the
// .env.veil-backup sidecars written earlier in init hold the cleartext
// secrets — without an ignore entry, `git add .` would commit them.
func appendGitignore(w io.Writer, root string) {
	gitignorePath := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			// .gitignore exists but is unreadable (permission denied, EISDIR,
			// dangling symlink, etc.). Best-effort: leave it alone.
			return
		}
		// Create a fresh .gitignore so the .veil-backup sidecars don't leak
		// via `git add .`. WriteFileNoFollow refuses a pre-planted dangling
		// symlink at this path. The contents (/.veil/, *.veil-backup) are
		// not sensitive, so use the conventional 0644 — a world-unreadable
		// .gitignore is surprising and diverges from every other repo.
		content := "/.veil/\n*.veil-backup\n"
		if werr := vault.WriteFileNoFollow(gitignorePath, []byte(content), 0o644); werr == nil {
			ui.Step(w, "created .gitignore with /.veil/ and *.veil-backup")
		}
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

	// Refuse a symlinked .gitignore so a hostile cloned repo can't redirect
	// our append into ~/.bashrc or similar. Preserve the existing file's
	// mode so we don't surprise users by narrowing a 0644 .gitignore to
	// 0600 on every append. If stat fails (race after the read above),
	// fall back to 0644 — the conventional mode for non-sensitive content.
	// Errors stay swallowed — appending .gitignore entries is best-effort.
	mode := os.FileMode(0o644)
	if info, err := os.Stat(gitignorePath); err == nil {
		mode = info.Mode().Perm()
	}
	_ = vault.WriteFileNoFollow(gitignorePath, []byte(content), mode)
}
