package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/mcpconfig"
	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/proxy"
	"github.com/8enji/veil/internal/scanner"
	"github.com/8enji/veil/internal/skiphost"
	"github.com/8enji/veil/internal/ui"
	"github.com/8enji/veil/internal/vault"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// lineReader wraps an io.Reader so that each Read call returns at most one
// line (up to and including the next '\n'). This prevents bufio.Scanner
// instances in the prompt helpers from consuming more than one line of input
// via read-ahead buffering, enabling multiple sequential prompts against the
// same underlying reader.
type lineReader struct {
	br *bufio.Reader
}

func newLineReader(r io.Reader) *lineReader {
	if br, ok := r.(*bufio.Reader); ok {
		return &lineReader{br: br}
	}
	return &lineReader{br: bufio.NewReader(r)}
}

func (l *lineReader) Read(p []byte) (int, error) {
	line, err := l.br.ReadString('\n')
	if len(line) > 0 {
		n := copy(p, line)
		if n < len(line) {
			return n, io.ErrShortBuffer
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

	// Detect non-interactive: --yes flag or non-TTY stdin.
	interactive := !yes
	if interactive {
		if f, ok := stdin.(*os.File); ok {
			if !isatty.IsTerminal(f.Fd()) && !isatty.IsCygwinTerminal(f.Fd()) {
				interactive = false
				fmt.Fprintln(w, ui.Muted.Sprint("Non-interactive mode: vaulting all detected secrets"))
			}
		}
	}

	// Wrap stdin so each prompt reads exactly one line via bufio.Scanner,
	// avoiding read-ahead that would consume input intended for later prompts.
	in := newLineReader(stdin)

	// 1. Resolve project root.
	root := flagPath
	if root == "" {
		r, err := config.FindProjectRoot(".")
		if err != nil {
			return cliError(err.Error(), "")
		}
		root = r
	} else {
		abs, err := filepath.Abs(root)
		if err != nil {
			return cliError(err.Error(), "")
		}
		root = abs
	}

	// 2. Check existing .veil/ directory.
	stateDir := config.ProjectStateDir(root)
	if info, err := os.Stat(stateDir); err == nil && info.IsDir() {
		if !force {
			return cliError("project already initialized", "Use --force to reinitialize")
		}
		// --force: confirm destructive reset.
		if interactive {
			if !promptYN(in, w, "This will replace your existing vault. Continue?", false) {
				fmt.Fprintln(w, ui.Muted.Sprint("Aborted."))
				return nil
			}
		}
	}

	// Phase: Scanning project.
	ui.Phase(w, "Scanning project...")

	// 3. Scan .env files.
	envPaths, err := scanner.Scan(root)
	if err != nil {
		return cliError(fmt.Sprintf("scanning .env files: %v", err), "")
	}

	// 3b. Discover MCP config.
	mcpConfigPath, err := mcpconfig.Discover()
	if err != nil {
		return cliError(fmt.Sprintf("discovering MCP config: %v", err), "")
	}

	// Early exit if nothing to process.
	if len(envPaths) == 0 && mcpConfigPath == "" {
		_, _ = fmt.Fprintf(w, "no .env files or MCP configs found in %s\n", root)
		return nil
	}

	// 3c. Interactive file selection.
	if interactive && len(envPaths) > 1 {
		fmt.Fprintf(w, "\nFound %d .env files:\n", len(envPaths))
		names := make([]string, len(envPaths))
		for i, p := range envPaths {
			rel, _ := filepath.Rel(root, p)
			if rel == "" {
				rel = filepath.Base(p)
			}
			names[i] = rel
			fmt.Fprintf(w, "  %s\n", rel)
		}
		fmt.Fprintln(w)
		choice := promptYNS(in, w, "Scan all?")
		switch choice {
		case choiceNo:
			envPaths = nil
		case choiceSelect:
			selected := promptMultiSelect(in, w, names)
			selectedSet := make(map[string]bool)
			for _, s := range selected {
				selectedSet[s] = true
			}
			var filtered []string
			for i, p := range envPaths {
				if selectedSet[names[i]] {
					filtered = append(filtered, p)
				}
			}
			envPaths = filtered
		}
	}

	// Report what will be scanned.
	if len(envPaths) > 0 {
		ui.Step(w, fmt.Sprintf("Found %d .env %s", len(envPaths), plural(len(envPaths), "file", "files")))
	}
	if mcpConfigPath != "" {
		ui.Step(w, "Found 1 MCP config")
	}
	_, _ = fmt.Fprintln(w)

	// 4. Generate project ID.
	projectID := vault.NewID()

	// 5. Determine keystore.
	ks, err := buildKeystore()
	if err != nil {
		return cliError(fmt.Sprintf("keystore: %v", err), "")
	}

	// 6. Create vault.
	v, err := vault.CreateVault(root, projectID, ks)
	if err != nil {
		return cliError(fmt.Sprintf("creating vault: %v", err), "")
	}

	// Phase: Vaulting secrets.
	ui.Phase(w, "Vaulting secrets...")

	// 7. Process each .env file.
	var secretsVaulted int
	var secretsScoped int
	for _, envPath := range envPaths {
		envFile, err := scanner.ParseFile(envPath)
		if err != nil {
			return cliError(fmt.Sprintf("parsing %s: %v", envPath, err), "")
		}

		// Collect secret-like lines.
		type secretLine struct {
			key   string
			value string
			index int // index into envFile.Lines
		}
		var secrets []secretLine
		for i, line := range envFile.Lines {
			if line.Kind != scanner.KVLine {
				continue
			}
			if !placeholder.IsSecretLike(line.Key, line.Value) {
				if flagVerbose {
					_, _ = fmt.Fprintf(w, "%s\n", ui.Muted.Sprintf("  skip (not secret-like): %s", line.Key))
				}
				continue
			}
			secrets = append(secrets, secretLine{key: line.Key, value: line.Value, index: i})
		}

		if len(secrets) == 0 {
			continue
		}

		// Interactive token selection.
		selectedKeys := make(map[string]bool)
		if interactive {
			rel, _ := filepath.Rel(root, envPath)
			if rel == "" {
				rel = filepath.Base(envPath)
			}
			fmt.Fprintf(w, "\nDetected %d %s in %s:\n", len(secrets), plural(len(secrets), "secret", "secrets"), rel)
			names := make([]string, len(secrets))
			for i, s := range secrets {
				redacted := redactValue(s.value)
				fmt.Fprintf(w, "  %-24s %s\n", s.key, ui.Muted.Sprint(redacted))
				names[i] = s.key
			}
			fmt.Fprintln(w)
			choice := promptYNS(in, w, "Vault all?")
			switch choice {
			case choiceYes:
				for _, s := range secrets {
					selectedKeys[s.key] = true
				}
			case choiceNo:
				continue // skip entire file
			case choiceSelect:
				selected := promptMultiSelect(in, w, names)
				for _, name := range selected {
					selectedKeys[name] = true
				}
			}
		} else {
			for _, s := range secrets {
				selectedKeys[s.key] = true
			}
		}

		fileChanged := false
		for _, s := range secrets {
			if !selectedKeys[s.key] {
				continue
			}

			ph, err := placeholder.Generate(s.key, s.value)
			if err != nil {
				return cliError(fmt.Sprintf("generating placeholder for %s: %v", s.key, err), "")
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
				if strings.Contains(err.Error(), "already exists") {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: duplicate key %q, skipping\n", s.key)
					continue
				}
				return cliError(fmt.Sprintf("vaulting %s: %v", s.key, err), "")
			}

			secretsVaulted++
			if len(credHosts) > 0 {
				secretsScoped++
			}

			if dryRun {
				_, _ = fmt.Fprintf(w, "%s\n", ui.Muted.Sprintf("  would vault: %s -> %s", s.key, ph))
			} else {
				envFile.SetValue(s.key, ph)
				fileChanged = true
			}
		}

		if !dryRun && fileChanged {
			if err := atomicWriteFile(envPath, envFile.Bytes()); err != nil {
				return cliError(fmt.Sprintf("writing %s: %v", envPath, err), "")
			}
		}
	}

	// 8b. Process MCP config.
	var mcpConfigsProcessed int
	if mcpConfigPath != "" {
		n, s, err := processMCPConfig(cmd, in, v, mcpConfigPath, force, dryRun, interactive)
		if err != nil {
			return err
		}
		secretsVaulted += n
		secretsScoped += s
		if n > 0 {
			mcpConfigsProcessed = 1
		}
	}

	// Report vault results.
	unscoped := secretsVaulted - secretsScoped
	ui.Step(w, fmt.Sprintf("%d %s stored in keychain", secretsVaulted, plural(secretsVaulted, "secret", "secrets")))
	if secretsScoped > 0 {
		ui.Step(w, fmt.Sprintf("%d auto-scoped to hosts", secretsScoped))
	}
	if unscoped > 0 {
		ui.Warn(w, fmt.Sprintf("%d unscoped (use veil add --host to scope)", unscoped))
	}
	_, _ = fmt.Fprintln(w)

	// Phase: Skip hosts.
	if interactive && !dryRun {
		fmt.Fprintln(w, "Skip hosts — any hosts the proxy should pass through untouched?")
		fmt.Fprintln(w, ui.Muted.Sprint("Common examples: api.anthropic.com, *.internal.company.com"))
		fmt.Fprintln(w, ui.Muted.Sprint("(You can manage these later with: veil skip)"))
		fmt.Fprintln(w)
		hosts := promptCSV(in, w, "Hosts to skip (comma-separated, or Enter to skip):")
		if len(hosts) > 0 {
			skipPath := config.SkipHostsFile(root)
			for _, h := range hosts {
				_, _ = skiphost.Add(skipPath, h)
				ui.Step(w, fmt.Sprintf("%s added to skip list", h))
			}
			_, _ = fmt.Fprintln(w)
		}
	}

	// Phase: Setting up proxy.
	ui.Phase(w, "Setting up proxy...")

	ca, err := proxy.LoadOrCreateCA()
	if err != nil {
		return cliError(fmt.Sprintf("setting up CA: %v", err), "")
	}
	_ = ca
	ui.Step(w, "CA certificate ready")
	_, _ = fmt.Fprintln(w)

	// 9. Append to project .gitignore.
	if !dryRun {
		appendGitignore(root)
	}

	// 10. Final summary.
	_, _ = fmt.Fprintf(w, "%s\n", ui.Success.Sprintf("Veil initialized for %s", root))
	_, _ = fmt.Fprintf(w, "  .env files processed:  %d\n", len(envPaths))
	if mcpConfigsProcessed > 0 {
		_, _ = fmt.Fprintf(w, "  MCP configs processed: %d\n", mcpConfigsProcessed)
	}
	_, _ = fmt.Fprintf(w, "  Secrets vaulted:       %d\n", secretsVaulted)
	_, _ = fmt.Fprintln(w)
	return nil
}

// redactValue returns a redacted display of a secret value, showing the
// first 4 characters followed by **** for visual identification.
func redactValue(value string) string {
	if len(value) <= 4 {
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
func processMCPConfig(cmd *cobra.Command, in io.Reader, v *vault.Vault, configPath string, force, dryRun, interactive bool) (int, int, error) {
	// Check for existing backup (indicates already migrated).
	backupPath := configPath + ".veil-backup"
	if _, err := os.Stat(backupPath); err == nil && !force {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s already has a backup (use --force to re-migrate)\n", configPath)
		return 0, 0, nil
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
		return 0, 0, nil
	}

	// Interactive MCP selection.
	selectedKeys := make(map[string]bool) // key = "server:key"
	keyOf := func(s mcpSecret) string { return s.server + ":" + s.key }
	if interactive {
		fmt.Fprintf(w, "\nDetected %d MCP %s:\n", len(allSecrets), plural(len(allSecrets), "secret", "secrets"))
		names := make([]string, len(allSecrets))
		for i, s := range allSecrets {
			redacted := redactValue(s.value)
			label := fmt.Sprintf("mcp:%s:%s", s.server, s.key)
			fmt.Fprintf(w, "  %-32s %s\n", label, ui.Muted.Sprint(redacted))
			names[i] = label
		}
		fmt.Fprintln(w)
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

	for _, s := range allSecrets {
		if !selectedKeys[keyOf(s)] {
			continue
		}
		serverName, key, value := s.server, s.key, s.value

		ph, err := placeholder.Generate(key, value)
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
			if strings.Contains(err.Error(), "already exists") {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: duplicate key %q, skipping\n", credName)
				continue
			}
			return 0, 0, cliError(fmt.Sprintf("vaulting %s: %v", credName, err), "")
		}

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
		// Create backup of original.
		originalData, err := os.ReadFile(configPath) // #nosec G304
		if err != nil {
			return 0, 0, cliError(fmt.Sprintf("reading MCP config for backup: %v", err), "")
		}
		if err := os.WriteFile(backupPath, originalData, 0600); err != nil {
			return 0, 0, cliError(fmt.Sprintf("writing MCP config backup: %v", err), "")
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

// appendGitignore adds /.veil/ to the project .gitignore if not already present.
func appendGitignore(root string) {
	gitignorePath := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		// No .gitignore — nothing to do.
		return
	}

	content := string(data)
	if strings.Contains(content, "/.veil/") {
		return
	}

	// Ensure content ends with a newline before appending.
	if len(content) > 0 && content[len(content)-1] != '\n' {
		content += "\n"
	}
	content += "/.veil/\n"

	_ = os.WriteFile(gitignorePath, []byte(content), 0600) //nolint:gosec // .gitignore is not sensitive
}
