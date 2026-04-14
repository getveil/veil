package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/mcpconfig"
	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/proxy"
	"github.com/8enji/veil/internal/scanner"
	"github.com/8enji/veil/internal/ui"
	"github.com/8enji/veil/internal/vault"
	"github.com/spf13/cobra"
)

func initCmd() *cobra.Command {
	var force, dryRun bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Veil for the current project",
		Long:  "Scan .env files, vault secrets, and replace them with placeholders.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(cmd, force, dryRun)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "reinitialize even if .veil/ exists")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be vaulted without making changes")
	return cmd
}

func runInit(cmd *cobra.Command, force, dryRun bool) error {
	w := cmd.OutOrStdout()

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
	if info, err := os.Stat(stateDir); err == nil && info.IsDir() && !force {
		return cliError("project already initialized", "Use --force to reinitialize")
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

	// Report what was found.
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

		fileChanged := false
		for _, line := range envFile.Lines {
			if line.Kind != scanner.KVLine {
				continue
			}

			if !placeholder.IsSecretLike(line.Key, line.Value) {
				if flagVerbose {
					_, _ = fmt.Fprintf(w, "%s\n", ui.Muted.Sprintf("  skip (not secret-like): %s", line.Key))
				}
				continue
			}

			ph, err := placeholder.Generate(line.Key, line.Value)
			if err != nil {
				return cliError(fmt.Sprintf("generating placeholder for %s: %v", line.Key, err), "")
			}

			credHosts := placeholder.HostsForCredential(line.Key, line.Value)

			cred := &vault.Credential{
				ID:           vault.NewID(),
				Name:         line.Key,
				Real:         line.Value,
				Placeholder:  ph,
				Source:       "init",
				AllowedHosts: credHosts,
				CreatedAt:    time.Now(),
			}
			if err := v.Add(cred); err != nil {
				if strings.Contains(err.Error(), "already exists") {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: duplicate key %q, skipping\n", line.Key)
					continue
				}
				return cliError(fmt.Sprintf("vaulting %s: %v", line.Key, err), "")
			}

			secretsVaulted++
			if len(credHosts) > 0 {
				secretsScoped++
			}

			if dryRun {
				_, _ = fmt.Fprintf(w, "%s\n", ui.Muted.Sprintf("  would vault: %s -> %s", line.Key, ph))
			} else {
				envFile.SetValue(line.Key, ph)
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
		n, s, err := processMCPConfig(cmd, v, mcpConfigPath, force, dryRun)
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
func processMCPConfig(cmd *cobra.Command, v *vault.Vault, configPath string, force, dryRun bool) (int, int, error) {
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

	var count int
	var scoped int
	configChanged := false

	for serverName, server := range mcpCfg.Servers() {
		for key, value := range server.Env {
			if !placeholder.IsSecretLike(key, value) {
				if flagVerbose {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", ui.Muted.Sprintf("  skip (not secret-like): mcp:%s:%s", serverName, key))
				}
				continue
			}

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
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", ui.Muted.Sprintf("  would vault: %s -> %s", credName, ph))
			} else {
				mcpCfg.SetEnvValue(serverName, key, ph)
				configChanged = true
			}
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
