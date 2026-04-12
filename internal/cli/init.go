package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/proxy"
	"github.com/8enji/veil/internal/scanner"
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
	// 1. Resolve project root.
	root := flagPath
	if root == "" {
		r, err := config.FindProjectRoot(".")
		if err != nil {
			return exitError(err.Error())
		}
		root = r
	} else {
		abs, err := filepath.Abs(root)
		if err != nil {
			return exitError(err.Error())
		}
		root = abs
	}

	// 2. Check existing .veil/ directory.
	stateDir := config.ProjectStateDir(root)
	if info, err := os.Stat(stateDir); err == nil && info.IsDir() && !force {
		return exitError("project already initialized (use --force to reinitialize)")
	}

	// 3. Scan .env files.
	envPaths, err := scanner.Scan(root)
	if err != nil {
		return exitError(fmt.Sprintf("scanning .env files: %v", err))
	}
	if len(envPaths) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "no .env files found in %s\n", root)
		return nil
	}

	// 4. Generate project ID.
	projectID := vault.NewID()

	// 5. Determine keystore.
	ks, err := buildKeystore()
	if err != nil {
		return exitError(fmt.Sprintf("keystore: %v", err))
	}

	// 6. Create vault.
	v, err := vault.CreateVault(root, projectID, ks)
	if err != nil {
		return exitError(fmt.Sprintf("creating vault: %v", err))
	}

	// 7. Ensure CA.
	ca, err := proxy.LoadOrCreateCA()
	if err != nil {
		return exitError(fmt.Sprintf("setting up CA: %v", err))
	}
	caFile, err := config.CAFile()
	if err != nil {
		return exitError(fmt.Sprintf("CA file path: %v", err))
	}
	_ = ca // CA struct is used only for side-effects (generation/loading).

	// 8. Process each .env file.
	var secretsVaulted int
	for _, envPath := range envPaths {
		envFile, err := scanner.ParseFile(envPath)
		if err != nil {
			return exitError(fmt.Sprintf("parsing %s: %v", envPath, err))
		}

		fileChanged := false
		for _, line := range envFile.Lines {
			if line.Kind != scanner.KVLine {
				continue
			}

			// Check for veil:skip directive.
			if strings.Contains(line.Raw, "# veil:skip") {
				if flagVerbose {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  skip (veil:skip): %s\n", line.Key)
				}
				continue
			}

			// Check if value looks like a secret.
			if !placeholder.IsSecretLike(line.Key, line.Value) {
				if flagVerbose {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  skip (not secret-like): %s\n", line.Key)
				}
				continue
			}

			// Generate placeholder.
			ph, err := placeholder.Generate(line.Key, line.Value)
			if err != nil {
				return exitError(fmt.Sprintf("generating placeholder for %s: %v", line.Key, err))
			}

			// Vault the real value.
			cred := &vault.Credential{
				ID:          vault.NewID(),
				Name:        line.Key,
				Real:        line.Value,
				Placeholder: ph,
				Source:      "init",
				CreatedAt:   time.Now(),
			}
			if err := v.Add(cred); err != nil {
				// Duplicate name — warn and skip.
				if strings.Contains(err.Error(), "already exists") {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: duplicate key %q, skipping\n", line.Key)
					continue
				}
				return exitError(fmt.Sprintf("vaulting %s: %v", line.Key, err))
			}

			secretsVaulted++

			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  would vault: %s -> %s\n", line.Key, ph)
			} else {
				envFile.SetValue(line.Key, ph)
				fileChanged = true
			}
		}

		// Write updated .env file (unless dry-run).
		if !dryRun && fileChanged {
			if err := atomicWriteFile(envPath, envFile.Bytes()); err != nil {
				return exitError(fmt.Sprintf("writing %s: %v", envPath, err))
			}
		}
	}

	// 9. Append to project .gitignore.
	if !dryRun {
		appendGitignore(root)
	}

	// 10. Print summary.
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Veil initialized for %s\n", root)
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Secrets vaulted: %d\n", secretsVaulted)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  .env files processed: %d\n", len(envPaths))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  CA: %s\n", caFile)
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Run 'veil trust' to install the CA into your system trust store.")

	return nil
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
