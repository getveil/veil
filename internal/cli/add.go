package cli

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/vault"
	"github.com/spf13/cobra"
)

func addCmd() *cobra.Command {
	var force bool
	var hosts []string
	var value string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a secret to the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAdd(cmd, args[0], force, hosts, value)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing credential")
	cmd.Flags().StringArrayVar(&hosts, "host", nil, "allowed destination host (repeatable)")
	cmd.Flags().StringVar(&value, "value", "", "credential value (skips stdin prompt)")
	return cmd
}

func runAdd(cmd *cobra.Command, name string, force bool, hosts []string, value string) error {
	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	v, err := openVault(root)
	if err != nil {
		return cliError(fmt.Sprintf("opening vault: %v", err), "")
	}

	// Load project config for scoping defaults.
	configPath := config.ConfigFile(root)
	cfg, err := config.Load(configPath)
	if err != nil {
		return cliError(fmt.Sprintf("loading config: %v", err), "")
	}

	// Read value from stdin if not provided via --value flag.
	if value == "" {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Enter value for %s: ", name)
		reader := bufio.NewReader(cmd.InOrStdin())
		var readErr error
		value, readErr = reader.ReadString('\n')
		if readErr != nil {
			// Accept EOF without newline (e.g. piped input).
			if value == "" {
				return cliError("no value provided", "")
			}
		}
		value = strings.TrimRight(value, "\r\n")
	}

	if value == "" {
		return cliError("no value provided", "")
	}

	// Generate placeholder.
	ph, err := placeholder.Generate(name, value)
	if err != nil {
		return cliError(fmt.Sprintf("generating placeholder: %v", err), "")
	}

	// Resolve allowed hosts: --host flags > config scoping > auto-detection.
	allowedHosts := hosts
	if len(allowedHosts) == 0 {
		if configHosts, ok := cfg.Scoping[name]; ok {
			allowedHosts = configHosts
		} else {
			allowedHosts = placeholder.HostsForCredential(name, value)
		}
	}

	// Handle --force: delete existing credential first.
	if force {
		_, _ = v.Delete(name)
	}

	cred := &vault.Credential{
		ID:           vault.NewID(),
		Name:         name,
		Real:         value,
		Placeholder:  ph,
		Source:       "manual",
		AllowedHosts: allowedHosts,
		CreatedAt:    time.Now(),
	}
	if err := v.Add(cred); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return cliError(fmt.Sprintf("credential %q already exists", name), "Use --force to overwrite")
		}
		return cliError(fmt.Sprintf("adding credential: %v", err), "")
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Added %s to vault\n", name)
	if len(allowedHosts) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Hosts: %s\n", strings.Join(allowedHosts, ", "))
	} else {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
			"Warning: no target hosts detected for %s. It won't be injected until scoped with --host.\n", name)
	}

	return nil
}
