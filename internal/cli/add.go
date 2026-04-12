package cli

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/vault"
	"github.com/spf13/cobra"
)

func addCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a secret to the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAdd(cmd, args[0], force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing credential")
	return cmd
}

func runAdd(cmd *cobra.Command, name string, force bool) error {
	root, err := resolveRoot()
	if err != nil {
		return exitError(err.Error())
	}

	v, err := openVault(root)
	if err != nil {
		return exitError(fmt.Sprintf("opening vault: %v", err))
	}

	// Read value from stdin.
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Enter value for %s: ", name)
	reader := bufio.NewReader(cmd.InOrStdin())
	value, err := reader.ReadString('\n')
	if err != nil {
		// Accept EOF without newline (e.g. piped input).
		if value == "" {
			return exitError("no value provided")
		}
	}
	value = strings.TrimRight(value, "\r\n")

	if value == "" {
		return exitError("no value provided")
	}

	// Generate placeholder.
	ph, err := placeholder.Generate(name, value)
	if err != nil {
		return exitError(fmt.Sprintf("generating placeholder: %v", err))
	}

	// Handle --force: delete existing credential first.
	if force {
		_, _ = v.Delete(name)
	}

	cred := &vault.Credential{
		ID:          vault.NewID(),
		Name:        name,
		Real:        value,
		Placeholder: ph,
		Source:      "manual",
		CreatedAt:   time.Now(),
	}
	if err := v.Add(cred); err != nil {
		return exitError(fmt.Sprintf("adding credential: %v", err))
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Added %s to vault\n", name)
	return nil
}
