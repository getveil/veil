package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/scanner"
	"github.com/8enji/veil/internal/ui"
	"github.com/8enji/veil/internal/vault"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Test seams for secret entry. stdinIsTerminal reports whether os.Stdin is
// a terminal; readSecretFromTerminal reads a password with local echo
// disabled. Tests swap these to exercise the TTY path without a real PTY.
var (
	stdinIsTerminal        = func() bool { return isatty.IsTerminal(os.Stdin.Fd()) }
	readSecretFromTerminal = func() ([]byte, error) {
		return term.ReadPassword(int(os.Stdin.Fd()))
	}
)

func addCmd() *cobra.Command {
	var force bool
	var hosts []string
	var value string
	var valueStdin bool
	var username string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a secret to the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAdd(cmd, args[0], force, hosts, value, valueStdin, username)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing credential")
	cmd.Flags().StringArrayVar(&hosts, "host", nil, "allowed destination host (repeatable)")
	cmd.Flags().StringVar(&value, "value", "", "secret value (UNSAFE: saved to shell history; prefer --value-stdin)")
	cmd.Flags().BoolVar(&valueStdin, "value-stdin", false, "read secret from stdin without a prompt")
	cmd.Flags().StringVar(&username, "user", "", "username for HTTP Basic credentials")
	cmd.MarkFlagsMutuallyExclusive("value", "value-stdin")
	return cmd
}

func runAdd(cmd *cobra.Command, name string, force bool, hosts []string, flagValue string, valueStdin bool, username string) error {
	return withVault(cmd, func(root string, v *vault.Vault) error {
		return runAddInVault(cmd, root, v, name, force, hosts, flagValue, valueStdin, username)
	})
}

func runAddInVault(cmd *cobra.Command, root string, v *vault.Vault, name string, force bool, hosts []string, flagValue string, valueStdin bool, username string) error {
	// Validate --user flag.
	userFlagSet := cmd.Flags().Changed("user")
	if userFlagSet && username == "" {
		return cliError("--user cannot be empty", "")
	}
	if username != "" && strings.Contains(username, ":") {
		return cliError("username cannot contain ':' (RFC 7617)", "")
	}
	isBasic := username != ""

	value, err := readCredentialValue(cmd, name, flagValue, valueStdin)
	if err != nil {
		return err
	}
	if value == "" {
		return cliError("no value provided", "")
	}

	// Generate secret placeholder.
	ph, err := placeholder.Generate(name, value, v.PlaceholderSet())
	if err != nil {
		return cliError(fmt.Sprintf("generating placeholder: %v", err), "")
	}

	// Generate username placeholder if HTTP Basic.
	var userPh string
	if isBasic {
		existing := v.PlaceholderSet()
		existing[ph] = struct{}{}
		userPh, err = placeholder.Generate(name+"_USER", username, existing)
		if err != nil {
			return cliError(fmt.Sprintf("generating username placeholder: %v", err), "")
		}
	}

	// Resolve allowed hosts: --host flags if provided, otherwise auto-detect.
	allowedHosts := hosts
	if len(allowedHosts) == 0 {
		allowedHosts = placeholder.HostsForCredential(name, value)
	}

	// Handle --force: delete existing credential, capture old placeholders for .env sync.
	var oldPlaceholder, oldUsernamePlaceholder string
	if force {
		if existing, found := v.Get(name); found {
			oldPlaceholder = existing.Placeholder
			oldUsernamePlaceholder = existing.UsernamePlaceholder
		}
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
	if isBasic {
		cred.Username = username
		cred.UsernamePlaceholder = userPh
	}
	if err := v.Add(cred); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return cliError(fmt.Sprintf("credential %q already exists", name), "Use --force to overwrite")
		}
		return cliError(fmt.Sprintf("adding credential: %v", err), "")
	}

	w := cmd.OutOrStdout()

	// If --force replaced a credential, update .env files with the new placeholder(s).
	if oldPlaceholder != "" && oldPlaceholder != cred.Placeholder {
		updated := syncPlaceholderInEnvFiles(root, oldPlaceholder, cred.Placeholder)
		if updated > 0 {
			ui.Step(w, fmt.Sprintf("Updated placeholder in %d .env %s", updated, plural(updated, "file", "files")))
		}
	}
	if oldUsernamePlaceholder != "" && oldUsernamePlaceholder != cred.UsernamePlaceholder {
		updated := syncPlaceholderInEnvFiles(root, oldUsernamePlaceholder, cred.UsernamePlaceholder)
		if updated > 0 {
			ui.Step(w, fmt.Sprintf("Updated user placeholder in %d .env %s", updated, plural(updated, "file", "files")))
		}
	}

	if isBasic {
		ui.Step(w, fmt.Sprintf("Added %s to vault (basic auth)", name))
		_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("User placeholder:"), cred.UsernamePlaceholder)
		_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Secret placeholder:"), cred.Placeholder)
	} else {
		ui.Step(w, fmt.Sprintf("Added %s to vault", name))
		_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Placeholder:"), cred.Placeholder)
	}
	if len(allowedHosts) > 0 {
		_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Hosts:"), strings.Join(allowedHosts, ", "))
	} else {
		ui.Warn(w, fmt.Sprintf("No target hosts detected for %s", name))
		_, _ = fmt.Fprintf(w, "    %s\n", ui.Muted.Sprint("Use veil add --host to scope it"))
	}

	return nil
}

// readCredentialValue returns the secret value for the add command.
// Precedence: explicit --value flag → --value-stdin (drain stdin) →
// interactive prompt. The interactive path uses term.ReadPassword when the
// real stdin is a terminal (so keystrokes are not echoed); tests inject
// their own stdin via cmd.SetIn, which bypasses the TTY check and reads a
// line.
func readCredentialValue(cmd *cobra.Command, name, flagValue string, valueStdin bool) (string, error) {
	switch {
	case flagValue != "":
		warnShellHistory(cmd.ErrOrStderr())
		return flagValue, nil
	case valueStdin:
		return readAllStdin(cmd.InOrStdin())
	default:
		return promptForSecret(cmd, name)
	}
}

// warnShellHistory prints a warning reminding the user that a secret
// supplied via --value survives in their shell history and suggesting
// safer alternatives. Always printed (regardless of TTY) so that users
// running the command inside a history-logging shell can't miss it.
func warnShellHistory(w io.Writer) {
	ui.FormatWarning(w,
		"--value puts the secret in your shell history",
		"Prefer: veil add KEY --value-stdin < secret.txt  (or omit --value to be prompted)")
}

// readAllStdin consumes the entirety of r as the secret value and returns
// it with any trailing newline stripped.
func readAllStdin(r io.Reader) (string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return "", cliErrorf("reading stdin: %v", err)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// promptForSecret reads the secret interactively. When the injected reader
// is os.Stdin AND os.Stdin is a TTY, ReadPassword is used so keystrokes
// are not echoed. Otherwise the reader is consumed line-oriented (existing
// behavior for piped input and tests).
func promptForSecret(cmd *cobra.Command, name string) (string, error) {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Enter value for %s: ", name)

	if cmd.InOrStdin() == os.Stdin && stdinIsTerminal() {
		pw, err := readSecretFromTerminal()
		// ReadPassword leaves the cursor on the prompt line; emit the
		// newline ourselves so the following output doesn't collide.
		_, _ = fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", cliError("no value provided", "")
			}
			return "", cliErrorf("reading password: %v", err)
		}
		return strings.TrimRight(string(pw), "\r\n"), nil
	}

	reader := bufio.NewReader(cmd.InOrStdin())
	raw, err := reader.ReadString('\n')
	if err != nil {
		// Accept EOF without newline (e.g. piped input).
		if raw == "" {
			return "", cliError("no value provided", "")
		}
	}
	return strings.TrimRight(raw, "\r\n"), nil
}

// syncPlaceholderInEnvFiles replaces oldPh with newPh in all .env files under root.
// Returns the number of files updated.
func syncPlaceholderInEnvFiles(root, oldPh, newPh string) int {
	envPaths, err := scanner.Scan(root)
	if err != nil {
		return 0
	}
	var count int
	for _, path := range envPaths {
		data, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			continue
		}
		content := string(data)
		if !strings.Contains(content, oldPh) {
			continue
		}
		updated := strings.ReplaceAll(content, oldPh, newPh)
		if err := atomicWriteFile(path, []byte(updated)); err != nil {
			continue
		}
		count++
	}
	return count
}
