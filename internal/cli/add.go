package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/getveil/veil/internal/placeholder"
	"github.com/getveil/veil/internal/scanner"
	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
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

// addOpts bundles the flag-backed inputs accepted by `veil add`.
type addOpts struct {
	force      bool
	hosts      []string
	value      string
	valueStdin bool
	username   string
}

func addCmd() *cobra.Command {
	var opts addOpts
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a secret to the vault",
		Example: `  # Add a bearer token (prompts for value, no echo)
  veil add STRIPE_KEY --host api.stripe.com

  # Add HTTP Basic credentials
  veil add ARTIFACTORY --user alice --host artifactory.example.com

  # Pipe a secret from stdin (avoids leaving it in shell history)
  printf %s "$TOKEN" | veil add GITHUB_TOKEN --value-stdin --host api.github.com`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAdd(cmd, args[0], opts)
		},
	}
	cmd.Flags().BoolVar(&opts.force, "force", false, "overwrite existing credential")
	cmd.Flags().StringArrayVar(&opts.hosts, "host", nil, "allowed destination host (repeatable)")
	cmd.Flags().StringVar(&opts.value, "value", "", "secret value (UNSAFE: saved to shell history; prefer --value-stdin)")
	cmd.Flags().BoolVar(&opts.valueStdin, "value-stdin", false, "read secret from stdin without a prompt")
	cmd.Flags().StringVar(&opts.username, "user", "", "username for HTTP Basic credentials")
	cmd.MarkFlagsMutuallyExclusive("value", "value-stdin")
	return cmd
}

func runAdd(cmd *cobra.Command, name string, opts addOpts) error {
	return withVault(cmd, func(root string, v *vault.Vault) error {
		return runAddInVault(cmd, root, v, name, opts)
	})
}

func runAddInVault(cmd *cobra.Command, root string, v *vault.Vault, name string, opts addOpts) error {
	// Validate --user flag.
	userFlagSet := cmd.Flags().Changed("user")
	if userFlagSet && opts.username == "" {
		return cliError("--user cannot be empty", "")
	}
	if opts.username != "" && strings.Contains(opts.username, ":") {
		return cliError("username cannot contain ':' (RFC 7617)", "")
	}

	isBasic := opts.username != ""

	value, err := readCredentialValue(cmd, name, opts.value, opts.valueStdin)
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
		userPh, err = placeholder.Generate(name+"_USER", opts.username, existing)
		if err != nil {
			return cliError(fmt.Sprintf("generating username placeholder: %v", err), "")
		}
	}

	// Resolve allowed hosts: --host flags if provided, otherwise auto-detect.
	allowedHosts := opts.hosts
	if len(allowedHosts) == 0 {
		allowedHosts = placeholder.HostsForCredential(name, value)
	}

	// Handle --force: delete existing credential, capture old placeholders for .env sync.
	var oldPlaceholder, oldUsernamePlaceholder string
	if opts.force {
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
		cred.Username = opts.username
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
//
// The replacement operates on the DECODED value of each KV line (via the
// scanner's parser) so quoted/escaped values round-trip correctly on write.
func syncPlaceholderInEnvFiles(root, oldPh, newPh string) int {
	envPaths, err := scanner.Scan(root)
	if err != nil {
		return 0
	}
	var count int
	for _, path := range envPaths {
		ef, err := scanner.ParseFile(path)
		if err != nil {
			continue
		}
		changed := false
		for _, line := range ef.Lines {
			if line.Kind != scanner.KVLine {
				continue
			}
			if !strings.Contains(line.Value, oldPh) {
				continue
			}
			updated := strings.ReplaceAll(line.Value, oldPh, newPh)
			if ef.SetValue(line.Key, updated) {
				changed = true
			}
		}
		if !changed {
			continue
		}
		if err := atomicWriteFile(path, ef.Bytes()); err != nil {
			continue
		}
		count++
	}
	return count
}
