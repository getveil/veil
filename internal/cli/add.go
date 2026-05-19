package cli

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
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

// awsAccessKeyIDRegex matches AWS static and temporary access key IDs.
// AKIA = long-term user/role; ASIA = STS-issued short-term.
var awsAccessKeyIDRegex = regexp.MustCompile(`^(AKIA|ASIA)[A-Z0-9]{16}$`)

// addOpts bundles the flag-backed inputs accepted by `veil add`. Passing a
// struct (rather than a growing positional parameter list) keeps the
// signature stable as new credential schemes are added.
type addOpts struct {
	force                bool
	hosts                []string
	value                string
	valueStdin           bool
	username             string
	scheme               string
	awsAccessKeyID       string
	awsSessionTokenFile  string
	awsSessionTokenStdin bool
	githubAppID          int64
	githubInstallationID int64
}

func addCmd() *cobra.Command {
	var opts addOpts
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a secret to the vault",
		// #nosec G101 -- AKIAIOSFODNN7EXAMPLE is AWS's documented placeholder access key, shown only in help text
		Example: `  # Add a bearer token (prompts for value, no echo)
  veil add STRIPE_KEY --host api.stripe.com

  # Add HTTP Basic credentials
  veil add ARTIFACTORY --user alice --host artifactory.example.com

  # Add AWS credentials with a session token (prompts for secret access key)
  veil add AWS_PROD --scheme aws \
    --aws-access-key-id AKIAIOSFODNN7EXAMPLE \
    --aws-session-token-file ./token.txt

  # Add a GitHub App private key (RSA PEM on stdin)
  veil add GH_APP --scheme github_app --github-app-id 123456 \
    --value-stdin < app.pem`,
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
	cmd.Flags().StringVar(&opts.scheme, "scheme", "", "credential scheme: aws, github_app (default: bearer or basic)")
	cmd.Flags().StringVar(&opts.awsAccessKeyID, "aws-access-key-id", "", "AWS access key ID (required for --scheme aws)")
	cmd.Flags().StringVar(&opts.awsSessionTokenFile, "aws-session-token-file", "", "path to a file containing an AWS session token")
	cmd.Flags().BoolVar(&opts.awsSessionTokenStdin, "aws-session-token-stdin", false, "read AWS session token from stdin (mutually exclusive with --value-stdin)")
	cmd.Flags().Int64Var(&opts.githubAppID, "github-app-id", 0, "GitHub App ID (required for --scheme github_app)")
	cmd.Flags().Int64Var(&opts.githubInstallationID, "github-installation-id", 0, "GitHub App installation ID (optional)")
	cmd.MarkFlagsMutuallyExclusive("value", "value-stdin")
	cmd.MarkFlagsMutuallyExclusive("aws-session-token-file", "aws-session-token-stdin")
	cmd.MarkFlagsMutuallyExclusive("value-stdin", "aws-session-token-stdin")
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

	switch opts.scheme {
	case "":
		// default: bearer (or basic when --user is set)
	case "aws":
		return runAddAWS(cmd, root, v, name, opts)
	case "github_app":
		return runAddGitHubApp(cmd, root, v, name, opts)
	default:
		return cliError(fmt.Sprintf("unknown --scheme %q", opts.scheme), "valid values: aws, github_app (omit for bearer/basic)")
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

// runAddAWS handles the `--scheme aws` branch. It generates an AKID-shaped
// placeholder for the access key (so SDKs scope a SigV4 Credential= string
// around it), a base64-ish placeholder for the secret, and — if supplied —
// a long base64-ish placeholder for a session token. All three go into the
// same Credential record; the proxy re-signs on the way out using the real
// values.
func runAddAWS(cmd *cobra.Command, root string, v *vault.Vault, name string, opts addOpts) error {
	if opts.username != "" {
		return cliError("--user is not valid with --scheme aws", "")
	}
	if opts.awsAccessKeyID == "" {
		return cliError("--aws-access-key-id is required for --scheme aws", "")
	}
	if !awsAccessKeyIDRegex.MatchString(opts.awsAccessKeyID) {
		return cliError("access key ID must match AKIA|ASIA + 16 upper-alphanumeric", "")
	}

	secret, err := readCredentialValue(cmd, name, opts.value, opts.valueStdin)
	if err != nil {
		return err
	}
	if secret == "" {
		return cliError("no value provided", "")
	}

	// Secret access key placeholder. Pass the canonical env-var name so the
	// AWS provider's role-aware dispatch picks a secret-style placeholder
	// even when the secret value happens to start with AKIA/ASIA.
	secretPh, err := placeholder.Generate("AWS_SECRET_ACCESS_KEY", secret, v.PlaceholderSet())
	if err != nil {
		return cliErrorf("generating placeholder: %v", err)
	}

	// Access key ID placeholder (AKIA-prefixed).
	existing := v.PlaceholderSet()
	existing[secretPh] = struct{}{}
	akIDPh := generateAWSAccessKeyIDPlaceholder(opts.awsAccessKeyID, existing)
	existing[akIDPh] = struct{}{}

	// Optional session token.
	var sessTok, sessPh string
	if opts.awsSessionTokenFile != "" {
		b, readErr := os.ReadFile(opts.awsSessionTokenFile) // #nosec G304
		if readErr != nil {
			return cliErrorf("read session token: %v", readErr)
		}
		sessTok = strings.TrimRight(string(b), "\r\n")
	} else if opts.awsSessionTokenStdin {
		sessTok, err = readAllStdin(cmd.InOrStdin())
		if err != nil {
			return err
		}
	}
	if sessTok != "" {
		sessPh, err = placeholder.GenerateAWSSessionToken(sessTok, existing)
		if err != nil {
			return cliErrorf("generating session token placeholder: %v", err)
		}
	}

	// Resolve allowed hosts: --host flags if provided, otherwise default to AWS.
	allowedHosts := opts.hosts
	if len(allowedHosts) == 0 {
		allowedHosts = []string{"*.amazonaws.com"}
	}

	// --force: collect old placeholders so .env files can be rewritten.
	var oldPhs []string
	if opts.force {
		if prev, found := v.Get(name); found {
			if prev.Placeholder != "" {
				oldPhs = append(oldPhs, prev.Placeholder)
			}
			if prev.AWSAccessKeyIDPlaceholder != "" {
				oldPhs = append(oldPhs, prev.AWSAccessKeyIDPlaceholder)
			}
			if prev.AWSSessionTokenPlaceholder != "" {
				oldPhs = append(oldPhs, prev.AWSSessionTokenPlaceholder)
			}
			_, _ = v.Delete(name)
		}
	}

	cred := &vault.Credential{
		ID:                         vault.NewID(),
		Name:                       name,
		Real:                       secret,
		Placeholder:                secretPh,
		Source:                     "manual",
		AllowedHosts:               allowedHosts,
		CreatedAt:                  time.Now(),
		Scheme:                     "aws",
		AWSAccessKeyID:             opts.awsAccessKeyID,
		AWSAccessKeyIDPlaceholder:  akIDPh,
		AWSSessionToken:            sessTok,
		AWSSessionTokenPlaceholder: sessPh,
	}
	if err := v.Add(cred); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return cliError(fmt.Sprintf("credential %q already exists", name), "Use --force to overwrite")
		}
		return cliErrorf("adding credential: %v", err)
	}

	// Pair old placeholders with new for .env sync. When the user adds a
	// session token for the first time, the new set has one extra entry
	// that no old entry matches — that's fine; the loop stops at the
	// shorter length.
	newPhs := []string{secretPh, akIDPh}
	if sessPh != "" {
		newPhs = append(newPhs, sessPh)
	}
	w := cmd.OutOrStdout()
	for i, oldPh := range oldPhs {
		if i >= len(newPhs) {
			break
		}
		if oldPh == newPhs[i] {
			continue
		}
		updated := syncPlaceholderInEnvFiles(root, oldPh, newPhs[i])
		if updated > 0 {
			ui.Step(w, fmt.Sprintf("Updated placeholder in %d .env %s", updated, plural(updated, "file", "files")))
		}
	}

	ui.Step(w, fmt.Sprintf("Added %s to vault (aws)", name))
	_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Access key placeholder:"), akIDPh)
	_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Secret placeholder:"), secretPh)
	if sessPh != "" {
		_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Session token placeholder:"), sessPh)
	}
	if len(allowedHosts) > 0 {
		_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Hosts:"), strings.Join(allowedHosts, ", "))
	}
	return nil
}

// runAddGitHubApp handles the `--scheme github_app` branch. The real value
// on stdin (or --value) is an RSA PEM private key belonging to a GitHub App;
// the stored placeholder is a fresh RSA 2048 PEM, so the SDK can load it
// and sign JWTs locally. The proxy detects the resulting JWT by its `iss`
// claim and re-signs with the real key before forwarding.
func runAddGitHubApp(cmd *cobra.Command, root string, v *vault.Vault, name string, opts addOpts) error {
	if opts.username != "" {
		return cliError("--user is not valid with --scheme github_app", "")
	}
	if opts.githubAppID <= 0 {
		return cliError("--github-app-id must be > 0 for --scheme github_app", "")
	}

	value, err := readCredentialValue(cmd, name, opts.value, opts.valueStdin)
	if err != nil {
		return err
	}
	if value == "" {
		return cliError("no value provided", "")
	}
	if err := validateRSAPEM(value); err != nil {
		return cliErrorf("--value must be an RSA PEM private key: %v", err)
	}

	placeholderPEM, err := placeholder.GenerateGitHubAppPrivateKey()
	if err != nil {
		return cliErrorf("generating placeholder key: %v", err)
	}

	// Resolve allowed hosts: --host flags if provided, otherwise default to api.github.com.
	allowedHosts := opts.hosts
	if len(allowedHosts) == 0 {
		allowedHosts = []string{"api.github.com"}
	}

	// --force: capture old placeholder for .env sync.
	var oldPh string
	if opts.force {
		if prev, found := v.Get(name); found {
			oldPh = prev.Placeholder
			_, _ = v.Delete(name)
		}
	}

	cred := &vault.Credential{
		ID:                   vault.NewID(),
		Name:                 name,
		Real:                 value,
		Placeholder:          placeholderPEM,
		Source:               "manual",
		AllowedHosts:         allowedHosts,
		CreatedAt:            time.Now(),
		Scheme:               "github_app",
		GitHubAppID:          opts.githubAppID,
		GitHubInstallationID: opts.githubInstallationID,
	}
	if err := v.Add(cred); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return cliError(fmt.Sprintf("credential %q already exists", name), "Use --force to overwrite")
		}
		return cliErrorf("adding credential: %v", err)
	}

	w := cmd.OutOrStdout()
	if oldPh != "" && oldPh != cred.Placeholder {
		updated := syncPlaceholderInEnvFiles(root, oldPh, cred.Placeholder)
		if updated > 0 {
			ui.Step(w, fmt.Sprintf("Updated placeholder in %d .env %s", updated, plural(updated, "file", "files")))
		}
	}

	ui.Step(w, fmt.Sprintf("Added %s to vault (github_app)", name))
	_, _ = fmt.Fprintf(w, "    %s %d\n", ui.Muted.Sprint("App ID:"), opts.githubAppID)
	_, _ = fmt.Fprintf(w, "    %s <generated RSA PEM — %d bytes>\n", ui.Muted.Sprint("Private key placeholder:"), len(placeholderPEM))
	if len(allowedHosts) > 0 {
		_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Hosts:"), strings.Join(allowedHosts, ", "))
	}
	return nil
}

// validateRSAPEM returns nil iff `value` decodes as a PEM block that
// contains either a PKCS#1 or PKCS#8-wrapped RSA private key.
func validateRSAPEM(value string) error {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return fmt.Errorf("no PEM block found")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return nil
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return nil
	}
	return fmt.Errorf("not an RSA private key (PKCS#1 or PKCS#8)")
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
// scanner's parser), so multi-line placeholders (e.g. GitHub App RSA PEMs)
// are re-escaped correctly on write. A raw strings.ReplaceAll on the file
// bytes would both fail to match escaped multi-line values and, if it did
// match, inject literal newlines into the .env.
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
