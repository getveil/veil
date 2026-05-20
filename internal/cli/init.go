package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/getveil/veil/internal/config"
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
		return wrapErr("scanning project", err)
	}

	if len(envPaths) == 0 {
		return runInitNoEnvFiles(w, root, dryRun)
	}

	envPaths = filterInputs(in, w, root, envPaths, interactive)

	if len(envPaths) > 0 {
		ui.Step(w, fmt.Sprintf("Found %d .env %s:", len(envPaths), plural(len(envPaths), "file", "files")))
		for _, p := range envPaths {
			ui.Dim(w, "  "+displayRel(root, p))
		}
	}
	_, _ = fmt.Fprintln(w)

	// Both gates run BEFORE buildKeystore / CreateVault so a refused project
	// never reaches the destructive keystore-delete / vault-recreate path
	// that --force would otherwise trigger.
	if err := refuseSymlinkedInputs(root, envPaths); err != nil {
		return err
	}
	if err := refusePlaceholderInputs(root, envPaths, force); err != nil {
		return err
	}

	ks, err := buildKeystore()
	if err != nil {
		return wrapErr("keystore", err)
	}
	// On Linux without Secret Service the keystore silently falls back to
	// an age-encrypted file gated by VEIL_PASSPHRASE. Surface that to the
	// user up front rather than letting them hit an opaque
	// ErrKeystoreUnavailable on the first vault write.
	if err := announceFileBackedKeystore(w, ks); err != nil {
		return err
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
	if err := setupProxyCA(w, dryRun); err != nil {
		return err
	}

	if !dryRun {
		appendGitignore(w, root)
	}

	if dryRun {
		_, _ = fmt.Fprintf(w, "%s\n", ui.Success.Sprintf("Dry-run preview for %s — no changes made", root))
		_, _ = fmt.Fprintf(w, "  .env files that would be processed:  %d\n", len(envPaths))
		_, _ = fmt.Fprintf(w, "  Secrets that would be vaulted:       %d\n", secretsVaulted)
		_, _ = fmt.Fprintln(w)
		ui.Dim(w, "Re-run without --dry-run to apply these changes.")
		_, _ = fmt.Fprintln(w)
	} else {
		_, _ = fmt.Fprintf(w, "%s\n", ui.Success.Sprintf("Veil initialized for %s", root))
		_, _ = fmt.Fprintf(w, "  .env files processed:  %d\n", len(envPaths))
		_, _ = fmt.Fprintf(w, "  Secrets vaulted:       %d\n", secretsVaulted)
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintf(w, "%s\n", ui.Bold.Sprint("Next:"))
		_, _ = fmt.Fprintf(w, "  veil run claude     %s\n", ui.Muted.Sprint("# or your agent of choice"))
		_, _ = fmt.Fprintf(w, "  veil status         %s\n", ui.Muted.Sprint("# see what's protected"))
		_, _ = fmt.Fprintln(w)
		// If the user passed --path pointing OUTSIDE their current project,
		// the .veil/ they just installed will be invisible to `veil run`
		// from the cwd. Surface that asymmetry plus the uninstall escape
		// hatch so they can roll back without manually deleting state.
		warnIfRootOutsideCWD(w, root)
	}
	return nil
}

// runInitNoEnvFiles handles the "scanner found nothing to vault" branch of
// init. Users who manage secrets via shell profile, direnv, 1Password CLI, or
// any tool that injects env vars outside .env files still need a working
// project: a .veil/ state dir + master key so `veil add` works, plus a CA
// cert so `veil run` can MITM HTTPS. We do the same setup the happy path
// does (sans the per-secret loop) and end with a "Next:" block that points
// at `veil add` with a concrete example.
//
// --dry-run preserves its no-side-effects contract: no vault, no CA, no
// gitignore writes — only the message and the "Would create" notice from
// setupProxyCA.
func runInitNoEnvFiles(w io.Writer, root string, dryRun bool) error {
	_, _ = fmt.Fprintf(w, "no .env files found in %s\n", root)
	_, _ = fmt.Fprintln(w)

	if !dryRun {
		ks, err := buildKeystore()
		if err != nil {
			return wrapErr("keystore", err)
		}
		// Same passphrase preflight as the happy path; without this a
		// user on Linux without Secret Service would hit an opaque
		// ErrKeystoreUnavailable when CreateVault tries ks.Set().
		if err := announceFileBackedKeystore(w, ks); err != nil {
			return err
		}
		if _, err := vault.CreateVault(root, vault.NewID(), ks); err != nil {
			return wrapErr("creating vault", err)
		}
	}

	ui.Phase(w, "Setting up proxy...")
	if err := setupProxyCA(w, dryRun); err != nil {
		return err
	}

	if !dryRun {
		appendGitignore(w, root)
	}

	if dryRun {
		_, _ = fmt.Fprintf(w, "%s\n", ui.Success.Sprintf("Dry-run preview for %s — no changes made", root))
		_, _ = fmt.Fprintln(w)
		ui.Dim(w, "Re-run without --dry-run to apply these changes.")
		_, _ = fmt.Fprintln(w)
		return nil
	}

	_, _ = fmt.Fprintf(w, "%s\n", ui.Success.Sprintf("Veil initialized for %s", root))
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "%s\n", ui.Bold.Sprint("Next:"))
	_, _ = fmt.Fprintf(w, "  Use `veil add <NAME> --value-stdin --host <host>` to vault credentials not in .env files.\n")
	_, _ = fmt.Fprintf(w, "  Then run your tool with `veil run <command>` to inject them into outbound HTTPS.\n")
	_, _ = fmt.Fprintln(w)
	warnIfRootOutsideCWD(w, root)
	return nil
}

// warnIfRootOutsideCWD prints a yellow advisory when `veil init --path <dir>`
// landed at a directory outside the current project root. No-op when --path
// was not passed (the resolved root IS the cwd's project root by definition)
// or when the resolved root is a descendant of the cwd's project root.
func warnIfRootOutsideCWD(w io.Writer, resolvedRoot string) {
	if flagPath == "" {
		return
	}
	cwdRoot, err := config.FindProjectRoot(".")
	if err != nil {
		// No detectable cwd project root means the user is initializing
		// fresh from somewhere with no marker — they explicitly picked
		// where to install, and a "you went outside the project" notice
		// here would be misleading. Stay silent.
		return
	}
	absResolved, err := filepath.Abs(resolvedRoot)
	if err != nil {
		return
	}
	absCWD, err := filepath.Abs(cwdRoot)
	if err != nil {
		return
	}
	if absResolved == absCWD {
		return
	}
	rel, err := filepath.Rel(absCWD, absResolved)
	if err == nil && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
		// resolvedRoot is inside the cwd project — nothing to warn about.
		return
	}
	ui.FormatWarning(w,
		fmt.Sprintf("Initialized at %s, which is outside the current project root.", ui.RedactPath(absResolved)),
		fmt.Sprintf("To reverse this, run: veil uninstall --path %s", ui.RedactPath(absResolved)),
	)
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

// atomicWriteFile writes data to path via a temporary file and rename.
//
// Intentionally NOT migrated to vault.WriteFileNoFollow — this helper
// rewrites user .env files where Sync+Rename gives torn-write crash
// safety that WriteFileNoFollow does not. The H9 holes don't apply:
// CreateTemp uses a random suffix so the tmp path can't be symlink-pre-
// planted, POSIX rename(2) replaces a symlink at path with the renamed
// file itself rather than following it, and the new file inherits the
// tmp's 0600 mode so any pre-existing widened perms on path are
// discarded with the old inode.
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
