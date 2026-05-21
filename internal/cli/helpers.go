package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/envkeys"
	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
	"github.com/spf13/cobra"
)

// resolveRoot determines the project root directory from the --path flag
// or by searching upward from the current directory.
func resolveRoot() (string, error) {
	if flagPath != "" {
		return filepath.Abs(flagPath)
	}
	return config.FindProjectRoot(".")
}

// buildKeystore returns the appropriate Keystore for the current environment.
func buildKeystore() (vault.Keystore, error) {
	if ks, ok := maybeTestKeystore(); ok {
		return ks, nil
	}
	fallbackPath, err := config.KeystoreFallbackFile()
	if err != nil {
		return nil, err
	}
	return vault.AutoKeystore(fallbackPath), nil
}

// announceFileBackedKeystore inspects ks and, when it is the FileKeystore
// fallback, surfaces a user-visible notice before the first vault op. When
// VEIL_PASSPHRASE is unset this returns a cliError so the caller short-circuits
// with an actionable message — otherwise it prints an info note so the user
// knows they are running in the file-backed mode and continues.
func announceFileBackedKeystore(w io.Writer, ks vault.Keystore) error {
	if !vault.IsFileBacked(ks) {
		return nil
	}
	fallbackPath, perr := config.KeystoreFallbackFile()
	if perr != nil {
		// Best-effort: if we can't even resolve the fallback path, fall
		// through so the underlying open/save error still surfaces.
		fallbackPath = ""
	}
	dir := ui.RedactPath(filepath.Dir(fallbackPath))
	if dir == "" {
		dir = "~/.local/state/veil/"
	}
	if os.Getenv(envkeys.Passphrase) == "" {
		msg := fmt.Sprintf(
			"No system keyring found. Veil will use an age-encrypted key file at %s.",
			dir,
		)
		hint := fmt.Sprintf(
			"Set %s in your environment before running 'veil init' or 'veil run'.",
			envkeys.Passphrase,
		)
		ui.FormatWarning(w, msg, hint)
		return cliErrorWith(vault.ErrPassphraseMissing, msg, hint)
	}
	ui.Dim(w, fmt.Sprintf("Using file-backed keystore at %s", dir))
	return nil
}

// openVault opens the vault at the given project root, using the appropriate
// keystore (mem for tests, auto for production).
func openVault(root string) (*vault.Vault, error) {
	ks, err := buildKeystore()
	if err != nil {
		return nil, err
	}
	return vault.Open(root, ks)
}

// requireInitializedProject resolves the project root and verifies the
// project has been initialized. On success it returns the root. On failure
// it returns a cliError/cliErrorWith that has already been printed — the
// caller just propagates it. Use this in commands that operate on project
// state but don't need the vault opened (e.g. `veil run`).
func requireInitializedProject(_ *cobra.Command) (string, error) {
	root, err := resolveRoot()
	if err != nil {
		return "", cliError(err.Error(), "")
	}
	stateDir := config.ProjectStateDir(root)
	if info, statErr := os.Stat(stateDir); statErr != nil || !info.IsDir() {
		return "", cliErrorWith(ErrNotInitialized,
			"Veil is not initialized in this project",
			"Run `veil init` to get started.")
	}
	return root, nil
}

// withVault resolves the project root, opens the vault, and invokes fn with
// the resolved root and opened vault. Any error from the prologue is
// printed and returned as a cliError/wrapErr (exit-code classified). fn's
// error is returned unchanged so callers can decide whether to print.
// Use this in commands that need the vault (add, list, remove, status, log).
func withVault(cmd *cobra.Command, fn func(root string, v *vault.Vault) error) error {
	root, err := requireInitializedProject(cmd)
	if err != nil {
		return err
	}
	v, err := openVault(root)
	if err != nil {
		return wrapErr("opening vault", err)
	}
	return fn(root, v)
}

// MaybeTestKeystoreForTest is exported for tests that need to assert the
// build-tag behavior of maybeTestKeystore.
var MaybeTestKeystoreForTest = maybeTestKeystore
