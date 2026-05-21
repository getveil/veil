package cli

import (
	"fmt"
	"os"

	"github.com/getveil/veil/internal/placeholder"
	"github.com/getveil/veil/internal/scanner"
	"github.com/getveil/veil/internal/vault"
)

// backupSuffix is appended to the original path to form the backup path.
const backupSuffix = ".veil-backup"

// backupExists reports whether src has a sibling backup file.
func backupExists(src string) bool {
	_, err := os.Stat(src + backupSuffix)
	return err == nil
}

// writeBackup copies src to src+".veil-backup" at mode 0600. The write goes
// through vault.WriteFileNoFollow, which fails with ELOOP if backupPath is a
// symlink — a hostile cloned repo that pre-plants a `.env.veil-backup`
// symlink (pointing at e.g. ~/.ssh/authorized_keys) would otherwise have
// the cleartext .env silently redirected to the symlink target by
// os.WriteFile, since the project's .gitignore — which lists *.veil-backup
// — is only written at the end of init. The helper also fchmods to 0600
// even when the backup pre-exists with widened perms.
func writeBackup(src string) error {
	data, err := os.ReadFile(src) // #nosec G304 -- src is a vaulted project file path
	if err != nil {
		return err
	}
	backupPath := src + backupSuffix
	if err := vault.WriteFileNoFollow(backupPath, data, 0o600); err != nil {
		return fmt.Errorf("opening backup %s: %w", backupPath, err)
	}
	return nil
}

// isOrphanByContent reports whether src has a .veil-backup AND its current
// content carries Veil-shaped placeholder values that the active vault does
// not own. That pattern means a prior Veil install vaulted the file but its
// vault state is gone (different vault root, wiped .veil/, etc.) — the
// backup, not the stale placeholders, is the true pre-Veil state.
//
// Heuristic discriminator (replaces the vault.meta vaulted-files registry
// dropped in the launch cuts): for each secret-like line in src, ask whether
// its value contains the Veil sentinel ("VEIL") AND whether the current
// vault carries it as a placeholder. A sentinel value that no current
// credential owns is the signal that the placeholders came from a different
// install. When every sentinel-bearing value is owned by v, the file is the
// output of THIS vault's prior successful init — not an orphan.
//
// Returns false for files with no backup, no secret-like lines, or no
// sentinel-bearing values (i.e. a regular cleartext .env that happens to
// have a backup sidecar).
func isOrphanByContent(v *vault.Vault, src string) (bool, error) {
	if !backupExists(src) {
		return false, nil
	}
	envFile, err := scanner.ParseFile(src)
	if err != nil {
		return false, err
	}
	knownPHs := v.PlaceholderSet()
	for _, line := range envFile.Lines {
		if line.Kind != scanner.KVLine {
			continue
		}
		if !placeholder.IsSecretLike(line.Key, line.Value) {
			continue
		}
		if !placeholder.ContainsSentinel(line.Value) {
			continue
		}
		if _, owned := knownPHs[line.Value]; !owned {
			return true, nil
		}
	}
	return false, nil
}

// reclaimOrphanedBackup restores src from its orphan backup so the next
// vaulting pass operates on the original (pre-Veil) bytes. Refuses a
// symlinked backup: rename(2) renames the link itself, which would replace
// the real .env with a symlink to an attacker-chosen target — leaking or
// clobbering it on the next writeBackup/atomicWriteFile pair.
func reclaimOrphanedBackup(src string) error {
	backupPath := src + backupSuffix
	info, err := os.Lstat(backupPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to reclaim symlinked backup %s — remove it and re-run init", backupPath)
	}
	return os.Rename(backupPath, src)
}
