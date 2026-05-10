package cli

import (
	"os"
	"path/filepath"

	"github.com/8enji/veil/internal/vault"
)

// backupSuffix is appended to the original path to form the backup path.
const backupSuffix = ".veil-backup"

// backupExists reports whether src has a sibling backup file.
func backupExists(src string) bool {
	_, err := os.Stat(src + backupSuffix)
	return err == nil
}

// writeBackup copies src to src+".veil-backup" at mode 0600. If the backup
// already exists, it is overwritten. Returns an error if src cannot be read
// or the backup cannot be written.
func writeBackup(src string) error {
	data, err := os.ReadFile(src) // #nosec G304 -- src is a vaulted project file path
	if err != nil {
		return err
	}
	return os.WriteFile(src+backupSuffix, data, 0600) // #nosec G304 G306 -- derived backup path
}

// recordVaultedBackup writes src's backup AND registers src's absolute path
// in vault.meta so uninstall can locate it even when src is outside root.
// Registry-write failures are returned (not just logged) — losing track of a
// vaulted file is the bug we're trying to prevent.
func recordVaultedBackup(root, src string) error {
	if err := writeBackup(src); err != nil {
		return err
	}
	return vault.AddVaultedFile(root, src)
}

// isOrphanedBackup reports whether src has a .veil-backup that is NOT
// registered in the current project's vault.meta. An orphan signals that the
// file was vaulted by a previous Veil install (whose registry was wiped or
// never written) — its backup, not the current placeholder-filled file, is
// the true pre-Veil state.
func isOrphanedBackup(root, src string) (bool, error) {
	if !backupExists(src) {
		return false, nil
	}
	abs, err := filepath.Abs(src)
	if err != nil {
		return false, err
	}
	registered, err := vault.ReadVaultedFiles(root)
	if err != nil {
		return false, err
	}
	for _, p := range registered {
		if p == abs {
			return false, nil
		}
	}
	return true, nil
}

// reclaimOrphanedBackup restores src from its orphan backup so the next
// vaulting pass operates on the original (pre-Veil) bytes, then removes the
// backup so init's own writeBackup can re-create it from the now-correct
// source.
func reclaimOrphanedBackup(src string) error {
	return os.Rename(src+backupSuffix, src)
}
