package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/getveil/veil/internal/vault"
)

// backupSuffix is appended to the original path to form the backup path.
const backupSuffix = ".veil-backup"

// backupExists reports whether src has a sibling backup file.
func backupExists(src string) bool {
	_, err := os.Stat(src + backupSuffix)
	return err == nil
}

// writeBackup copies src to src+".veil-backup" at mode 0600. Overwrites an
// existing regular-file backup. Refuses a pre-existing symlink backup via
// O_NOFOLLOW (returns ELOOP), so a hostile clone shipping a `.env.veil-backup`
// symlink pointing at e.g. ~/.ssh/authorized_keys cannot redirect the
// cleartext write — the project .gitignore is only updated at the end of
// init, so the malicious symlink would otherwise reach this write.
func writeBackup(src string) error {
	data, err := os.ReadFile(src) // #nosec G304 -- src is a vaulted project file path
	if err != nil {
		return err
	}
	backupPath := src + backupSuffix
	// O_NOFOLLOW closes the TOCTOU window an Lstat+Write pair would leave.
	f, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- derived backup path
	if err != nil {
		return fmt.Errorf("opening backup %s: %w", backupPath, err)
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	return f.Close()
}

// registerVaultedFile records src in the project's vault.meta registry
// (under the given kind). It does not touch the .veil-backup sidecar.
func registerVaultedFile(root, src string, kind vault.FileKind) error {
	return vault.AddVaultedFile(root, src, kind)
}

// recordVaultedBackup writes src's backup AND registers src's absolute path
// in vault.meta so uninstall can locate it even when src is outside root.
// The kind is stored so uninstall picks the right classifier without
// re-deriving from the basename.
func recordVaultedBackup(root, src string, kind vault.FileKind) error {
	if err := writeBackup(src); err != nil {
		return err
	}
	return registerVaultedFile(root, src, kind)
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
	for _, entry := range registered {
		if entry.Path == abs {
			return false, nil
		}
	}
	return true, nil
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
