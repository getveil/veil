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

// writeBackup copies src to src+".veil-backup" at mode 0600. If the backup
// already exists as a regular file it is overwritten. If it exists as a
// symlink the open fails with ELOOP and writeBackup returns an error — a
// hostile cloned repo that pre-plants a `.env.veil-backup` symlink (pointing
// at e.g. ~/.ssh/authorized_keys) would otherwise have the cleartext .env
// silently redirected to the symlink target by os.WriteFile, since the
// project's .gitignore — which lists *.veil-backup — is only written at the
// end of init.
func writeBackup(src string) error {
	data, err := os.ReadFile(src) // #nosec G304 -- src is a vaulted project file path
	if err != nil {
		return err
	}
	backupPath := src + backupSuffix
	// O_NOFOLLOW makes open(2) fail with ELOOP if backupPath is a symlink,
	// closing the TOCTOU window between an Lstat+Write pair.
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

// writeBackupOnly creates the .veil-backup sidecar for src. No metadata
// registration is performed; callers must invoke registerVaultedFile to
// record the file in vault.meta as a separate step.
func writeBackupOnly(src string) error {
	return writeBackup(src)
}

// registerVaultedFile records src in the project's vault.meta registry
// (under the given kind). It does not touch the .veil-backup sidecar.
func registerVaultedFile(root, src string, kind vault.FileKind) error {
	return vault.AddVaultedFile(root, src, kind)
}

// recordVaultedBackup writes src's backup AND registers src's absolute path
// in vault.meta so uninstall can locate it even when src is outside root.
// Registry-write failures are returned (not just logged) — losing track of a
// vaulted file is the bug we're trying to prevent. The kind is stored so
// uninstall picks the right classifier without re-deriving from the basename.
func recordVaultedBackup(root, src string, kind vault.FileKind) error {
	if err := writeBackupOnly(src); err != nil {
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
// vaulting pass operates on the original (pre-Veil) bytes, then removes the
// backup so init's own writeBackup can re-create it from the now-correct
// source. Refuses if the backup is a symlink: os.Rename renames the symlink
// itself, so a pre-planted .env.veil-backup symlink would replace the real
// .env with a symlink pointing at an attacker-chosen target, after which the
// next writeBackup/atomicWriteFile pair would leak/clobber that target's
// content. The leaf-symlink check on src happens earlier in refuseSymlinked-
// Inputs; this one closes the same hole on the backup path.
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
