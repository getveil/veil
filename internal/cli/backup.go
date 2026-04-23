package cli

import "os"

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
