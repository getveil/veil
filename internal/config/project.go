package config

import (
	"fmt"
	"os"
	"path/filepath"
)

func FindProjectRoot(start string) (string, error) {
	if !filepath.IsAbs(start) {
		abs, err := filepath.Abs(start)
		if err != nil {
			return "", err
		}
		start = abs
	}
	start = filepath.Clean(start)

	home, homeErr := os.UserHomeDir()
	if homeErr == nil {
		home = filepath.Clean(home)
	}

	cur := start
	for {
		if hasMarker(cur) {
			return cur, nil
		}
		if homeErr == nil && cur == home {
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}

	stop := home
	if homeErr != nil {
		stop = "/"
	}
	return "", fmt.Errorf("no project root found (looked for .git, .veil, or .env from %s up to %s)", start, stop)
}

func hasMarker(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return true
	}
	if info, err := os.Stat(filepath.Join(dir, ".veil")); err == nil && info.IsDir() {
		return true
	}
	if info, err := os.Stat(filepath.Join(dir, ".env")); err == nil && !info.IsDir() {
		return true
	}
	return false
}

func ProjectStateDir(root string) string {
	return filepath.Join(root, ".veil")
}

func VaultFile(root string) string {
	return filepath.Join(ProjectStateDir(root), "vault.bin")
}

func VaultBackupFile(root string) string {
	return filepath.Join(ProjectStateDir(root), "vault.bin.bak")
}

func VaultMetaFile(root string) string {
	return filepath.Join(ProjectStateDir(root), "vault.meta")
}

func AuditDBFile(root string) string {
	return filepath.Join(ProjectStateDir(root), "audit.sqlite")
}

func VaultGitignoreFile(root string) string {
	return filepath.Join(ProjectStateDir(root), ".gitignore")
}
