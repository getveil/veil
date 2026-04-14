// Package config resolves per-user and per-project filesystem paths for Veil.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func CADir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return caDir(runtime.GOOS, home, os.Getenv("XDG_DATA_HOME"))
}

func CAFile() (string, error) {
	dir, err := CADir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "root.pem"), nil
}

func CAKeyFile() (string, error) {
	dir, err := CADir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "root.key"), nil
}

func KeystoreFallbackFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return keystoreFallback(runtime.GOOS, home, os.Getenv("XDG_STATE_HOME"))
}

func EnsureDir(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

func caDir(goos, home, xdgData string) (string, error) {
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "veil", "ca"), nil
	case "linux":
		if xdgData != "" && filepath.IsAbs(xdgData) {
			return filepath.Join(xdgData, "veil", "ca"), nil
		}
		return filepath.Join(home, ".local", "share", "veil", "ca"), nil
	default:
		return "", fmt.Errorf("unsupported GOOS: %s", goos)
	}
}

func keystoreFallback(goos, home, xdgState string) (string, error) {
	switch goos {
	case "darwin", "linux":
		if xdgState != "" && filepath.IsAbs(xdgState) {
			return filepath.Join(xdgState, "veil", "master.key.age"), nil
		}
		return filepath.Join(home, ".local", "state", "veil", "master.key.age"), nil
	default:
		return "", fmt.Errorf("unsupported GOOS: %s", goos)
	}
}

// PidFile returns the per-session pidfile path for the given PID. Each
// concurrent veil run writes its own file (proxy-<pid>.pid) so multiple
// sessions in the same project do not collide.
func PidFile(root string, pid int) string {
	return filepath.Join(ProjectStateDir(root), fmt.Sprintf("proxy-%d.pid", pid))
}

// PidFileGlob returns the glob pattern (suitable for filepath.Glob) that
// matches every per-session pidfile in the project state directory.
func PidFileGlob(root string) string {
	return filepath.Join(ProjectStateDir(root), "proxy-*.pid")
}
