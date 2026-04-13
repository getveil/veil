package runner

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// WritePidFile writes the given PID to path.
func WritePidFile(path string, pid int) error {
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", pid)), 0600)
}

// ReadPidFile reads and parses the PID from a pid file.
func ReadPidFile(path string) (int, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid pid file: %w", err)
	}
	return pid, nil
}

// RemovePidFile removes the pid file at path. Errors are ignored.
func RemovePidFile(path string) {
	_ = os.Remove(path)
}

// IsProcessAlive checks if a process with the given PID is running.
func IsProcessAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. Send signal 0 to check liveness.
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}
