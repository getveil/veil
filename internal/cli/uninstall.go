package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/8enji/veil/internal/config"
)

// activeProxyPIDs returns the list of PIDs from proxy-*.pid files that
// correspond to live processes. Dead PIDs and unreadable files are ignored.
func activeProxyPIDs(root string) ([]int, error) {
	matches, err := filepath.Glob(config.PidFileGlob(root))
	if err != nil {
		return nil, err
	}
	var live []int
	for _, p := range matches {
		pid, ok := readPIDFile(p)
		if !ok {
			continue
		}
		if isProcessAlive(pid) {
			live = append(live, pid)
		}
	}
	return live, nil
}

// readPIDFile reads a pidfile and returns the integer PID. Returns false
// if the file cannot be read or does not contain a parseable integer.
func readPIDFile(path string) (int, bool) {
	data, err := os.ReadFile(path) // #nosec G304 -- pidfile path derived from state dir glob
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// isProcessAlive reports whether a process with the given PID exists.
// Uses signal 0 (no-op signal) to test existence without affecting the
// target. Returns false on permission errors as well — if we can't signal
// it, we can't safely claim it's live.
func isProcessAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// ESRCH (no such process) → dead. Other errors (EPERM) treat as dead too
	// because we can't confirm liveness; conservative for uninstall purposes
	// where a stale pidfile shouldn't block cleanup.
	return false
}

// formatPIDList formats a slice of PIDs for error messages.
func formatPIDList(pids []int) string {
	parts := make([]string, len(pids))
	for i, p := range pids {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ", ")
}
