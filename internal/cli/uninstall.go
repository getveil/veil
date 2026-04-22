package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/mcpconfig"
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

// backupKind classifies a backup pair by the kind of file it covers.
type backupKind int

const (
	backupKindEnv backupKind = iota
	backupKindMCP
)

// backupPair pairs an original file path with its backup. Either may be
// missing on disk at discovery time; classification runs later.
type backupPair struct {
	original string
	backup   string
	kind     backupKind
}

// envCuratedNames mirrors scanner.curatedNames. Kept local to avoid
// exporting scanner internals; the list changes rarely.
var envCuratedNames = []string{
	".env",
	".env.local",
	".env.development",
	".env.production",
}

// discoverBackups returns every (original, backup) pair that uninstall
// should consider. For .env files: iterates curatedNames, returns a pair
// when either the original or the backup exists. For MCP: consults
// mcpconfig.Discover() and returns a pair only if the MCP backup exists.
func discoverBackups(root string) ([]backupPair, error) {
	var pairs []backupPair
	for _, name := range envCuratedNames {
		orig := filepath.Join(root, name)
		backup := orig + backupSuffix
		_, origErr := os.Stat(orig)
		_, backErr := os.Stat(backup)
		if origErr != nil && backErr != nil {
			continue
		}
		pairs = append(pairs, backupPair{original: orig, backup: backup, kind: backupKindEnv})
	}

	mcpPath, _ := mcpconfigDiscover()
	if mcpPath != "" {
		if _, err := os.Stat(mcpPath + backupSuffix); err == nil {
			pairs = append(pairs, backupPair{
				original: mcpPath,
				backup:   mcpPath + backupSuffix,
				kind:     backupKindMCP,
			})
		}
	}
	return pairs, nil
}

// mcpconfigDiscover wraps mcpconfig.Discover so tests can observe the seam
// without importing the package into the uninstall_test package.
var mcpconfigDiscover = func() (string, error) { return mcpconfig.Discover() }
