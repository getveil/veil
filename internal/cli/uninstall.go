package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/mcpconfig"
	"github.com/8enji/veil/internal/scanner"
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

	mcpPath, err := mcpconfigDiscover()
	if err != nil {
		return nil, fmt.Errorf("discovering MCP config: %w", err)
	}
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

// classification enumerates how a (current, backup) pair relates.
type classification int

const (
	classUnmodified classification = iota
	classModified
	classOriginalMissing
)

// placeholderResolver maps a placeholder string to its real value.
// An empty / nil resolver means "we cannot substitute" — classification
// falls back to byte comparison only.
type placeholderResolver map[string]string

// classifyEnvPair compares the current .env file to its backup after
// reverse-substituting placeholders with real values. Returns:
//   - classUnmodified: after substitution, bytes match the backup.
//   - classModified: bytes differ. The returned string is a unified diff
//     between the (substitution-applied) current file and the backup.
//   - classOriginalMissing: current file does not exist on disk.
func classifyEnvPair(original, backup string, resolver placeholderResolver) (classification, string, error) {
	backupBytes, err := os.ReadFile(backup) // #nosec G304
	if err != nil {
		return 0, "", fmt.Errorf("read backup %s: %w", backup, err)
	}
	currentBytes, err := os.ReadFile(original) // #nosec G304
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return classOriginalMissing, "", nil
		}
		return 0, "", fmt.Errorf("read %s: %w", original, err)
	}

	expected := expectedOriginalEnv(currentBytes, resolver)
	if bytes.Equal(expected, backupBytes) {
		return classUnmodified, "", nil
	}
	return classModified, renderUnifiedDiff(backupBytes, expected), nil
}

// expectedOriginalEnv parses current as a .env file and replaces each
// KV-line's value with the real value from resolver when the current value
// is a known placeholder. Returns the reconstructed bytes via
// scanner.EnvFile.Bytes() so formatting is preserved.
func expectedOriginalEnv(current []byte, resolver placeholderResolver) []byte {
	envFile := scanner.ParseBytes(current)
	if resolver != nil {
		for _, line := range envFile.Lines {
			if line.Kind != scanner.KVLine {
				continue
			}
			if real, ok := resolver[line.Value]; ok {
				envFile.SetValue(line.Key, real)
			}
		}
	}
	return envFile.Bytes()
}

// renderUnifiedDiff produces a minimal unified diff between a and b.
// Task 4.5 replaces this stub with the full implementation.
func renderUnifiedDiff(a, b []byte) string {
	if bytes.Equal(a, b) {
		return ""
	}
	return fmt.Sprintf("--- backup\n+++ current\n- %d bytes\n+ %d bytes\n", len(a), len(b))
}
