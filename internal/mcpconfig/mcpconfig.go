// Package mcpconfig discovers, parses, and rewrites Claude Desktop MCP configuration files.
package mcpconfig

import (
	"os"
	"path/filepath"
	"runtime"
)

const configFileName = "claude_desktop_config.json"

// Discover returns the path to Claude Desktop's MCP config file, or "" if not found.
func Discover() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir, err := claudeConfigDir(runtime.GOOS, home)
	if err != nil {
		return "", nil // unsupported platform — not an error, just no config
	}
	return discoverIn(dir)
}

// discoverIn checks whether claude_desktop_config.json exists in dir.
// Exported for testing with controlled paths.
func discoverIn(dir string) (string, error) {
	p := filepath.Join(dir, configFileName)
	info, err := os.Stat(p)
	if err != nil {
		return "", nil // file doesn't exist
	}
	if info.IsDir() {
		return "", nil
	}
	return p, nil
}

// claudeConfigDir returns the platform-specific Claude Desktop config directory.
func claudeConfigDir(goos, home string) (string, error) {
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude"), nil
	case "linux":
		return filepath.Join(home, ".config", "Claude"), nil
	default:
		return "", nil
	}
}
