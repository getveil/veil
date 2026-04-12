// Package mcpconfig discovers, parses, and rewrites Claude Desktop MCP configuration files.
package mcpconfig

import (
	"encoding/json"
	"fmt"
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

// ServerConfig represents a single MCP server entry.
type ServerConfig struct {
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`

	// overflow captures unknown JSON fields for round-trip fidelity.
	overflow map[string]json.RawMessage
}

// ConfigFile represents a parsed Claude Desktop configuration file.
type ConfigFile struct {
	path    string
	servers map[string]*ServerConfig

	// topLevel preserves all top-level keys for round-trip fidelity.
	// "mcpServers" is removed from this map and stored in servers.
	topLevel map[string]json.RawMessage
}

// Parse reads and parses the Claude Desktop config file at path.
func Parse(path string) (*ConfigFile, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from Discover(), not user input
	if err != nil {
		return nil, fmt.Errorf("mcpconfig: read %s: %w", path, err)
	}

	// Parse top-level as raw messages to preserve unknown keys.
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(data, &topLevel); err != nil {
		return nil, fmt.Errorf("mcpconfig: parse %s: %w", path, err)
	}

	servers := make(map[string]*ServerConfig)

	if raw, ok := topLevel["mcpServers"]; ok {
		// Parse each server as raw message first, then decode known fields.
		var rawServers map[string]json.RawMessage
		if err := json.Unmarshal(raw, &rawServers); err != nil {
			return nil, fmt.Errorf("mcpconfig: parse mcpServers: %w", err)
		}

		for name, rawServer := range rawServers {
			sc := &ServerConfig{}
			if err := json.Unmarshal(rawServer, sc); err != nil {
				return nil, fmt.Errorf("mcpconfig: parse server %q: %w", name, err)
			}

			// Capture overflow: all fields that aren't command/args/env.
			var allFields map[string]json.RawMessage
			if err := json.Unmarshal(rawServer, &allFields); err != nil {
				return nil, fmt.Errorf("mcpconfig: parse server %q overflow: %w", name, err)
			}
			delete(allFields, "command")
			delete(allFields, "args")
			delete(allFields, "env")
			if len(allFields) > 0 {
				sc.overflow = allFields
			}

			if sc.Env == nil {
				sc.Env = make(map[string]string)
			}
			servers[name] = sc
		}
	}

	return &ConfigFile{
		path:     path,
		servers:  servers,
		topLevel: topLevel,
	}, nil
}

// Servers returns the MCP server configurations.
func (c *ConfigFile) Servers() map[string]*ServerConfig {
	return c.servers
}
