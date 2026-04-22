// Package mcpconfig discovers, parses, and rewrites Claude Desktop MCP configuration files.
package mcpconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/8enji/veil/internal/envkeys"
)

const configFileName = "claude_desktop_config.json"

// Discover returns the path to Claude Desktop's MCP config file, or "" if not found.
// If envkeys.MCPConfigOverride is set, it is used instead (for testing).
func Discover() (string, error) {
	if override := os.Getenv(envkeys.MCPConfigOverride); override != "" {
		info, err := os.Stat(override) // #nosec G304 G703 -- override is an opt-in test hook
		if err != nil {
			return "", nil
		}
		if info.IsDir() {
			return "", nil
		}
		return override, nil
	}

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
		return "", fmt.Errorf("unsupported platform: %s", goos)
	}
}

// ServerConfig represents a single MCP server entry.
type ServerConfig struct {
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`

	// hasEnv tracks whether "env" was present in the original JSON,
	// so Bytes() can preserve "env": {} on round-trip.
	hasEnv bool

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
	cfg, err := parseContent(data)
	if err != nil {
		return nil, err
	}
	cfg.path = path
	return cfg, nil
}

// ParseBytes parses an MCP config from a byte slice. Behaves identically
// to Parse modulo the I/O step. The returned ConfigFile has no path set.
func ParseBytes(data []byte) (*ConfigFile, error) {
	return parseContent(data)
}

// parseContent contains the JSON parsing logic shared by Parse and ParseBytes.
func parseContent(data []byte) (*ConfigFile, error) {
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(data, &topLevel); err != nil {
		return nil, fmt.Errorf("mcpconfig: parse: %w", err)
	}

	servers := make(map[string]*ServerConfig)

	if raw, ok := topLevel["mcpServers"]; ok {
		var rawServers map[string]json.RawMessage
		if err := json.Unmarshal(raw, &rawServers); err != nil {
			return nil, fmt.Errorf("mcpconfig: parse mcpServers: %w", err)
		}
		for name, rawServer := range rawServers {
			sc := &ServerConfig{}
			if err := json.Unmarshal(rawServer, sc); err != nil {
				return nil, fmt.Errorf("mcpconfig: parse server %q: %w", name, err)
			}
			var allFields map[string]json.RawMessage
			if err := json.Unmarshal(rawServer, &allFields); err != nil {
				return nil, fmt.Errorf("mcpconfig: parse server %q overflow: %w", name, err)
			}
			_, sc.hasEnv = allFields["env"]
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
		servers:  servers,
		topLevel: topLevel,
	}, nil
}

// Servers returns the MCP server configurations.
func (c *ConfigFile) Servers() map[string]*ServerConfig {
	return c.servers
}

// SetEnvValue replaces an env var value for a specific server.
func (c *ConfigFile) SetEnvValue(server, key, value string) {
	if s, ok := c.servers[server]; ok {
		s.Env[key] = value
	}
}

// Bytes serializes the config back to formatted JSON.
// Uses 2-space indentation to match Claude Desktop's formatting.
func (c *ConfigFile) Bytes() ([]byte, error) {
	// Rebuild the top-level map with the modified mcpServers.
	out := make(map[string]json.RawMessage, len(c.topLevel))
	for k, v := range c.topLevel {
		if k == "mcpServers" {
			continue
		}
		out[k] = v
	}

	// Serialize mcpServers with overflow fields preserved.
	// Always emit mcpServers if it was present in the original, even if empty.
	if _, hadServers := c.topLevel["mcpServers"]; hadServers {
		serversMap := make(map[string]json.RawMessage, len(c.servers))
		for name, sc := range c.servers {
			serverBytes, err := marshalServer(sc)
			if err != nil {
				return nil, fmt.Errorf("mcpconfig: marshal server %q: %w", name, err)
			}
			serversMap[name] = serverBytes
		}
		raw, err := json.Marshal(serversMap)
		if err != nil {
			return nil, fmt.Errorf("mcpconfig: marshal mcpServers: %w", err)
		}
		out["mcpServers"] = raw
	}

	// Use an encoder with HTML escaping disabled.
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return nil, fmt.Errorf("mcpconfig: encode config: %w", err)
	}
	return buf.Bytes(), nil
}

// marshalServer produces JSON for a server config, merging known fields with overflow.
// Fields are emitted in conventional order (command, args, env) followed by overflow.
func marshalServer(sc *ServerConfig) (json.RawMessage, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')

	first := true
	writeKey := func(key string, val json.RawMessage) {
		if !first {
			buf.WriteByte(',')
		}
		first = false
		k, _ := json.Marshal(key)
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(val)
	}

	// Known fields in conventional order.
	raw, err := json.Marshal(sc.Command)
	if err != nil {
		return nil, err
	}
	writeKey("command", raw)

	if len(sc.Args) > 0 {
		raw, err = json.Marshal(sc.Args)
		if err != nil {
			return nil, err
		}
		writeKey("args", raw)
	}

	if len(sc.Env) > 0 || sc.hasEnv {
		raw, err = json.Marshal(sc.Env)
		if err != nil {
			return nil, err
		}
		writeKey("env", raw)
	}

	// Overflow fields (unknown fields from original JSON).
	for k, v := range sc.overflow {
		writeKey(k, v)
	}

	buf.WriteByte('}')
	return buf.Bytes(), nil
}
