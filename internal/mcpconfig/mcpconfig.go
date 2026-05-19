// Package mcpconfig discovers, parses, and rewrites MCP configuration files
// for Claude Desktop, Claude Code, and Cursor (both user-global and
// project-local scope).
package mcpconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/getveil/veil/internal/envkeys"
)

// claudeDesktopUserLocation returns the platform-specific subpath of Claude
// Desktop's user-global config, or ok=false on unsupported platforms.
// Exposed for tests; production callers route through userLocations().
func claudeDesktopUserLocation() (parts []string, ok bool) {
	for _, loc := range userLocations() {
		if loc.Client != ClaudeDesktop || loc.Scope != UserScope {
			continue
		}
		parts = loc.subpath(runtime.GOOS)
		return parts, parts != nil
	}
	return nil, false
}

// Discover returns every user-global MCP config Veil should consider. The
// returned slice is empty (not an error) when no configs are found, when the
// platform is unsupported, or when VEIL_MCP_DISABLE_DISCOVERY is set.
//
// Backward compat: if VEIL_MCP_CONFIG_PATH is set, it replaces the Claude
// Desktop entry only — other clients (Claude Code, Cursor) are still probed.
func Discover() ([]DiscoveredConfig, error) {
	if os.Getenv(envkeys.MCPDisableDiscovery) != "" {
		return nil, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	override := os.Getenv(envkeys.MCPConfigOverride)
	var out []DiscoveredConfig

	for _, loc := range userLocations() {
		if loc.Client == ClaudeDesktop && override != "" {
			p, ok := resolveOverride(override)
			if ok {
				out = append(out, DiscoveredConfig{Path: p, Client: ClaudeDesktop, Scope: UserScope})
			}
			continue
		}
		sub := loc.subpath(runtime.GOOS)
		if sub == nil {
			continue
		}
		p := filepath.Join(append([]string{home}, sub...)...)
		info, err := os.Lstat(p)
		if err != nil || info.IsDir() {
			continue
		}
		out = append(out, DiscoveredConfig{Path: p, Client: loc.Client, Scope: UserScope})
	}
	return out, nil
}

// resolveOverride checks the VEIL_MCP_CONFIG_PATH value. Missing files (or
// directories) yield (_, false) so the caller drops the override and treats
// it as absent rather than surfacing an error.
func resolveOverride(p string) (string, bool) {
	info, err := os.Stat(p) // #nosec G304 G703 -- override is an opt-in test hook
	if err != nil || info.IsDir() {
		return "", false
	}
	return p, true
}

// ParentAnchors returns one anchor per user-scope location for the symlink
// guard. Override-pinned Claude Desktop is omitted (the user explicitly
// chose the path). Project-scope configs anchor at the project root and are
// walked by the existing project-side guard.
func ParentAnchors() ([]ParentAnchor, error) {
	if os.Getenv(envkeys.MCPDisableDiscovery) != "" {
		return nil, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	override := os.Getenv(envkeys.MCPConfigOverride)

	var out []ParentAnchor
	for _, loc := range userLocations() {
		if loc.Client == ClaudeDesktop && override != "" {
			continue
		}
		sub := loc.subpath(runtime.GOOS)
		if sub == nil {
			continue
		}
		out = append(out, ParentAnchor{
			Anchor:  home,
			Subpath: sub,
			Client:  loc.Client,
		})
	}
	return out, nil
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

// ConfigFile represents a parsed MCP config file.
type ConfigFile struct {
	path    string
	servers map[string]*ServerConfig

	// topLevel preserves all top-level keys for round-trip fidelity.
	// "mcpServers" is removed from this map and stored in servers.
	topLevel map[string]json.RawMessage
}

// Parse reads and parses the MCP config file at path.
func Parse(path string) (*ConfigFile, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from Discover(), not user input
	if err != nil {
		return nil, fmt.Errorf("mcpconfig: read %s: %w", path, err)
	}
	cfg, err := parseContent(data)
	if err != nil {
		return nil, fmt.Errorf("mcpconfig: parse %s: %w", path, err)
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
// Errors returned are bare (no "mcpconfig:" prefix) so callers can wrap with context.
func parseContent(data []byte) (*ConfigFile, error) {
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(data, &topLevel); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	servers := make(map[string]*ServerConfig)

	if raw, ok := topLevel["mcpServers"]; ok {
		var rawServers map[string]json.RawMessage
		if err := json.Unmarshal(raw, &rawServers); err != nil {
			return nil, fmt.Errorf("parse mcpServers: %w", err)
		}
		for name, rawServer := range rawServers {
			sc := &ServerConfig{}
			if err := json.Unmarshal(rawServer, sc); err != nil {
				return nil, fmt.Errorf("parse server %q: %w", name, err)
			}
			var allFields map[string]json.RawMessage
			if err := json.Unmarshal(rawServer, &allFields); err != nil {
				return nil, fmt.Errorf("parse server %q overflow: %w", name, err)
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

// SetArg replaces a positional arg value for a specific server. Out-of-range
// indices and unknown server names are no-ops so callers can pass through
// indices computed from the original args slice without separate bounds
// checks.
func (c *ConfigFile) SetArg(server string, index int, value string) {
	s, ok := c.servers[server]
	if !ok {
		return
	}
	if index < 0 || index >= len(s.Args) {
		return
	}
	s.Args[index] = value
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
