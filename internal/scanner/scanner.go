// Package scanner discovers and parses .env files in a project root.
package scanner

import (
	"path/filepath"

	"github.com/getveil/veil/internal/mcpconfig"
)

// Scan discovers .env files anywhere beneath root. The walk honors a
// hardcoded baseline of excluded directories (node_modules, .git, .veil,
// vendor, target, dist, build, .next, .nuxt, .turbo, .cache, .pnpm-store,
// .yarn) and skips symlinked directories without descending. Symlinked
// .env files ARE included so the action layer can refuse them explicitly.
//
// Returns absolute paths sorted alphabetically. An empty slice is returned
// when no files are found.
func Scan(root string) ([]string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	res, err := walkProject(abs)
	if err != nil {
		return nil, err
	}
	if res.envPaths == nil {
		return []string{}, nil
	}
	return res.envPaths, nil
}

// ScanResult is the bundle of files the recursive walker found.
type ScanResult struct {
	EnvPaths   []string                     // sorted absolute paths to .env / .env.* files
	MCPConfigs []mcpconfig.DiscoveredConfig // project-scoped MCP configs (Scope = ProjectScope)
}

// ScanAll discovers every .env file and every project-local MCP config in
// one walk of root. Both lists are sorted alphabetically by path.
func ScanAll(root string) (ScanResult, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return ScanResult{}, err
	}
	res, err := walkProject(abs)
	if err != nil {
		return ScanResult{}, err
	}
	if res.envPaths == nil {
		res.envPaths = []string{}
	}
	if res.mcpConfigs == nil {
		res.mcpConfigs = []mcpconfig.DiscoveredConfig{}
	}
	return ScanResult{EnvPaths: res.envPaths, MCPConfigs: res.mcpConfigs}, nil
}
