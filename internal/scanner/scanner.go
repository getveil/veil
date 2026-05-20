// Package scanner discovers and parses .env files in a project root.
package scanner

import (
	"path/filepath"
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
	paths, err := walkProject(abs)
	if err != nil {
		return nil, err
	}
	if paths == nil {
		return []string{}, nil
	}
	return paths, nil
}
