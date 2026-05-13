// Package scanner discovers and parses .env files in a project root.
package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// curatedNames is the list of .env file basenames we look for.
var curatedNames = []string{
	".env",
	".env.local",
	".env.development",
	".env.production",
}

// excludeSuffixes lists suffixes that mark a file as an example/sample.
var excludeSuffixes = []string{
	".example",
	".sample",
}

// Scan discovers .env files in root by checking a curated list of names.
// It returns absolute paths sorted alphabetically. Files matching example/sample
// patterns are excluded. If no files are found, an empty slice is returned.
//
// Uses os.Lstat (not os.Stat) so symlinks are reported as symlinks rather than
// silently followed. Symlinks ARE included in the result set — it is the
// caller's job to refuse them at the action layer, so the user sees a clear
// error instead of having their symlink replaced and cleartext materialized
// into the project tree.
func Scan(root string) ([]string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	root = abs
	var found []string
	for _, name := range curatedNames {
		if isExcluded(name) {
			continue
		}
		p := filepath.Join(root, name)
		info, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		found = append(found, p)
	}
	sort.Strings(found)
	if found == nil {
		found = []string{}
	}
	return found, nil
}

// isExcluded returns true if the name matches an exclusion pattern.
func isExcluded(name string) bool {
	for _, suffix := range excludeSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
