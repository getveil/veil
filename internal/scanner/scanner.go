// Package scanner discovers and parses .env files in a project root.
package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
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
func Scan(root string, ignorePatterns ...string) ([]string, error) {
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
		if isIgnored(name, ignorePatterns) {
			continue
		}
		p := filepath.Join(root, name)
		info, err := os.Stat(p)
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

// isIgnored returns true if the relPath matches any of the provided glob patterns.
func isIgnored(relPath string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := doublestar.Match(pattern, relPath)
		if err != nil {
			continue
		}
		if matched {
			return true
		}
	}
	return false
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
