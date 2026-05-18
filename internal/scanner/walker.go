package scanner

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// baselineExcludeDirs is the set of directory basenames the walker always
// skips, regardless of .gitignore presence. Source-tree noise that never
// holds project secrets.
var baselineExcludeDirs = map[string]struct{}{
	".git":         {},
	".veil":        {},
	"node_modules": {},
	"vendor":       {},
	"target":       {},
	"dist":         {},
	"build":        {},
	".next":        {},
	".nuxt":        {},
	".turbo":       {},
	".cache":       {},
	".pnpm-store":  {},
	".yarn":        {},
}

// envFileExcludeSuffixes lists suffixes that mark an .env file as an
// example/sample/template — never a real secret-bearing file. Also excludes
// `.veil-backup`, Veil's own sidecar: a `.env.veil-backup` is the byte-
// faithful original of the adjacent placeholder `.env` and is handled by
// the backup/recovery code path, not the regular scan.
var envFileExcludeSuffixes = []string{
	".example",
	".sample",
	".template",
	".dist",
	".veil-backup",
}

// matchesEnvBasename reports whether name is `.env` or `.env.<anything>`
// excluding the example/sample/template/dist suffix family. Trailing matches
// like `.env.local.example` are excluded.
func matchesEnvBasename(name string) bool {
	if name != ".env" && !strings.HasPrefix(name, ".env.") {
		return false
	}
	for _, suf := range envFileExcludeSuffixes {
		if strings.HasSuffix(name, suf) {
			return false
		}
	}
	return true
}

// walkResult collects everything the walker discovered in one pass.
type walkResult struct {
	envPaths []string
}

// walkProject performs the recursive walk from root, returning every .env-
// shaped file (basename match) found beneath, sorted alphabetically.
//
// Directory pruning:
//   - baseline excludes (node_modules, .git, etc.) always apply.
//   - symlinked directories are silently skipped (no descent).
//
// Symlinked files are returned in the result set so the existing leaf-
// symlink refusal gate surfaces an explicit error to the user.
func walkProject(root string) (walkResult, error) {
	var res walkResult

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			if _, skip := baselineExcludeDirs[d.Name()]; skip {
				return fs.SkipDir
			}
			return nil
		}
		// filepath.WalkDir does not follow symbolic links: a symlinked
		// directory arrives here with d.IsDir()==false and d.Type() carrying
		// ModeSymlink. We never descend into the link target. If the link's
		// basename happens to match an env pattern below, the leaf symlink
		// gets returned and the existing refuseSymlinkedInputs gate at the
		// action layer surfaces an explicit error.
		if !matchesEnvBasename(d.Name()) {
			return nil
		}
		res.envPaths = append(res.envPaths, path)
		return nil
	})
	if err != nil {
		return walkResult{}, err
	}

	sort.Strings(res.envPaths)
	return res, nil
}
