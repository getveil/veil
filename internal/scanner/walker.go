package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	gitignore "github.com/sabhiram/go-gitignore"

	"github.com/getveil/veil/internal/mcpconfig"
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
	envPaths   []string
	mcpConfigs []mcpconfig.DiscoveredConfig
}

// gitignoreStack tracks per-directory .gitignore matchers, applied from root
// downward. Each entry's Dir is the directory that owns the .gitignore; its
// patterns apply to that directory and below.
type gitignoreStack []gitignoreEntry

type gitignoreEntry struct {
	Dir     string
	Matcher *gitignore.GitIgnore
}

// loadGitignore returns the matcher for the .gitignore file in dir, or nil
// if absent / unreadable.
func loadGitignore(dir string) *gitignore.GitIgnore {
	p := filepath.Join(dir, ".gitignore")
	info, err := os.Lstat(p)
	if err != nil || info.IsDir() {
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Refuse to read a symlinked .gitignore — a hostile project could
		// point it at an attacker file. Treat as absent.
		return nil
	}
	matcher, err := gitignore.CompileIgnoreFile(p)
	if err != nil {
		return nil
	}
	return matcher
}

// matchesDir reports whether path (a directory) is ignored by any matcher
// in the stack. A trailing slash is appended before matching so patterns
// like "dir/" (directory-only in gitignore semantics) prune at descent
// time rather than at the leaf, avoiding wasted traversal of large
// ignored subtrees.
func (s gitignoreStack) matchesDir(path string) bool {
	for _, e := range s {
		rel, err := filepath.Rel(e.Dir, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		if e.Matcher.MatchesPath(filepath.ToSlash(rel) + "/") {
			return true
		}
	}
	return false
}

// matchesFile reports whether path (a file) is ignored by any matcher
// in the stack.
func (s gitignoreStack) matchesFile(path string) bool {
	for _, e := range s {
		rel, err := filepath.Rel(e.Dir, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		if e.Matcher.MatchesPath(filepath.ToSlash(rel)) {
			return true
		}
	}
	return false
}

// projectMCPMatch reports whether path's tail matches a project-relative
// MCP config pattern from mcpconfig.ProjectFilenames(). Returns the matched
// client and true on hit.
func projectMCPMatch(root, path string) (mcpconfig.Client, bool) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", false
	}
	relSlash := filepath.ToSlash(rel)
	for _, pf := range mcpconfig.ProjectFilenames() {
		suffix := strings.Join(pf.Path, "/")
		if relSlash == suffix || strings.HasSuffix(relSlash, "/"+suffix) {
			return pf.Client, true
		}
	}
	return "", false
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
	stack := gitignoreStack{}
	if m := loadGitignore(root); m != nil {
		stack = append(stack, gitignoreEntry{Dir: root, Matcher: m})
	}

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
			// Baseline pruning takes precedence over .gitignore negation —
			// these dirs are never scanned, period.
			if _, skip := baselineExcludeDirs[d.Name()]; skip {
				return fs.SkipDir
			}
			// .gitignore-pruned directories are skipped before descent.
			if stack.matchesDir(path) {
				return fs.SkipDir
			}
			// Layer this directory's .gitignore onto the stack for its subtree.
			if m := loadGitignore(path); m != nil {
				stack = append(stack, gitignoreEntry{Dir: path, Matcher: m})
			}
			return nil
		}
		// filepath.WalkDir does not follow symbolic links: a symlinked
		// directory arrives here with d.IsDir()==false and d.Type() carrying
		// ModeSymlink. We never descend into the link target. If the link's
		// basename happens to match an env pattern below, the leaf symlink
		// gets returned and the existing refuseSymlinkedInputs gate at the
		// action layer surfaces an explicit error.
		//
		// Apply .gitignore to files — a user can ignore a specific file by
		// name. Checked before any pattern match so it applies uniformly to
		// .env files AND project-local MCP configs.
		if stack.matchesFile(path) {
			return nil
		}
		// Env file?
		if matchesEnvBasename(d.Name()) {
			res.envPaths = append(res.envPaths, path)
			return nil
		}
		// Project-local MCP config?
		if client, ok := projectMCPMatch(root, path); ok {
			res.mcpConfigs = append(res.mcpConfigs, mcpconfig.DiscoveredConfig{
				Path:   path,
				Client: client,
				Scope:  mcpconfig.ProjectScope,
			})
			return nil
		}
		return nil
	})
	if err != nil {
		return walkResult{}, err
	}
	sort.Strings(res.envPaths)
	sort.Slice(res.mcpConfigs, func(i, j int) bool {
		return res.mcpConfigs[i].Path < res.mcpConfigs[j].Path
	})
	return res, nil
}
