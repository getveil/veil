package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScan_FindsNestedEnvFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".env"), "A=1")
	mustMkdir(t, filepath.Join(root, "apps", "api"))
	mustWrite(t, filepath.Join(root, "apps", "api", ".env"), "B=1")
	mustMkdir(t, filepath.Join(root, "packages", "db"))
	mustWrite(t, filepath.Join(root, "packages", "db", ".env.local"), "C=1")

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	want := []string{
		filepath.Join(root, ".env"),
		filepath.Join(root, "apps", "api", ".env"),
		filepath.Join(root, "packages", "db", ".env.local"),
	}
	if !stringSetEqual(got, want) {
		t.Errorf("Scan returned %v, want %v", got, want)
	}
}

func TestScan_DiscoversExtendedNames(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".env.test", ".env.staging", ".env.ci", ".env.preview", ".env.api"} {
		mustWrite(t, filepath.Join(root, name), "X=1")
	}
	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("expected 5 files, got %d: %v", len(got), got)
	}
}

func TestScan_ExcludesExampleSampleTemplateDist(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".env"), "A=1")
	for _, name := range []string{".env.example", ".env.sample", ".env.template", ".env.dist", ".env.local.example"} {
		mustWrite(t, filepath.Join(root, name), "X=1")
	}
	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 || got[0] != filepath.Join(root, ".env") {
		t.Errorf("Scan = %v, want only .env", got)
	}
}

func TestScan_SkipsBaselineDirs(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".env"), "A=1")
	for _, dir := range []string{".git", ".veil", "node_modules", "vendor", "target", "dist", "build", ".next", ".nuxt", ".turbo", ".cache", ".pnpm-store", ".yarn"} {
		full := filepath.Join(root, dir)
		mustMkdir(t, full)
		mustWrite(t, filepath.Join(full, ".env"), "X=1")
	}
	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 || got[0] != filepath.Join(root, ".env") {
		t.Errorf("Scan = %v, want only root .env (baseline dirs leaked)", got)
	}
}

func TestScan_ExcludesVeilBackupSidecar(t *testing.T) {
	// .env.veil-backup is Veil's own byte-faithful backup of the adjacent
	// placeholder .env. The backup/recovery code path handles it; the
	// regular scan must not surface it as a regular env file (which would
	// duplicate every credential during init).
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".env"), "A=1")
	mustWrite(t, filepath.Join(root, ".env.veil-backup"), "A=1")
	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 || got[0] != filepath.Join(root, ".env") {
		t.Errorf("Scan = %v, want only .env (veil-backup leaked)", got)
	}
}

func TestScan_BaselineSkipIsNameMatch(t *testing.T) {
	// A baseline-excluded dir name at any depth must be pruned. Each of
	// the 13 baseline names is exercised separately so a regression that
	// silently drops one name from the exclude set is caught.
	for _, name := range []string{
		".git", ".veil", "node_modules", "vendor", "target", "dist",
		"build", ".next", ".nuxt", ".turbo", ".cache", ".pnpm-store", ".yarn",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			deep := filepath.Join(root, "apps", "api", name, "pkg")
			mustMkdir(t, deep)
			mustWrite(t, filepath.Join(deep, ".env"), "X=1")
			got, err := Scan(root)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(got) != 0 {
				t.Errorf("expected 0 files; nested %s/.env leaked: %v", name, got)
			}
		})
	}
}

func TestScan_DoesNotFollowSymlinkedDirs(t *testing.T) {
	// A symlinked directory inside the project must not be traversed —
	// filepath.WalkDir does not follow symlinks, so the .env inside the
	// link target should never be discovered. This locks the contract
	// even if a future Go stdlib change made WalkDir follow symlinks.
	externalDir := t.TempDir()
	mustWrite(t, filepath.Join(externalDir, ".env"), "LEAKED=1")

	root := t.TempDir()
	link := filepath.Join(root, "linked-dir")
	if err := os.Symlink(externalDir, link); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Scan walked into symlinked dir: %v", got)
	}
}

func TestScan_RespectsGitignore(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".gitignore"), "ignored/\n*.log\n")
	mustWrite(t, filepath.Join(root, ".env"), "A=1")
	mustMkdir(t, filepath.Join(root, "ignored"))
	mustWrite(t, filepath.Join(root, "ignored", ".env"), "B=1")

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 || got[0] != filepath.Join(root, ".env") {
		t.Errorf("Scan = %v; ignored/.env should have been pruned via .gitignore", got)
	}
}

func TestScan_NestedGitignoreStacks(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".env"), "A=1")
	mustWrite(t, filepath.Join(root, ".gitignore"), "")
	mustMkdir(t, filepath.Join(root, "apps", "api"))
	mustMkdir(t, filepath.Join(root, "apps", "web"))
	mustWrite(t, filepath.Join(root, "apps", "web", ".gitignore"), ".env\n")
	mustWrite(t, filepath.Join(root, "apps", "api", ".env"), "B=1")
	mustWrite(t, filepath.Join(root, "apps", "web", ".env"), "C=1")

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := []string{
		filepath.Join(root, ".env"),
		filepath.Join(root, "apps", "api", ".env"),
	}
	if !stringSetEqual(got, want) {
		t.Errorf("Scan = %v, want %v", got, want)
	}
}

func TestScan_BaselineOverridesGitignoreNegation(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".gitignore"), "!node_modules/\n")
	mustMkdir(t, filepath.Join(root, "node_modules"))
	mustWrite(t, filepath.Join(root, "node_modules", ".env"), "X=1")

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("baseline failed: node_modules/.env leaked despite negation: %v", got)
	}
}

func TestScan_DirPatternPrunesAtDescent(t *testing.T) {
	// A "dir/" gitignore pattern must prune at directory-descent time so
	// the walker never traverses into the ignored tree. Without the
	// trailing-slash fix, the directory check is a no-op and the walker
	// descends fully, filtering only at file leaves — correct result but
	// wasteful I/O.
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".gitignore"), "ignored-tree/\n")
	mustMkdir(t, filepath.Join(root, "ignored-tree", "deeply", "nested"))
	mustWrite(t, filepath.Join(root, "ignored-tree", "deeply", "nested", ".env"), "X=1")
	mustWrite(t, filepath.Join(root, "ignored-tree", "a.txt"), "x")
	mustWrite(t, filepath.Join(root, "ignored-tree", "b.txt"), "x")

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Scan = %v; ignored-tree/ should have been pruned at descent", got)
	}
}

func TestScan_GitignoreNegationInsideNonBaselineDir(t *testing.T) {
	// Document current behavior for re-included files inside a
	// gitignore-pruned non-baseline dir. The walker prunes at the
	// directory level (matchesDir returns true), so the negated file
	// is never reached. This is a deviation from full gitignore
	// semantics but matches what users actually want from a secret
	// scanner — don't read files in dirs you said to ignore.
	// Uses "bundles/" (not a baseline-excluded name) so the assertion
	// exercises the gitignore matchesDir path, not the baseline floor.
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".gitignore"), "bundles/\n!bundles/.env.production\n")
	mustMkdir(t, filepath.Join(root, "bundles"))
	mustWrite(t, filepath.Join(root, "bundles", ".env.production"), "REAL=1")

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("bundles/.env.production should be pruned with bundles/ (current behavior): %v", got)
	}
}

func TestScanAll_FindsProjectMCPConfigs(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".env"), "A=1")
	mustWrite(t, filepath.Join(root, ".mcp.json"), `{}`)
	mustMkdir(t, filepath.Join(root, ".cursor"))
	mustWrite(t, filepath.Join(root, ".cursor", "mcp.json"), `{}`)

	res, err := ScanAll(root)
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(res.EnvPaths) != 1 || res.EnvPaths[0] != filepath.Join(root, ".env") {
		t.Errorf("EnvPaths = %v, want only root .env", res.EnvPaths)
	}
	if len(res.MCPConfigs) != 2 {
		t.Fatalf("MCPConfigs = %d, want 2: %+v", len(res.MCPConfigs), res.MCPConfigs)
	}
	seen := map[string]bool{}
	for _, c := range res.MCPConfigs {
		seen[string(c.Client)] = true
		if c.Scope != "project" {
			t.Errorf("scope = %q, want project", c.Scope)
		}
	}
	if !seen["claude-code"] || !seen["cursor"] {
		t.Errorf("missing clients: %+v", res.MCPConfigs)
	}
}

func TestScanAll_NestedProjectMCPConfig(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "apps", "web", ".cursor")
	mustMkdir(t, deep)
	mustWrite(t, filepath.Join(deep, "mcp.json"), `{}`)
	res, err := ScanAll(root)
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(res.MCPConfigs) != 1 || res.MCPConfigs[0].Path != filepath.Join(deep, "mcp.json") {
		t.Errorf("nested .cursor/mcp.json not found: %+v", res.MCPConfigs)
	}
}

func TestScanAll_GitignoreSuppressesProjectMCP(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".gitignore"), "private/\n")
	mustMkdir(t, filepath.Join(root, "private"))
	mustWrite(t, filepath.Join(root, "private", ".mcp.json"), `{}`)
	res, err := ScanAll(root)
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(res.MCPConfigs) != 0 {
		t.Errorf("private/.mcp.json should be gitignore-pruned: %+v", res.MCPConfigs)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func stringSetEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(b))
	for _, s := range b {
		seen[s] = true
	}
	for _, s := range a {
		if !seen[s] {
			return false
		}
	}
	return true
}
