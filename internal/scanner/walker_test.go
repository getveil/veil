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
