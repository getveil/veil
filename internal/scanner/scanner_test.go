package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScan_CuratedFilesOnly(t *testing.T) {
	dir := t.TempDir()

	// Create all the test files
	files := []string{
		".env",
		".env.local",
		".env.development",
		".env.production",
		".env.example",
		".env.sample",
		".env.custom.example",
		".env.custom.sample",
		".env.test", // not in curated list
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("X=1\n"), 0o644); err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
	}

	got, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	want := []string{
		filepath.Join(dir, ".env"),
		filepath.Join(dir, ".env.development"),
		filepath.Join(dir, ".env.local"),
		filepath.Join(dir, ".env.production"),
	}

	if len(got) != len(want) {
		t.Fatalf("Scan returned %d files, want %d:\n  got:  %v\n  want: %v", len(got), len(want), got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Scan[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestScan_AlphabeticalOrder(t *testing.T) {
	dir := t.TempDir()

	// Create files in non-alphabetical order
	for _, name := range []string{".env.production", ".env", ".env.local"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("X=1\n"), 0o644); err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
	}

	got, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1] {
			t.Errorf("not sorted: %q comes after %q", got[i], got[i-1])
		}
	}
}

func TestScan_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	got, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got == nil {
		t.Error("Scan returned nil, want empty slice")
	}
	if len(got) != 0 {
		t.Errorf("Scan returned %d files, want 0", len(got))
	}
}

func TestScan_SubsetExists(t *testing.T) {
	dir := t.TempDir()

	// Only create .env and .env.local
	for _, name := range []string{".env", ".env.local"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("X=1\n"), 0o644); err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
	}

	got, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("Scan returned %d files, want 2: %v", len(got), got)
	}
}

func TestScan_IgnoresDirectories(t *testing.T) {
	dir := t.TempDir()

	// Create a directory named .env
	if err := os.Mkdir(filepath.Join(dir, ".env"), 0o755); err != nil {
		t.Fatalf("creating .env dir: %v", err)
	}

	got, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Scan returned %d files, want 0 (directory should be ignored)", len(got))
	}
}

func TestScan_IgnorePatterns(t *testing.T) {
	dir := t.TempDir()

	// Create .env and .env.local.
	for _, name := range []string{".env", ".env.local"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("X=1\n"), 0o644); err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
	}

	// Ignore .env.local.
	got, err := Scan(dir, ".env.local")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(got), got)
	}
	if filepath.Base(got[0]) != ".env" {
		t.Errorf("expected .env, got %s", got[0])
	}
}

func TestScan_IgnoreGlobStar(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.production"), []byte("X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Ignore all .env.* files using glob.
	got, err := Scan(dir, ".env.*")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(got), got)
	}
	if filepath.Base(got[0]) != ".env" {
		t.Errorf("expected .env, got %s", got[0])
	}
}

func TestScan_NoIgnorePatterns(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{".env", ".env.local"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("X=1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// No ignore patterns — same as current behavior.
	got, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 files, got %d: %v", len(got), got)
	}
}
