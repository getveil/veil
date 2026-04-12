package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func mkdirs(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("mkdir %q: %v", path, err)
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("touch %q: %v", path, err)
	}
}

func TestFindProjectRootGitDir(t *testing.T) {
	home := setupHome(t)
	proj := filepath.Join(home, "proj")
	sub := filepath.Join(proj, "sub", "dir")
	mkdirs(t, sub)
	mkdirs(t, filepath.Join(proj, ".git"))

	got, err := FindProjectRoot(sub)
	if err != nil {
		t.Fatalf("FindProjectRoot: %v", err)
	}
	if got != proj {
		t.Errorf("got %q, want %q", got, proj)
	}
}

func TestFindProjectRootGitFile(t *testing.T) {
	home := setupHome(t)
	proj := filepath.Join(home, "proj")
	sub := filepath.Join(proj, "sub")
	mkdirs(t, sub)
	touch(t, filepath.Join(proj, ".git"))

	got, err := FindProjectRoot(sub)
	if err != nil {
		t.Fatalf("FindProjectRoot: %v", err)
	}
	if got != proj {
		t.Errorf("got %q, want %q", got, proj)
	}
}

func TestFindProjectRootVeilDir(t *testing.T) {
	home := setupHome(t)
	proj := filepath.Join(home, "proj")
	sub := filepath.Join(proj, "sub")
	mkdirs(t, sub)
	mkdirs(t, filepath.Join(proj, ".veil"))

	got, err := FindProjectRoot(sub)
	if err != nil {
		t.Fatalf("FindProjectRoot: %v", err)
	}
	if got != proj {
		t.Errorf("got %q, want %q", got, proj)
	}
}

func TestFindProjectRootEnvFile(t *testing.T) {
	home := setupHome(t)
	proj := filepath.Join(home, "proj")
	sub := filepath.Join(proj, "sub")
	mkdirs(t, sub)
	touch(t, filepath.Join(proj, ".env"))

	got, err := FindProjectRoot(sub)
	if err != nil {
		t.Fatalf("FindProjectRoot: %v", err)
	}
	if got != proj {
		t.Errorf("got %q, want %q", got, proj)
	}
}

func TestFindProjectRootCloserGitWins(t *testing.T) {
	home := setupHome(t)
	outer := filepath.Join(home, "outer")
	inner := filepath.Join(outer, "inner")
	start := filepath.Join(inner, "deep")
	mkdirs(t, start)
	touch(t, filepath.Join(outer, ".env"))
	mkdirs(t, filepath.Join(inner, ".git"))

	got, err := FindProjectRoot(start)
	if err != nil {
		t.Fatalf("FindProjectRoot: %v", err)
	}
	if got != inner {
		t.Errorf("got %q, want %q", got, inner)
	}
}

func TestFindProjectRootNoMarker(t *testing.T) {
	home := setupHome(t)
	proj := filepath.Join(home, "proj")
	mkdirs(t, proj)

	_, err := FindProjectRoot(proj)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no project root found") {
		t.Errorf("error message = %q, want substring 'no project root found'", err.Error())
	}
}

func TestFindProjectRootStopsAtHome(t *testing.T) {
	home := setupHome(t)
	touch(t, filepath.Join(home, ".env"))
	sub := filepath.Join(home, "a", "b")
	mkdirs(t, sub)

	got, err := FindProjectRoot(sub)
	if err != nil {
		t.Fatalf("FindProjectRoot: %v", err)
	}
	if got != home {
		t.Errorf("got %q, want %q", got, home)
	}
}

func TestFindProjectRootRelativeStart(t *testing.T) {
	home := setupHome(t)
	proj := filepath.Join(home, "proj")
	mkdirs(t, proj)
	mkdirs(t, filepath.Join(proj, ".git"))

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(proj); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	got, err := FindProjectRoot(".")
	if err != nil {
		t.Fatalf("FindProjectRoot: %v", err)
	}

	wantResolved, err := filepath.EvalSymlinks(proj)
	if err != nil {
		t.Fatalf("evalsymlinks: %v", err)
	}
	gotResolved, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatalf("evalsymlinks: %v", err)
	}
	if gotResolved != wantResolved {
		t.Errorf("got %q, want %q", gotResolved, wantResolved)
	}
}

func TestProjectStateDir(t *testing.T) {
	root := "/tmp/proj"
	got := ProjectStateDir(root)
	want := filepath.Join(root, ".veil")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestVaultHelpers(t *testing.T) {
	root := "/tmp/proj"
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"VaultFile", VaultFile(root), filepath.Join(root, ".veil", "vault.bin")},
		{"VaultBackupFile", VaultBackupFile(root), filepath.Join(root, ".veil", "vault.bin.bak")},
		{"VaultMetaFile", VaultMetaFile(root), filepath.Join(root, ".veil", "vault.meta")},
		{"AuditDBFile", AuditDBFile(root), filepath.Join(root, ".veil", "audit.sqlite")},
		{"VaultGitignoreFile", VaultGitignoreFile(root), filepath.Join(root, ".veil", ".gitignore")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %q, want %q", tc.got, tc.want)
			}
		})
	}
}
