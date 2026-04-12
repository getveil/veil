package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCaDirHelper(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		home    string
		xdg     string
		want    string
		wantErr bool
	}{
		{
			name: "darwin ignores xdg",
			goos: "darwin",
			home: "/Users/alice",
			xdg:  "/somewhere/data",
			want: "/Users/alice/Library/Application Support/veil/ca",
		},
		{
			name: "darwin no xdg",
			goos: "darwin",
			home: "/Users/alice",
			want: "/Users/alice/Library/Application Support/veil/ca",
		},
		{
			name: "linux with xdg absolute",
			goos: "linux",
			home: "/home/alice",
			xdg:  "/custom/data",
			want: "/custom/data/veil/ca",
		},
		{
			name: "linux empty xdg falls back",
			goos: "linux",
			home: "/home/alice",
			xdg:  "",
			want: "/home/alice/.local/share/veil/ca",
		},
		{
			name: "linux non-absolute xdg falls back",
			goos: "linux",
			home: "/home/alice",
			xdg:  "relative/path",
			want: "/home/alice/.local/share/veil/ca",
		},
		{
			name:    "unsupported goos",
			goos:    "windows",
			home:    "C:/Users/alice",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := caDir(tc.goos, tc.home, tc.xdg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestKeystoreFallbackHelper(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		home    string
		xdg     string
		want    string
		wantErr bool
	}{
		{
			name: "darwin with xdg state",
			goos: "darwin",
			home: "/Users/alice",
			xdg:  "/custom/state",
			want: "/custom/state/veil/master.key.age",
		},
		{
			name: "darwin empty xdg",
			goos: "darwin",
			home: "/Users/alice",
			want: "/Users/alice/.local/state/veil/master.key.age",
		},
		{
			name: "linux with xdg state",
			goos: "linux",
			home: "/home/alice",
			xdg:  "/custom/state",
			want: "/custom/state/veil/master.key.age",
		},
		{
			name: "linux empty xdg",
			goos: "linux",
			home: "/home/alice",
			want: "/home/alice/.local/state/veil/master.key.age",
		},
		{
			name: "linux non-absolute xdg falls back",
			goos: "linux",
			home: "/home/alice",
			xdg:  "rel/path",
			want: "/home/alice/.local/state/veil/master.key.age",
		},
		{
			name:    "unsupported goos",
			goos:    "plan9",
			home:    "/home/alice",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := keystoreFallback(tc.goos, tc.home, tc.xdg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCADirEnvOverride(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping on %s", runtime.GOOS)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	if runtime.GOOS == "linux" {
		custom := t.TempDir()
		t.Setenv("XDG_DATA_HOME", custom)
		got, err := CADir()
		if err != nil {
			t.Fatalf("CADir: %v", err)
		}
		want := filepath.Join(custom, "veil", "ca")
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}

		t.Setenv("XDG_DATA_HOME", "")
		got, err = CADir()
		if err != nil {
			t.Fatalf("CADir empty: %v", err)
		}
		want = filepath.Join(home, ".local", "share", "veil", "ca")
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}

	if runtime.GOOS == "darwin" {
		t.Setenv("XDG_DATA_HOME", "/anywhere/else")
		got, err := CADir()
		if err != nil {
			t.Fatalf("CADir: %v", err)
		}
		want := filepath.Join(home, "Library", "Application Support", "veil", "ca")
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestCAFileAndKeyFile(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping on %s", runtime.GOOS)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")

	caFile, err := CAFile()
	if err != nil {
		t.Fatalf("CAFile: %v", err)
	}
	caKey, err := CAKeyFile()
	if err != nil {
		t.Fatalf("CAKeyFile: %v", err)
	}
	dir, err := CADir()
	if err != nil {
		t.Fatalf("CADir: %v", err)
	}

	if filepath.Dir(caFile) != dir {
		t.Errorf("CAFile dir = %q, want %q", filepath.Dir(caFile), dir)
	}
	if filepath.Base(caFile) != "root.pem" {
		t.Errorf("CAFile base = %q, want root.pem", filepath.Base(caFile))
	}
	if filepath.Dir(caKey) != dir {
		t.Errorf("CAKeyFile dir = %q, want %q", filepath.Dir(caKey), dir)
	}
	if filepath.Base(caKey) != "root.key" {
		t.Errorf("CAKeyFile base = %q, want root.key", filepath.Base(caKey))
	}
}

func TestKeystoreFallbackFile(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping on %s", runtime.GOOS)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", "")

	got, err := KeystoreFallbackFile()
	if err != nil {
		t.Fatalf("KeystoreFallbackFile: %v", err)
	}
	want := filepath.Join(home, ".local", "state", "veil", "master.key.age")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	custom := t.TempDir()
	t.Setenv("XDG_STATE_HOME", custom)
	got, err = KeystoreFallbackFile()
	if err != nil {
		t.Fatalf("KeystoreFallbackFile override: %v", err)
	}
	want = filepath.Join(custom, "veil", "master.key.age")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEnsureDirFresh(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "a", "b", "c")

	if err := EnsureDir(target, 0o700); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("not a dir")
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("mode = %o, want 0700", info.Mode().Perm())
	}
}

func TestEnsureDirIdempotent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "x")
	if err := EnsureDir(target, 0o700); err != nil {
		t.Fatalf("first EnsureDir: %v", err)
	}
	if err := EnsureDir(target, 0o700); err != nil {
		t.Fatalf("second EnsureDir: %v", err)
	}
}

func TestEnsureDirPermissionFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, cannot test permission failure")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "locked")
	if err := os.Mkdir(parent, 0o500); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(parent, 0o700)
	})

	target := filepath.Join(parent, "child")
	err := EnsureDir(target, 0o700)
	if err == nil {
		t.Fatalf("expected error creating dir under read-only parent")
	}
	if !errors.Is(err, os.ErrPermission) && !os.IsPermission(err) {
		t.Errorf("expected permission error, got: %v", err)
	}
}
