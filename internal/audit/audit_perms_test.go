package audit_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/8enji/veil/internal/audit"
)

func TestOpenSetsRestrictivePerms(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sub", "audit.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	s, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := dbPath + suffix
		info, err := os.Stat(p)
		if err != nil {
			if suffix == "-wal" && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			t.Fatalf("stat %s: %v", p, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o, want 0600", p, info.Mode().Perm())
		}
	}
	parent := filepath.Dir(dbPath)
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("parent %s mode %o, want 0700", parent, info.Mode().Perm())
	}
}

// TestOpenSidecarNeverWorldReadable hammers Open with a concurrent stat
// poller. Without the umask guard, SQLite's default 0644 is visible on
// -wal/-shm for a short window before the subsequent Chmod — this poller
// will catch it.
func TestOpenSidecarNeverWorldReadable(t *testing.T) {
	for iter := 0; iter < 20; iter++ {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "audit.db")

		stop := make(chan struct{})
		bad := make(chan string, 32)
		done := make(chan struct{})

		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, suffix := range []string{"", "-wal", "-shm"} {
					p := dbPath + suffix
					info, err := os.Stat(p)
					if err != nil {
						continue
					}
					if info.Mode().Perm()&0o077 != 0 {
						select {
						case bad <- fmt.Sprintf("%s mode %o at iter %d", p, info.Mode().Perm(), iter):
						default:
						}
					}
				}
			}
		}()

		s, err := audit.Open(dbPath)
		close(stop)
		<-done
		if err != nil {
			t.Fatalf("Open iter %d: %v", iter, err)
		}
		_ = s.Close()

		select {
		case msg := <-bad:
			t.Fatalf("world-readable sidecar observed: %s", msg)
		default:
		}
	}
}

func TestOpenCorrectsExistingPerms(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	// Pre-create the file with open perms.
	if err := os.WriteFile(dbPath, nil, 0o644); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	s, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 0600", info.Mode().Perm())
	}
}
