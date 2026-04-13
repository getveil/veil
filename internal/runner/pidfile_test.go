package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndReadPidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.pid")

	if err := WritePidFile(path, 12345); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	pid, err := ReadPidFile(path)
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	if pid != 12345 {
		t.Errorf("expected pid 12345, got %d", pid)
	}

	RemovePidFile(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("pid file should be removed")
	}
}

func TestReadPidFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.pid")
	_, err := ReadPidFile(path)
	if err == nil {
		t.Fatal("expected error for missing pid file")
	}
}

func TestReadPidFileCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.pid")
	if err := os.WriteFile(path, []byte("not-a-number\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadPidFile(path)
	if err == nil {
		t.Fatal("expected error for corrupt pid file")
	}
}
