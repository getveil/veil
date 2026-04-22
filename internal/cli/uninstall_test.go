package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/8enji/veil/internal/config"
)

func TestActiveProxyPIDsIgnoresDeadPIDs(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Write a PID file for an extremely high PID that won't exist.
	pidFile := filepath.Join(stateDir, "proxy-99999999.pid")
	if err := os.WriteFile(pidFile, []byte("99999999\n"), 0600); err != nil {
		t.Fatal(err)
	}

	live, err := activeProxyPIDs(root)
	if err != nil {
		t.Fatalf("activeProxyPIDs: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("expected no live PIDs, got %v", live)
	}
}

func TestActiveProxyPIDsDetectsLivePID(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Use the current test process's PID — guaranteed alive.
	ourPID := os.Getpid()
	pidFile := filepath.Join(stateDir, fmt.Sprintf("proxy-%d.pid", ourPID))
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", ourPID)), 0600); err != nil {
		t.Fatal(err)
	}

	live, err := activeProxyPIDs(root)
	if err != nil {
		t.Fatalf("activeProxyPIDs: %v", err)
	}
	if len(live) != 1 || live[0] != ourPID {
		t.Errorf("expected [%d], got %v", ourPID, live)
	}
}

func TestActiveProxyPIDsNoStateDir(t *testing.T) {
	root := t.TempDir()
	live, err := activeProxyPIDs(root)
	if err != nil {
		t.Fatalf("activeProxyPIDs: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("expected no PIDs for missing state dir, got %v", live)
	}
}
