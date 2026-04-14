package skiphost

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NonexistentFile(t *testing.T) {
	hosts, err := Load("/nonexistent/path/skip_hosts")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("expected empty slice, got %v", hosts)
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")
	if err := os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	hosts, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("expected empty slice, got %v", hosts)
	}
}

func TestLoad_WithEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")
	content := "# Managed by veil skip\napi.anthropic.com\n*.internal.corp.com\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	hosts, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "api.anthropic.com" {
		t.Errorf("expected api.anthropic.com, got %q", hosts[0])
	}
	if hosts[1] != "*.internal.corp.com" {
		t.Errorf("expected *.internal.corp.com, got %q", hosts[1])
	}
}

func TestLoad_SkipsBlanksAndComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")
	content := "# comment\n\napi.anthropic.com\n  \n# another comment\n*.foo.com\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	hosts, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2, got %d: %v", len(hosts), hosts)
	}
}

func TestSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")
	err := Save(path, []string{"api.anthropic.com", "*.internal.corp.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hosts, err := Load(path)
	if err != nil {
		t.Fatalf("load after save: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2, got %d", len(hosts))
	}
}

func TestAdd_NewHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")

	added, err := Add(path, "api.anthropic.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !added {
		t.Error("expected added=true for new host")
	}

	hosts, _ := Load(path)
	if len(hosts) != 1 || hosts[0] != "api.anthropic.com" {
		t.Errorf("expected [api.anthropic.com], got %v", hosts)
	}
}

func TestAdd_Duplicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")

	_, _ = Add(path, "api.anthropic.com")
	added, err := Add(path, "api.anthropic.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if added {
		t.Error("expected added=false for duplicate")
	}

	hosts, _ := Load(path)
	if len(hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(hosts))
	}
}

func TestRemove_Existing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")

	_, _ = Add(path, "api.anthropic.com")
	_, _ = Add(path, "*.internal.corp.com")

	removed, err := Remove(path, "api.anthropic.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !removed {
		t.Error("expected removed=true")
	}

	hosts, _ := Load(path)
	if len(hosts) != 1 || hosts[0] != "*.internal.corp.com" {
		t.Errorf("expected [*.internal.corp.com], got %v", hosts)
	}
}

func TestRemove_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")

	_, _ = Add(path, "api.anthropic.com")

	removed, err := Remove(path, "not.there.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if removed {
		t.Error("expected removed=false for nonexistent host")
	}
}
