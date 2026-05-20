package skiphost

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		host    string
		wantErr bool
	}{
		// Reject: catastrophic — Go's httpproxy treats bare "*" as bypass-all,
		// silently disabling Veil for the whole project.
		{"bare wildcard", "*", true},
		{"bare wildcard with whitespace", "  *  ", true},
		// Reject: empty / whitespace-only.
		{"empty", "", true},
		{"whitespace only", "   ", true},
		// Reject: pure punctuation has no host content.
		{"single dot", ".", true},
		{"multiple dots", "...", true},
		{"colons only", ":::", true},
		{"slashes only", "///", true},
		// Reject: would corrupt NO_PROXY parsing (commas split entries).
		{"contains comma", "foo,bar", true},
		// Reject: whitespace inside is not a valid env-var entry.
		{"contains space", "foo bar.com", true},
		{"contains tab", "foo\tbar.com", true},
		{"contains newline", "foo\nbar.com", true},
		// Reject: control characters.
		{"contains control char", "foo\x00bar.com", true},
		// Accept: legitimate NO_PROXY forms that Veil already supports.
		{"plain hostname", "api.anthropic.com", false},
		{"single label", "localhost", false},
		{"wildcard subdomain", "*.internal.corp.com", false},
		{"leading dot", ".internal.com", false},
		{"ipv4", "192.168.1.1", false},
		{"cidr", "10.0.0.0/8", false},
		{"host with port", "api.example.com:8443", false},
		{"trims surrounding whitespace", "  api.example.com  ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.host)
			if tc.wantErr && err == nil {
				t.Fatalf("Validate(%q) = nil, want error", tc.host)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate(%q) = %v, want nil", tc.host, err)
			}
			if tc.wantErr && err != nil && !errors.Is(err, ErrInvalidHost) {
				t.Errorf("Validate(%q) error %v does not wrap ErrInvalidHost", tc.host, err)
			}
		})
	}
}

func TestAdd_RejectsInvalid(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"*", "", "...", "foo,bar", "foo bar"} {
		host := host
		t.Run(host, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "skip_hosts")
			added, err := Add(path, host)
			if err == nil {
				t.Fatalf("Add(%q) succeeded; want error", host)
			}
			if !errors.Is(err, ErrInvalidHost) {
				t.Errorf("Add(%q) returned %v, want ErrInvalidHost", host, err)
			}
			if added {
				t.Errorf("Add(%q) reported added=true", host)
			}
			// File should not have been created with the bad entry.
			if _, statErr := os.Stat(path); statErr == nil {
				hosts, _ := Load(path)
				if len(hosts) != 0 {
					t.Errorf("Add(%q) wrote %v to file", host, hosts)
				}
			}
		})
	}
}

// Defense-in-depth: a hand-edited "*" in skip_hosts must not flow through to
// NO_PROXY. parse drops invalid entries silently so Load returns only safe ones.
func TestLoad_FiltersInvalidEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")
	content := "# Managed by veil skip\napi.anthropic.com\n*\n\n...\n*.internal.corp.com\nfoo,bar\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	hosts, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"api.anthropic.com", "*.internal.corp.com"}
	if len(hosts) != len(want) {
		t.Fatalf("expected %v, got %v", want, hosts)
	}
	for i, h := range want {
		if hosts[i] != h {
			t.Errorf("hosts[%d] = %q, want %q", i, hosts[i], h)
		}
	}
}

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

