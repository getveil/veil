package mcpconfig

import (
	"runtime"
	"testing"
)

func TestUserLocationsContainsClaudeDesktop(t *testing.T) {
	found := false
	for _, loc := range userLocations() {
		if loc.Client == ClaudeDesktop && loc.Scope == UserScope {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("userLocations() missing Claude Desktop user-scope entry")
	}
}

func TestUserLocationsContainsClaudeCodeAndCursor(t *testing.T) {
	wantClients := map[Client]bool{
		ClaudeCode: false,
		Cursor:     false,
	}
	for _, loc := range userLocations() {
		if loc.Scope != UserScope {
			continue
		}
		if _, ok := wantClients[loc.Client]; ok {
			wantClients[loc.Client] = true
		}
	}
	for c, found := range wantClients {
		if !found {
			t.Errorf("userLocations() missing user-scope entry for %s", c)
		}
	}
}

func TestUserLocationsClaudeDesktopMatchesLegacyPath(t *testing.T) {
	// Claude Desktop's path must keep matching the legacy claudeConfigSubpath
	// table so existing installs upgrade cleanly.
	var legacy []string
	switch runtime.GOOS {
	case "darwin":
		legacy = []string{"Library", "Application Support", "Claude", "claude_desktop_config.json"}
	case "linux":
		legacy = []string{".config", "Claude", "claude_desktop_config.json"}
	default:
		t.Skip("no legacy Claude Desktop path on this platform")
	}

	for _, loc := range userLocations() {
		if loc.Client != ClaudeDesktop || loc.Scope != UserScope {
			continue
		}
		got := loc.subpath(runtime.GOOS)
		if !slicesEqual(got, legacy) {
			t.Errorf("Claude Desktop subpath = %v, want %v", got, legacy)
		}
		return
	}
	t.Fatal("Claude Desktop user location not found")
}

func TestProjectFilenamesContainsClaudeCodeAndCursor(t *testing.T) {
	wantClients := map[Client]bool{
		ClaudeCode: false,
		Cursor:     false,
	}
	for _, pf := range ProjectFilenames() {
		if _, ok := wantClients[pf.Client]; ok {
			wantClients[pf.Client] = true
		}
	}
	for c, found := range wantClients {
		if !found {
			t.Errorf("ProjectFilenames() missing %s", c)
		}
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
