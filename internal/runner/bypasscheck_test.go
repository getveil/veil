package runner

import (
	"errors"
	"strings"
	"testing"
)

// stubLookPath returns a lookPath function that "finds" exactly the names in
// present. This lets bypass-check tests probe the static detection table
// without depending on what's actually installed on the host.
func stubLookPath(present ...string) func(string) (string, error) {
	set := make(map[string]struct{}, len(present))
	for _, n := range present {
		set[n] = struct{}{}
	}
	return func(name string) (string, error) {
		if _, ok := set[name]; ok {
			return "/fake/path/" + name, nil
		}
		return "", errors.New("not found")
	}
}

func TestDetectBypassClients_DarwinDocker(t *testing.T) {
	got := detectBypassClients("darwin", stubLookPath("docker"))
	if len(got) != 1 {
		t.Fatalf("got %d warnings, want 1: %+v", len(got), got)
	}
	if got[0].Tool != "docker" {
		t.Errorf("Tool = %q, want %q", got[0].Tool, "docker")
	}
	if !strings.Contains(got[0].Message, "docker") {
		t.Errorf("Message should mention docker; got %q", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "docs/DOCKER.md") {
		t.Errorf("Message should link docs/DOCKER.md; got %q", got[0].Message)
	}
}

func TestDetectBypassClients_DarwinDotnet(t *testing.T) {
	got := detectBypassClients("darwin", stubLookPath("dotnet"))
	if len(got) != 1 {
		t.Fatalf("got %d warnings, want 1: %+v", len(got), got)
	}
	if got[0].Tool != "dotnet" {
		t.Errorf("Tool = %q, want %q", got[0].Tool, "dotnet")
	}
	if !strings.Contains(strings.ToLower(got[0].Message), "dotnet") &&
		!strings.Contains(got[0].Message, ".NET") {
		t.Errorf("Message should mention dotnet/.NET; got %q", got[0].Message)
	}
}

func TestDetectBypassClients_DarwinNone(t *testing.T) {
	got := detectBypassClients("darwin", stubLookPath())
	if len(got) != 0 {
		t.Fatalf("expected no warnings, got %+v", got)
	}
}

func TestDetectBypassClients_LinuxDockerNoWarning(t *testing.T) {
	got := detectBypassClients("linux", stubLookPath("docker"))
	for _, w := range got {
		if w.Tool == "docker" {
			t.Errorf("docker should not warn on linux; got %+v", w)
		}
	}
}

func TestDetectBypassClients_SccacheAnyPlatform(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			got := detectBypassClients(goos, stubLookPath("sccache"))
			found := false
			for _, w := range got {
				if w.Tool == "sccache" {
					found = true
					if !strings.Contains(strings.ToLower(w.Message), "sccache") {
						t.Errorf("Message should mention sccache; got %q", w.Message)
					}
				}
			}
			if !found {
				t.Errorf("expected sccache warning on %s; got %+v", goos, got)
			}
		})
	}
}

func TestDetectBypassClients_DarwinAllThree(t *testing.T) {
	got := detectBypassClients("darwin", stubLookPath("docker", "dotnet", "sccache"))
	if len(got) != 3 {
		t.Fatalf("got %d warnings, want 3: %+v", len(got), got)
	}
	wantOrder := []string{"docker", "dotnet", "sccache"}
	for i, w := range got {
		if w.Tool != wantOrder[i] {
			t.Errorf("warnings[%d].Tool = %q, want %q", i, w.Tool, wantOrder[i])
		}
	}
}
