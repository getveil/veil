package runner

import (
	"strings"
	"testing"
)

func TestBypassWarningForCommand_DarwinDocker(t *testing.T) {
	w := bypassWarningForCommand("darwin", "docker")
	if w == nil {
		t.Fatal("expected warning for docker on darwin, got nil")
	}
	if w.Tool != "docker" {
		t.Errorf("Tool = %q, want %q", w.Tool, "docker")
	}
	if !strings.Contains(w.Message, "docker") {
		t.Errorf("Message should mention docker; got %q", w.Message)
	}
	if !strings.Contains(w.Message, "docs/DOCKER.md") {
		t.Errorf("Message should link docs/DOCKER.md; got %q", w.Message)
	}
}

func TestBypassWarningForCommand_DarwinDotnet(t *testing.T) {
	w := bypassWarningForCommand("darwin", "dotnet")
	if w == nil {
		t.Fatal("expected warning for dotnet on darwin, got nil")
	}
	if w.Tool != "dotnet" {
		t.Errorf("Tool = %q, want %q", w.Tool, "dotnet")
	}
	if !strings.Contains(strings.ToLower(w.Message), "dotnet") &&
		!strings.Contains(w.Message, ".NET") {
		t.Errorf("Message should mention dotnet/.NET; got %q", w.Message)
	}
}

func TestBypassWarningForCommand_LinuxDockerNil(t *testing.T) {
	if w := bypassWarningForCommand("linux", "docker"); w != nil {
		t.Errorf("docker on linux should not warn; got %+v", w)
	}
}

func TestBypassWarningForCommand_SccacheAnyPlatform(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			w := bypassWarningForCommand(goos, "sccache")
			if w == nil {
				t.Fatalf("expected sccache warning on %s, got nil", goos)
			}
			if w.Tool != "sccache" {
				t.Errorf("Tool = %q, want %q", w.Tool, "sccache")
			}
		})
	}
}

func TestBypassWarningForCommand_UnrelatedCommandSilent(t *testing.T) {
	for _, cmd := range []string{"claude", "cursor", "echo", "bash", "zsh", "pytest", "make"} {
		t.Run(cmd, func(t *testing.T) {
			if w := bypassWarningForCommand("darwin", cmd); w != nil {
				t.Errorf("unrelated command %q should not warn; got %+v", cmd, w)
			}
		})
	}
}

func TestBypassWarningForCommand_AcceptsFullPath(t *testing.T) {
	// Callers pass the resolved realpath, not the bare name. The detector
	// must strip directories before matching against the rule table.
	w := bypassWarningForCommand("darwin", "/usr/local/bin/docker")
	if w == nil || w.Tool != "docker" {
		t.Errorf("/usr/local/bin/docker on darwin should match docker rule; got %+v", w)
	}
}
