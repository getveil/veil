package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestSetColorNever(t *testing.T) {
	SetColor("never")
	if !color.NoColor {
		t.Error("SetColor(\"never\") should set color.NoColor = true")
	}
}

func TestSetColorAlways(t *testing.T) {
	SetColor("always")
	if color.NoColor {
		t.Error("SetColor(\"always\") should set color.NoColor = false")
	}
}

func TestStep(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	Step(&buf, "Found 3 .env files")
	got := buf.String()
	if !strings.Contains(got, "✓") {
		t.Errorf("Step should contain ✓, got: %q", got)
	}
	if !strings.Contains(got, "Found 3 .env files") {
		t.Errorf("Step should contain message, got: %q", got)
	}
}

func TestWarn(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	Warn(&buf, "2 unscoped credentials")
	got := buf.String()
	if !strings.Contains(got, "!") {
		t.Errorf("Warn should contain !, got: %q", got)
	}
	if !strings.Contains(got, "2 unscoped credentials") {
		t.Errorf("Warn should contain message, got: %q", got)
	}
}

func TestPhase(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	Phase(&buf, "Scanning project...")
	got := buf.String()
	if !strings.Contains(got, "Scanning project...") {
		t.Errorf("Phase should contain message, got: %q", got)
	}
}
