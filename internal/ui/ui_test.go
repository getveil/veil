package ui

import (
	"bytes"
	"strings"
	"testing"
	"text/tabwriter"
	"time"

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

func TestHeader(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	Header(&buf, "Veil Status")
	got := buf.String()
	if !strings.Contains(got, "Veil Status") {
		t.Errorf("Header should contain label, got: %q", got)
	}
}

func TestFooter(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	Footer(&buf, "5 credentials")
	got := buf.String()
	if !strings.Contains(got, "5 credentials") {
		t.Errorf("Footer should contain message, got: %q", got)
	}
}

func TestRelativeTime(t *testing.T) {
	now := time.Now()
	tests := []struct {
		input time.Time
		want  string
	}{
		{now.Add(-10 * time.Second), "just now"},
		{now.Add(-5 * time.Minute), "5m ago"},
		{now.Add(-3 * time.Hour), "3h ago"},
		{now.Add(-2 * 24 * time.Hour), "2d ago"},
	}
	for _, tt := range tests {
		got := RelativeTime(tt.input)
		if got != tt.want {
			t.Errorf("RelativeTime(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRelativeTimeOld(t *testing.T) {
	old := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	got := RelativeTime(old)
	if got != "2026-03-15" {
		t.Errorf("RelativeTime(old date) = %q, want date string", got)
	}
}

func TestTableHeader(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 4, ' ', 0)
	TableHeader(tw, "NAME", "HOST", "SOURCE")
	tw.Flush()
	got := buf.String()
	if !strings.Contains(got, "NAME") || !strings.Contains(got, "HOST") || !strings.Contains(got, "SOURCE") {
		t.Errorf("TableHeader should contain column names, got: %q", got)
	}
}

func TestFormatError(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	err := FormatError(&buf, "project not initialized", "Run veil init to get started")
	if err == nil {
		t.Error("FormatError should return a non-nil error")
	}
	got := buf.String()
	if !strings.Contains(got, "error:") {
		t.Errorf("FormatError should contain 'error:', got: %q", got)
	}
	if !strings.Contains(got, "project not initialized") {
		t.Errorf("FormatError should contain message, got: %q", got)
	}
	if !strings.Contains(got, "veil init") {
		t.Errorf("FormatError should contain hint, got: %q", got)
	}
}

func TestFormatErrorNoHint(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	_ = FormatError(&buf, "no value provided", "")
	got := buf.String()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 1 {
		t.Errorf("FormatError with no hint should be 1 line, got %d: %q", len(lines), got)
	}
}

func TestFormatWarning(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	FormatWarning(&buf, "2 credentials have no host scope", "Use veil add --host to scope them")
	got := buf.String()
	if !strings.Contains(got, "warning:") {
		t.Errorf("FormatWarning should contain 'warning:', got: %q", got)
	}
	if !strings.Contains(got, "2 credentials have no host scope") {
		t.Errorf("FormatWarning should contain message, got: %q", got)
	}
}
