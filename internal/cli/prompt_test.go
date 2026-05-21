package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseYNS_Defaults(t *testing.T) {
	tests := []struct {
		input string
		want  ynsChoice
	}{
		{"", choiceYes},
		{"\n", choiceYes},
		{"y\n", choiceYes},
		{"Y\n", choiceYes},
		{"n\n", choiceNo},
		{"N\n", choiceNo},
		{"select\n", choiceSelect},
		{"s\n", choiceSelect},
		{"S\n", choiceSelect},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			w := new(bytes.Buffer)
			got := promptYNS(r, w, "Test?")
			if got != tt.want {
				t.Errorf("input %q: got %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// TestPromptYNS_DisplaysShortHelpText verifies the prompt now advertises the
// terse "(Y/n/s)" form rather than the older "(Y/n/select)" — the legacy form
// implied "select" was the literal input, leaving users unsure if "s" alone
// would work. Both inputs continue to map to choiceSelect (covered above).
func TestPromptYNS_DisplaysShortHelpText(t *testing.T) {
	r := strings.NewReader("y\n")
	w := new(bytes.Buffer)
	_ = promptYNS(r, w, "Vault all?")
	got := w.String()
	if !strings.Contains(got, "(Y/n/s)") {
		t.Errorf("prompt should advertise %q, got: %s", "(Y/n/s)", got)
	}
	if strings.Contains(got, "(Y/n/select)") {
		t.Errorf("prompt should NOT still advertise %q, got: %s", "(Y/n/select)", got)
	}
}

func TestParseCSV_Hosts(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"\n", nil},
		{"api.anthropic.com\n", []string{"api.anthropic.com"}},
		{"api.anthropic.com, *.internal.com\n", []string{"api.anthropic.com", "*.internal.com"}},
		{"  api.anthropic.com , *.internal.com  \n", []string{"api.anthropic.com", "*.internal.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			w := new(bytes.Buffer)
			got := promptCSV(r, w, "Hosts:")
			if len(got) != len(tt.want) {
				t.Fatalf("input %q: got %v, want %v", tt.input, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("input %q [%d]: got %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestMultiSelect(t *testing.T) {
	items := []string{"GITHUB_TOKEN", "DATABASE_URL", "STRIPE_KEY"}
	input := "1,3\n"
	r := strings.NewReader(input)
	w := new(bytes.Buffer)

	selected := promptMultiSelect(r, w, items)
	if len(selected) != 2 {
		t.Fatalf("expected 2 selected, got %d: %v", len(selected), selected)
	}
	if selected[0] != "GITHUB_TOKEN" || selected[1] != "STRIPE_KEY" {
		t.Errorf("expected [GITHUB_TOKEN, STRIPE_KEY], got %v", selected)
	}
}

func TestMultiSelect_All(t *testing.T) {
	items := []string{"A", "B", "C"}
	r := strings.NewReader("\n")
	w := new(bytes.Buffer)

	selected := promptMultiSelect(r, w, items)
	if len(selected) != 3 {
		t.Fatalf("expected 3, got %d", len(selected))
	}
}

func TestPromptYN_Defaults(t *testing.T) {
	tests := []struct {
		input      string
		defaultYes bool
		want       bool
	}{
		{"\n", true, true},
		{"\n", false, false},
		{"y\n", false, true},
		{"n\n", true, false},
	}
	for _, tt := range tests {
		r := strings.NewReader(tt.input)
		w := new(bytes.Buffer)
		got := promptYN(r, w, "Continue?", tt.defaultYes)
		if got != tt.want {
			t.Errorf("input=%q default=%v: got %v, want %v", tt.input, tt.defaultYes, got, tt.want)
		}
	}
}
