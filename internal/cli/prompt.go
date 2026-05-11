package cli

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/getveil/veil/internal/ui"
)

type ynsChoice int

const (
	choiceYes ynsChoice = iota
	choiceNo
	choiceSelect
)

// promptYNS asks a Y/n/select question. Default is Y (empty input = yes).
func promptYNS(r io.Reader, w io.Writer, question string) ynsChoice {
	_, _ = fmt.Fprintf(w, "%s %s ", question, ui.Bold.Sprint("(Y/n/select):"))
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return choiceYes
	}
	input := strings.TrimSpace(strings.ToLower(scanner.Text()))
	switch input {
	case "", "y", "yes":
		return choiceYes
	case "n", "no":
		return choiceNo
	case "s", "select":
		return choiceSelect
	default:
		return choiceYes
	}
}

// promptYN asks a yes/no question with the given default.
func promptYN(r io.Reader, w io.Writer, question string, defaultYes bool) bool {
	hint := "(y/N)"
	if defaultYes {
		hint = "(Y/n)"
	}
	_, _ = fmt.Fprintf(w, "%s %s ", question, ui.Bold.Sprint(hint))
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return defaultYes
	}
	input := strings.TrimSpace(strings.ToLower(scanner.Text()))
	switch input {
	case "":
		return defaultYes
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return defaultYes
	}
}

// promptCSV asks for comma-separated input and returns trimmed, non-empty values.
// Returns nil if the user enters nothing.
func promptCSV(r io.Reader, w io.Writer, prompt string) []string {
	_, _ = fmt.Fprintf(w, "%s ", prompt)
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return nil
	}
	raw := strings.TrimSpace(scanner.Text())
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// promptMultiSelect displays numbered items and lets the user pick by typing
// comma-separated numbers. Empty input selects all. Returns the selected items
// in their original order.
func promptMultiSelect(r io.Reader, w io.Writer, items []string) []string {
	for i, item := range items {
		_, _ = fmt.Fprintf(w, "  %s %s\n", ui.Muted.Sprintf("[%d]", i+1), item)
	}
	_, _ = fmt.Fprintf(w, "\n%s ", ui.Bold.Sprint("Select (comma-separated numbers, or Enter for all):"))

	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return items
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" {
		return items
	}

	selectedSet := make(map[int]bool)
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > len(items) {
			continue
		}
		selectedSet[n-1] = true
	}

	var selected []string
	for i, item := range items {
		if selectedSet[i] {
			selected = append(selected, item)
		}
	}
	return selected
}
