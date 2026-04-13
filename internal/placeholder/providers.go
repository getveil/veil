package placeholder

import "strings"

// ProviderPattern describes a secret pattern that can be matched and replaced
// with a structurally-valid placeholder.
type ProviderPattern struct {
	Name     string
	Match    func(name, value string) bool
	Generate func(value string) string
	Hosts    []string // curated host set for this provider
}

// registry holds all registered provider patterns, checked in order.
var registry []ProviderPattern

// register adds a provider pattern to the registry.
func register(p ProviderPattern) {
	registry = append(registry, p)
}

// Format describes a secret format that can be matched and replaced using
// declarative fields instead of hand-authored Match/Generate functions.
type Format struct {
	Name     string
	Prefixes []string // value prefixes to match, e.g. ["ghp_", "github_pat_"]
	KeyHints []string // substrings to match in env key name (case-insensitive)
	Length   int      // total output length including prefix (0 = match input length)
	Charset  string   // "alphanumeric", "hex", "base64", "upper-alphanumeric"
	Hosts    []string
}

// registerFormat constructs a ProviderPattern from a Format and appends it
// to the registry.
func registerFormat(f Format) {
	p := ProviderPattern{
		Name:  f.Name,
		Hosts: f.Hosts,
		Match: func(name, value string) bool {
			for _, pfx := range f.Prefixes {
				if strings.HasPrefix(value, pfx) {
					return true
				}
			}
			upper := strings.ToUpper(name)
			for _, hint := range f.KeyHints {
				if strings.Contains(upper, strings.ToUpper(hint)) {
					return true
				}
			}
			return false
		},
		Generate: func(value string) string {
			prefix := ""
			for _, pfx := range f.Prefixes {
				if strings.HasPrefix(value, pfx) {
					prefix = pfx
					break
				}
			}
			total := f.Length
			if total == 0 {
				total = len(value)
			}
			rest := total - len(prefix)
			if rest < 0 {
				rest = 0
			}
			var body string
			switch f.Charset {
			case "hex":
				body = randFromAlphabet(rest, "0123456789abcdef")
			case "base64":
				body = randBase64ish(rest)
			case "upper-alphanumeric":
				body = randUpperAlphanumeric(rest)
			default:
				body = randAlphanumeric(rest)
			}
			return prefix + body
		},
	}
	register(p)
}
