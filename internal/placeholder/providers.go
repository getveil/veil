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
// This is the package-level default, populated by init() in provider_*.go
// files. Isolated Registry instances (for tests) do not share this slice.
var registry []ProviderPattern

// register adds a provider pattern to the default registry.
func register(p ProviderPattern) {
	registry = append(registry, p)
}

// Registry holds a set of provider patterns, checked in registration order.
// Use NewRegistry to construct an isolated registry for tests; DefaultRegistry
// returns a view over the package-level slice populated at init() time.
type Registry struct {
	patterns []ProviderPattern
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{} }

// Register appends a provider pattern.
func (r *Registry) Register(p ProviderPattern) {
	r.patterns = append(r.patterns, p)
}

// Match returns the first provider whose Match returns true, or nil if none.
func (r *Registry) Match(name, value string) *ProviderPattern {
	for i := range r.patterns {
		if r.patterns[i].Match(name, value) {
			return &r.patterns[i]
		}
	}
	return nil
}

// Get returns the provider with the given name, or (zero, false).
func (r *Registry) Get(name string) (ProviderPattern, bool) {
	for _, p := range r.patterns {
		if p.Name == name {
			return p, true
		}
	}
	return ProviderPattern{}, false
}

// DefaultRegistry returns a Registry view over the package-level registry.
// The returned Registry's patterns slice references the same backing array,
// so iteration sees all providers registered via register(); however, a
// Registry obtained this way should be treated as read-only — use
// NewRegistry for tests that need to register provider patterns.
func DefaultRegistry() *Registry { return &Registry{patterns: registry} }

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
			// Embed Sentinel at the start of the body (see engine.go).
			return sentinelize(prefix+body, len(prefix))
		},
	}
	register(p)
}
