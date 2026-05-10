package placeholder

import (
	"sort"
	"strings"
	"sync"
)

// ProviderPattern describes a secret pattern that can be matched and replaced
// with a structurally-valid placeholder. Generate receives the same (name,
// value) pair as Match so providers can choose a placeholder shape based on
// the credential's role rather than guessing from the value alone — required
// for fields like AWS where the role (AKID vs secret) cannot always be
// inferred from the value's prefix.
type ProviderPattern struct {
	Name     string
	Match    func(name, value string) bool
	Generate func(name, value string) string
	Hosts    []string // curated host set for this provider
	Priority int      // higher runs first; see priority.go for tiers
}

// registry holds all registered provider patterns, checked in order of
// Priority (descending). This is the package-level default, populated by
// init() in provider_*.go files. Isolated Registry instances (for tests) do
// not share this slice.
var registry []ProviderPattern

// defaultSortMu serializes Priority-descending sorts of the package-level
// registry slice inside DefaultRegistry. Using a package-level mutex (rather
// than a per-wrapper sync.Once) ensures that concurrent callers of
// DefaultRegistry cannot sort the shared backing array simultaneously.
var defaultSortMu sync.Mutex

// register adds a provider pattern to the default registry.
func register(p ProviderPattern) {
	registry = append(registry, p)
}

// Registry holds a set of provider patterns. Use NewRegistry to construct an
// isolated registry for tests; DefaultRegistry returns a view over the
// package-level slice populated at init() time.
//
// Patterns are sorted by Priority (descending, stable) on first call to
// Match/All/Names. Calling register() after sortPatterns has fired produces
// undefined ordering — in practice all register() calls run during package
// init(), before any user code invokes these methods.
type Registry struct {
	patterns []ProviderPattern
	sortOnce sync.Once
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{} }

// Register appends a provider pattern.
func (r *Registry) Register(p ProviderPattern) {
	r.patterns = append(r.patterns, p)
}

// sortPatterns sorts r.patterns by Priority descending (stable) the first
// time it is called. Subsequent calls are no-ops. This path is used by
// isolated Registry instances (NewRegistry); wrappers returned by
// DefaultRegistry already hold a pre-sorted private snapshot and have their
// sortOnce pre-fired so this method is a no-op for them.
func (r *Registry) sortPatterns() {
	r.sortOnce.Do(func() {
		sort.SliceStable(r.patterns, func(i, j int) bool {
			return r.patterns[i].Priority > r.patterns[j].Priority
		})
	})
}

// Match returns the first provider whose Match returns true, or nil if none.
// Patterns are checked in Priority-descending order.
func (r *Registry) Match(name, value string) *ProviderPattern {
	r.sortPatterns()
	for i := range r.patterns {
		if r.patterns[i].Match(name, value) {
			return &r.patterns[i]
		}
	}
	return nil
}

// Get returns the provider with the given name, or (zero, false).
func (r *Registry) Get(name string) (ProviderPattern, bool) {
	r.sortPatterns()
	for _, p := range r.patterns {
		if p.Name == name {
			return p, true
		}
	}
	return ProviderPattern{}, false
}

// All returns the registered patterns sorted by Priority descending.
// For wrappers returned by DefaultRegistry the slice is a private copy;
// for NewRegistry wrappers it references the wrapper's own slice.
// Callers must not append to or sort the returned slice.
func (r *Registry) All() []ProviderPattern {
	r.sortPatterns()
	return r.patterns
}

// Names returns the names of all registered providers in Priority-descending
// order. Useful for contract tests that want to enumerate the registry
// without hard-coding a list.
func (r *Registry) Names() []string {
	r.sortPatterns()
	out := make([]string, len(r.patterns))
	for i, p := range r.patterns {
		out[i] = p.Name
	}
	return out
}

// DefaultRegistry returns a Registry view over the package-level registry.
// The package-level defaultSortMu serializes the sort so that concurrent
// callers cannot sort the shared backing array simultaneously, and the
// returned wrapper holds a defensive copy of the sorted slice so iteration
// on one wrapper never races a sort on another.
//
// Each call returns a fresh wrapper so tests that mutate the package-level
// slice (e.g. `registry = registry[:before]`) still see the current state.
func DefaultRegistry() *Registry {
	defaultSortMu.Lock()
	sort.SliceStable(registry, func(i, j int) bool {
		return registry[i].Priority > registry[j].Priority
	})
	// Defensive copy: the returned wrapper gets its own backing array so
	// that concurrent DefaultRegistry() sorts on the package-level slice
	// cannot race with iteration over this wrapper's patterns.
	snap := make([]ProviderPattern, len(registry))
	copy(snap, registry)
	defaultSortMu.Unlock()
	// Return a wrapper whose sortOnce is already "fired" so its own
	// sortPatterns is a no-op (the snapshot is already sorted).
	r := &Registry{patterns: snap}
	r.sortOnce.Do(func() {}) // mark as sorted; no re-sort needed
	return r
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
	Priority int // optional; defaults to PriorityFormat if zero
}

// registerFormat constructs a ProviderPattern from a Format and appends it
// to the registry.
func registerFormat(f Format) {
	// Sort prefixes by length descending so Match and Generate always pick
	// the longest matching prefix. Without this, callers who register
	// ["sk-", "sk-ant-"] see Generate produce "sk-..." losing the "ant-"
	// segment — a silent correctness bug.
	prefixes := make([]string, len(f.Prefixes))
	copy(prefixes, f.Prefixes)
	sort.SliceStable(prefixes, func(i, j int) bool {
		return len(prefixes[i]) > len(prefixes[j])
	})

	priority := f.Priority
	if priority == 0 {
		priority = PriorityFormat
	}

	p := ProviderPattern{
		Name:     f.Name,
		Hosts:    f.Hosts,
		Priority: priority,
		Match: func(name, value string) bool {
			for _, pfx := range prefixes {
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
		Generate: func(_, value string) string {
			prefix := ""
			for _, pfx := range prefixes {
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
