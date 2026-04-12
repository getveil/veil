package placeholder

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
