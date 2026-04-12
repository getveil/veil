package placeholder

// ProviderPattern describes a secret pattern that can be matched and replaced
// with a structurally-valid placeholder.
type ProviderPattern struct {
	Name     string
	Match    func(name, value string) bool
	Generate func(value string) string
}

// registry holds all registered provider patterns, checked in order.
var registry []ProviderPattern

// Register adds a provider pattern to the registry.
func Register(p ProviderPattern) {
	registry = append(registry, p)
}
