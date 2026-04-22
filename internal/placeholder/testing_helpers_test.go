package placeholder

import "testing"

// mustProvider returns the registered provider with the given name, or fails
// the test if none is registered. Uses the package-level DefaultRegistry()
// (public API) rather than iterating the private registry slice.
func mustProvider(t *testing.T, name string) ProviderPattern {
	t.Helper()
	p, ok := DefaultRegistry().Get(name)
	if !ok {
		t.Fatalf("%s provider not registered", name)
	}
	return p
}
