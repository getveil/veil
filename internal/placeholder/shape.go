package placeholder

// passesValueShapeGate reports whether value is plausibly credential-
// shaped: long enough AND varied enough to be a real token rather than
// a config literal, environment label, or short identifier.
//
// Returns true iff len(value) >= secretMinLength AND
// distinctBytes(value) >= nameMatchMinDistinct. Both constants live in
// secretlike.go and gate the IsSecretLike name-pattern path; reusing
// them keeps the model coherent rather than introducing parallel scales.
//
// This is the single chokepoint that all provider matching flows through:
// (*Registry).Match calls it before iterating providers, and
// HostsForCredential calls it before its provider-host loop. Hand-written
// providers no longer need to re-implement a length floor — the gate runs
// once, here, ahead of any per-provider Match.
func passesValueShapeGate(value string) bool {
	return len(value) >= secretMinLength &&
		distinctBytes(value) >= nameMatchMinDistinct
}
