package placeholder

// Priority controls the order in which the registry resolves matches.
// Higher Priority runs first. Providers registered within the same tier
// are matched in registration order (stable sort).
//
// The Registry sorts its backing slice on first call to Match/All/Names
// via a sync.Once, so adding a provider after resolution has started is
// not supported (all init() calls run before any Generate is called).
const (
	// PriorityHandwritten is the priority for hand-written providers that
	// implement custom Match/Generate logic — e.g. supabase's JWT builder,
	// github's multi-segment fine-grained PAT structure, aws's two-shape
	// access-key / secret-key split. These run before declarative Format
	// providers so that a value matching a specific hand-written shape is
	// resolved by that provider even if a Format entry would also match by
	// keyhint.
	PriorityHandwritten = 100

	// PriorityFormat is the default priority for declarative Format
	// providers registered via registerFormat. Format providers are matched
	// after any applicable hand-written provider.
	PriorityFormat = 50
)
