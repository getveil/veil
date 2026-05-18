package correlate

import "regexp"

// basicUserRegex captures decoration around a USERNAME / USER token.
// `(?:NAME)?` is non-capturing so submatch indices stay at 1=prefix,
// 2=middle, 3=suffix. The `.*?` is non-greedy so the shortest prefix
// wins (`DB_USERNAME` -> prefix=`DB_`, middle=`USERNAME`, suffix=``).
var basicUserRegex = regexp.MustCompile(`^(.*?)(USER(?:NAME)?)(.*)$`)

// basicPasswordPartners lists the partner middle tokens to try, in
// preference order. PASSWORD is preferred over PASS so a project that
// defines both gets paired against the canonical name.
var basicPasswordPartners = []string{"PASSWORD", "PASS"}

// basicCorrelator pairs a username candidate with its password partner
// using shared decoration matching. The username half is intentionally
// NOT value-shape gated — typical USERNAME values are short non-secret
// identifiers like "alice" or "8enji". The password half must clear
// hasBasicPasswordShape to avoid pairing fixture-style trivial values
// (DB_USER=test, DB_PASSWORD=test).
type basicCorrelator struct{}

// Detect emits one Group per username candidate that has a valid
// password partner. Iteration order is the input slice order, so when
// multiple username vars share a partner, the first-listed wins (the
// rest fall into remaining).
func (basicCorrelator) Detect(candidates []Candidate) (groups []Group, remaining []Candidate) {
	byKey := make(map[string]Candidate, len(candidates))
	for _, c := range candidates {
		byKey[c.Key] = c
	}
	consumed := make(map[string]struct{}, len(candidates))

	for _, c := range candidates {
		if _, done := consumed[c.Key]; done {
			continue
		}
		// Refuse empty username — the proxy's tryRewriteBasic rejects
		// credentials with empty Username (basic_decoder.go:92), so a
		// paired-but-empty-user cred would just fail to swap.
		if c.Value == "" {
			continue
		}
		m := basicUserRegex.FindStringSubmatch(c.Key)
		if m == nil {
			continue
		}
		prefix, suffix := m[1], m[3]

		var passKey string
		var passCand Candidate
		var found bool
		for _, word := range basicPasswordPartners {
			partner := prefix + word + suffix
			if _, alreadyPaired := consumed[partner]; alreadyPaired {
				continue
			}
			if p, ok := byKey[partner]; ok {
				passKey = partner
				passCand = p
				found = true
				break
			}
		}
		if !found {
			continue
		}
		if !hasBasicPasswordShape(passCand.Value) {
			continue
		}

		groups = append(groups, Group{
			Scheme:  "basic",
			Name:    passKey,
			Members: []Candidate{c, passCand},
			Basic: &BasicGroup{
				Username:    c.Value,
				Password:    passCand.Value,
				UsernameVar: c.Key,
				PasswordVar: passKey,
			},
		})
		consumed[c.Key] = struct{}{}
		consumed[passKey] = struct{}{}
	}

	for _, c := range candidates {
		if _, done := consumed[c.Key]; done {
			continue
		}
		remaining = append(remaining, c)
	}
	return groups, remaining
}

// basicPasswordMinLength and basicPasswordMinDistinct mirror the floors
// in internal/placeholder/secretlike.go (nameMatchMinLength /
// nameMatchMinDistinct). Kept local to keep the correlate package free
// of a placeholder dependency.
const (
	basicPasswordMinLength   = 12
	basicPasswordMinDistinct = 6
)

// hasBasicPasswordShape reports whether v looks like a real password
// (non-trivial length and enough distinct bytes to rule out repetitive
// fixtures).
func hasBasicPasswordShape(v string) bool {
	if len(v) < basicPasswordMinLength {
		return false
	}
	var seen [256]bool
	n := 0
	for i := 0; i < len(v); i++ {
		if !seen[v[i]] {
			seen[v[i]] = true
			n++
		}
	}
	return n >= basicPasswordMinDistinct
}
