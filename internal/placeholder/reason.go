package placeholder

import "strings"

// ReasonKind identifies which gate inside DetectWithReason fired. Used by
// the init command to annotate the Managed-by-Veil summary so a user can
// see why each value was classified as a secret.
type ReasonKind int

const (
	// ReasonNone means the value did not match any gate; the detection
	// returned false.
	ReasonNone ReasonKind = iota
	// ReasonProvider means a registered provider pattern matched. The
	// Reason's Detail field carries the provider name (e.g. "openai").
	ReasonProvider
	// ReasonKeyName means the key-name heuristic matched. The Reason's
	// Detail field carries the matched hint substring (e.g. "key",
	// "token"); the same value also cleared the value-shape floor.
	ReasonKeyName
	// ReasonEntropy means the length+entropy+distinct-byte heuristic
	// matched.
	ReasonEntropy
)

// String returns a stable lowercase token used in user-facing annotation.
func (k ReasonKind) String() string {
	switch k {
	case ReasonProvider:
		return "provider"
	case ReasonKeyName:
		return "name"
	case ReasonEntropy:
		return "entropy"
	default:
		return "none"
	}
}

// Reason describes which gate inside DetectWithReason fired and carries
// optional detail (provider name, matched key hint).
type Reason struct {
	Kind   ReasonKind
	Detail string
}

// Annotation returns a parenthesized tag suitable for appending to a
// Managed-by-Veil summary line — e.g. "(provider:openai)", "(name:token)",
// "(entropy)". Returns "" for ReasonNone so callers can skip the trailing
// tag for non-detections.
func (r Reason) Annotation() string {
	if r.Kind == ReasonNone {
		return ""
	}
	if r.Detail != "" {
		return "(" + r.Kind.String() + ":" + r.Detail + ")"
	}
	return "(" + r.Kind.String() + ")"
}

// Confidence groups detection reasons into HIGH/LOW bands. Provider matches
// are structural — they identify a credential by shape — so they sit in the
// HIGH band. Key-name and entropy gates are heuristic; the value could
// plausibly be something other than a real credential, so they sit in the
// LOW band.
type Confidence int

const (
	// ConfidenceNone is the zero value for non-detections.
	ConfidenceNone Confidence = iota
	// ConfidenceHigh: structural match (provider pattern).
	ConfidenceHigh
	// ConfidenceLow: heuristic match (key name or value entropy).
	ConfidenceLow
)

// Confidence classifies the reason into HIGH/LOW bands.
func (r Reason) Confidence() Confidence {
	switch r.Kind {
	case ReasonProvider:
		return ConfidenceHigh
	case ReasonKeyName, ReasonEntropy:
		return ConfidenceLow
	}
	return ConfidenceNone
}

// secretNameHints lists the substrings matched by the key-name heuristic,
// in the order they should be reported. The first hint contained in the
// upper-cased name wins. Order matters for overlapping hints
// (e.g. "PASSWD" contains "PWD" — but PASSWD is checked first).
var secretNameHints = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN", "CREDENTIAL",
	"AUTH", "KEY", "PWD", "DSN",
}

// matchedKeyHint returns the lowercase hint substring that matched name,
// or "" when none do. Mirrors the substrings encoded in secretNamePattern.
func matchedKeyHint(name string) string {
	upper := strings.ToUpper(name)
	for _, h := range secretNameHints {
		if strings.Contains(upper, h) {
			return strings.ToLower(h)
		}
	}
	return ""
}

// DetectWithReason runs the same gate order as IsSecretLike and returns
// which gate matched. The boolean result mirrors IsSecretLike so callers
// can use DetectWithReason as a drop-in replacement when they need the
// gate identity in addition to the yes/no answer.
func DetectWithReason(name, value string) (bool, Reason) {
	// Pre-gates: public-bundle prefixes and stub values short-circuit
	// to (false, ReasonNone). These mirror IsSecretLike exactly.
	if hasPublicEnvPrefix(name) {
		return false, Reason{Kind: ReasonNone}
	}
	if isStubValue(value) {
		return false, Reason{Kind: ReasonNone}
	}

	// 1. Provider patterns (Priority-sorted).
	for _, p := range DefaultRegistry().All() {
		if p.Match(name, value) {
			return true, Reason{Kind: ReasonProvider, Detail: p.Name}
		}
	}

	// 2. Key name heuristic, gated by value shape.
	if secretNamePattern.MatchString(name) {
		if len(value) >= nameMatchMinLength && distinctBytes(value) >= nameMatchMinDistinct {
			return true, Reason{Kind: ReasonKeyName, Detail: matchedKeyHint(name)}
		}
	}

	// 3. Length + entropy + distinct-byte check.
	if len(value) >= secretMinLength &&
		shannonEntropy(value) >= secretMinEntropy &&
		distinctBytes(value) >= secretMinDistinct {
		return true, Reason{Kind: ReasonEntropy}
	}

	return false, Reason{Kind: ReasonNone}
}
