// Package correlate detects related credential groups among flat lists of
// secret-like env-var candidates. Init phases call DetectAll to distinguish
// scheme-requiring groups (e.g., AWS SigV4 triples) from loose bearer-style
// secrets. This file is the dispatch + types only; per-scheme logic lives
// in sibling files (aws.go, etc.).
package correlate

// Candidate is one secret-like key/value pair fed into the correlator.
// Matches the shape already built internally by processEnvFile and
// processShellEnv.
type Candidate struct {
	Key   string
	Value string
}

// Group is one correlated credential, ready to be vaulted as a scheme.
// Scheme-specific payload is discriminated by Scheme.
type Group struct {
	Scheme  string
	Name    string
	Members []Candidate
	AWS     *AWSGroup
	Basic   *BasicGroup
}

// AWSGroup carries the real values and source variable names for an AWS
// credential group.
type AWSGroup struct {
	AccessKeyID     string
	SecretKey       string
	SessionToken    string
	AccessKeyIDVar  string
	SecretKeyVar    string
	SessionTokenVar string
}

// BasicGroup carries the real values and source variable names for an
// HTTP Basic credential pair. UsernameVar/PasswordVar hold the original
// env-var names so the init flow can rewrite the source file with
// placeholders for both halves.
type BasicGroup struct {
	Username    string
	Password    string
	UsernameVar string
	PasswordVar string
}

// Correlator consumes a flat list of secret-like candidates and returns
// correlation groups plus the remaining uncorrelated candidates.
type Correlator interface {
	Detect(candidates []Candidate) (groups []Group, remaining []Candidate)
}

// correlators is the fixed dispatch list. Adding a new scheme is one line
// here plus the sibling file. Order matters when schemes could overlap
// (in practice PEMs and AKIDs are structurally distinct, so overlap is
// unreachable).
var correlators = []Correlator{
	awsCorrelator{},
}

// DetectAll runs each registered correlator in order, passing only
// remaining (un-consumed) candidates to later correlators.
func DetectAll(candidates []Candidate) (groups []Group, remaining []Candidate) {
	remaining = candidates
	for _, c := range correlators {
		g, r := c.Detect(remaining)
		groups = append(groups, g...)
		remaining = r
	}
	return groups, remaining
}
