package proxy

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/cloudflare/ahocorasick"
	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/placeholder"
	"github.com/getveil/veil/internal/vault"
)

// Note: the AWS SigV4, GitHub App JWT, and HTTP Basic decode-and-swap
// paths were removed in the v1 launch cut. The proxy now only performs
// literal placeholder substitution; outbound traffic whose authentication
// requires re-signing or username/password pairing is out of scope.

// defaultBodyCap is the maximum body size the injector will scan (10 MiB).
const defaultBodyCap = 10 * 1024 * 1024

// Injector performs Aho-Corasick multi-pattern matching to replace placeholder
// strings with real secret values in HTTP requests. All fields are set at
// construction and never mutated, so concurrent ProcessRequest / Replace
// calls don't need synchronization.
type Injector struct {
	matcher  *ahocorasick.Matcher
	patterns []string                     // ordered slice of placeholder strings
	creds    map[string]*vault.Credential // placeholder -> credential
	audit    *audit.Store                 // nil = no audit
	agentPID int
	agentCmd string
	bodyCap  int // max body size to scan (bytes)
}

// NewInjector creates an Injector from a placeholder map. The auditStore may be
// nil to disable audit recording.
func NewInjector(placeholderMap map[string]*vault.Credential, auditStore *audit.Store, agentPID int, agentCmd string) *Injector {
	patterns, creds := extractPatterns(placeholderMap)
	var matcher *ahocorasick.Matcher
	if len(patterns) > 0 {
		matcher = ahocorasick.NewStringMatcher(patterns)
	}
	return &Injector{
		matcher:  matcher,
		patterns: patterns,
		creds:    creds,
		audit:    auditStore,
		agentPID: agentPID,
		agentCmd: agentCmd,
		bodyCap:  defaultBodyCap,
	}
}

// ProcessRequest scans a request's URL, headers, and body for placeholder
// strings and replaces them with real secret values. It returns the modified
// components and a slice of audit injection records.
func (inj *Injector) ProcessRequest(
	requestID string,
	method string,
	rawURL string,
	header http.Header,
	body []byte,
) (newURL string, newHeader http.Header, newBody []byte, injections []audit.Injection) {
	matcher := inj.matcher
	patterns := inj.patterns
	creds := inj.creds

	now := time.Now()

	// Parse host and path from the URL for audit records. The raw query is
	// intentionally discarded here: it may contain placeholder-sized tokens,
	// and URLPath is logged in plaintext — keeping it path-only prevents a
	// secondary leak into audit storage. Query-string injection still works
	// because the URL-scanning block below runs Aho-Corasick against the
	// full rawURL.
	host, urlPath, _ := parseRequestURL(rawURL)

	// Helper to build an audit.Injection record.
	makeInjection := func(cred *vault.Credential, location string, before, after int) audit.Injection {
		return audit.Injection{
			Timestamp:      now,
			RequestID:      requestID,
			Host:           host,
			Method:         method,
			URLPath:        urlPath,
			CredentialID:   cred.ID,
			CredentialName: cred.Name,
			AgentPID:       inj.agentPID,
			AgentCmd:       inj.agentCmd,
			BytesBefore:    before,
			BytesAfter:     after,
			Location:       location,
		}
	}

	// --- URL scanning ---
	newURL = rawURL
	if matcher != nil {
		matched := matchedPatterns(matcher, []byte(rawURL), patterns)
		var evs []audit.Injection
		newURL, evs = applyMatched(rawURL, matched, creds, host, "url", makeInjection)
		injections = append(injections, evs...)
	}

	// --- Header scanning ---
	newHeader = header.Clone()

	if matcher != nil {
		for name, values := range newHeader {
			for i, v := range values {
				matched := matchedPatterns(matcher, []byte(v), patterns)
				if len(matched) == 0 {
					continue
				}
				out, evs := applyMatched(v, matched, creds, host, "header", makeInjection)
				values[i] = out
				injections = append(injections, evs...)
			}
			newHeader[name] = values
		}
	}

	// --- Body scanning ---
	newBody = body
	if matcher != nil && len(body) > 0 && len(body) <= inj.bodyCap {
		matched := matchedPatterns(matcher, body, patterns)
		if len(matched) > 0 {
			out, evs := applyMatched(string(body), matched, creds, host, "body", makeInjection)
			newBody = []byte(out)
			injections = append(injections, evs...)
		}
	}

	// Record injections to the audit store if configured.
	if inj.audit != nil {
		for _, injection := range injections {
			inj.audit.Record(injection)
		}
	}

	return newURL, newHeader, newBody, injections
}

// hostAuthorized checks if a credential is allowed to be injected for the given host.
func hostAuthorized(cred *vault.Credential, host string) bool {
	return placeholder.HostMatches(host, cred.AllowedHosts)
}

// Replace performs placeholder replacement on a single string and returns the
// result. It uses the AC matcher for detection, then strings.ReplaceAll for
// each matched pattern.
func (inj *Injector) Replace(input string) string {
	matcher := inj.matcher
	patterns := inj.patterns
	creds := inj.creds

	if matcher == nil {
		return input
	}

	matched := matchedPatterns(matcher, []byte(input), patterns)
	for _, placeholder := range matched {
		input = strings.ReplaceAll(input, placeholder, creds[placeholder].Real)
	}
	return input
}

// extractPatterns builds the ordered patterns slice and credential map from a
// placeholder map.
func extractPatterns(pm map[string]*vault.Credential) ([]string, map[string]*vault.Credential) {
	patterns := make([]string, 0, len(pm))
	creds := make(map[string]*vault.Credential, len(pm))
	for placeholder, cred := range pm {
		patterns = append(patterns, placeholder)
		creds[placeholder] = cred
	}
	return patterns, creds
}

// matchedPatterns runs the AC matcher and returns the deduplicated list of
// placeholder strings that were found in the input.
func matchedPatterns(matcher *ahocorasick.Matcher, input []byte, patterns []string) []string {
	hits := matcher.MatchThreadSafe(input)
	if len(hits) == 0 {
		return nil
	}
	result := make([]string, 0, len(hits))
	for _, idx := range hits {
		if idx >= 0 && idx < len(patterns) {
			result = append(result, patterns[idx])
		}
	}
	return result
}

// applyMatched rewrites input in a single pass, replacing each host-authorized
// placeholder in matched with its real value. Overlapping matches at the same
// start are resolved by longest-wins; matches that fall inside an already-
// applied replacement are skipped. Emits one audit injection per distinct
// matched placeholder: `location` for authorized swaps, "blocked" otherwise.
//
// SEC-7: the previous implementation called strings.ReplaceAll per matched
// placeholder in non-deterministic map-iteration order. Because each call
// operated on the output of the previous call, a real value that contained
// another credential's placeholder pattern would be corrupted when that
// credential's replacement ran afterward. The single-pass rewriter only ever
// indexes into the original input, so rewritten bytes are never re-scanned.
func applyMatched(
	input string,
	matched []string,
	creds map[string]*vault.Credential,
	host string,
	location string,
	makeInjection func(*vault.Credential, string, int, int) audit.Injection,
) (string, []audit.Injection) {
	if len(matched) == 0 {
		return input, nil
	}

	type site struct {
		start  int
		length int
		real   string
	}
	var sites []site
	for _, ph := range matched {
		cred := creds[ph]
		if !hostAuthorized(cred, host) {
			continue
		}
		phLen := len(ph)
		offset := 0
		for {
			idx := strings.Index(input[offset:], ph)
			if idx < 0 {
				break
			}
			sites = append(sites, site{
				start:  offset + idx,
				length: phLen,
				real:   cred.Real,
			})
			offset = offset + idx + phLen
		}
	}

	// Longest match at the same start wins; otherwise earliest start first.
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].start != sites[j].start {
			return sites[i].start < sites[j].start
		}
		return sites[i].length > sites[j].length
	})

	var b strings.Builder
	b.Grow(len(input))
	cursor := 0
	for _, s := range sites {
		if s.start < cursor {
			continue
		}
		b.WriteString(input[cursor:s.start])
		b.WriteString(s.real)
		cursor = s.start + s.length
	}
	b.WriteString(input[cursor:])
	output := b.String()

	before := len(input)
	after := len(output)
	events := make([]audit.Injection, 0, len(matched))
	for _, ph := range matched {
		cred := creds[ph]
		if hostAuthorized(cred, host) {
			events = append(events, makeInjection(cred, location, before, after))
		} else {
			events = append(events, makeInjection(cred, "blocked", 0, 0))
		}
	}
	return output, events
}

// parseRequestURL extracts host, path, and raw query from a URL. On parse
// failure all three are empty. Callers that want to avoid leaking query
// contents into audit logs should discard rawQuery.
func parseRequestURL(rawURL string) (host, path, rawQuery string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", ""
	}
	return u.Host, u.Path, u.RawQuery
}
