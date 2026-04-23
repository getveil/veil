package proxy

import (
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/vault"
	"github.com/cloudflare/ahocorasick"
)

// defaultBodyCap is the maximum body size the injector will scan (10 MiB).
const defaultBodyCap = 10 * 1024 * 1024

// Injector performs Aho-Corasick multi-pattern matching to replace placeholder
// strings with real secret values in HTTP requests.
type Injector struct {
	mu       sync.RWMutex
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

// Reload rebuilds the AC matcher and credential map for vault reload during
// runtime.
func (inj *Injector) Reload(placeholderMap map[string]*vault.Credential) {
	patterns, creds := extractPatterns(placeholderMap)
	var matcher *ahocorasick.Matcher
	if len(patterns) > 0 {
		matcher = ahocorasick.NewStringMatcher(patterns)
	}
	inj.mu.Lock()
	inj.matcher = matcher
	inj.patterns = patterns
	inj.creds = creds
	inj.mu.Unlock()
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
	inj.mu.RLock()
	matcher := inj.matcher
	patterns := inj.patterns
	creds := inj.creds
	inj.mu.RUnlock()

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

	// --- Basic auth pre-pass ---
	// Decode Authorization / Proxy-Authorization Basic headers and rewrite them
	// with real user:secret pairs before the literal Aho-Corasick scan sees the
	// (already-rewritten) bytes. Swaps produced here participate in the same
	// audit-injection stream as literal matches.
	basicSwaps := decodeAndSwapBasic(newHeader, creds, host)
	for _, s := range basicSwaps {
		s.RequestID = requestID
		s.Method = method
		s.URLPath = urlPath
		s.AgentPID = inj.agentPID
		s.AgentCmd = inj.agentCmd
		injections = append(injections, s)
	}

	// --- AWS SigV4 signer ---
	// Run the SigV4 re-signer between the Basic pre-pass and the literal
	// header scan. This ensures the SDK-supplied placeholder AKID is
	// rewritten and the Authorization signature is recomputed before the
	// Aho-Corasick header pass would otherwise blindly substitute the
	// placeholder bytes (producing a malformed Authorization header).
	shim := &http.Request{
		Method: method,
		Header: newHeader,
	}
	if u, err := url.Parse(newURL); err == nil {
		shim.URL = u
	} else {
		shim.URL = &url.URL{}
	}
	awsInjs, _ := signAWSSigV4(shim, body, creds, host)
	for _, s := range awsInjs {
		s.RequestID = requestID
		s.Method = method
		s.URLPath = urlPath
		s.AgentPID = inj.agentPID
		s.AgentCmd = inj.agentCmd
		injections = append(injections, s)
	}
	// signAWSSigV4 may have mutated shim.Header; persist those changes.
	newHeader = shim.Header

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

	// --- Mismatch detector (post-pass) ---
	if !anyNonBlocked(injections) {
		credList := dedupCredentials(creds)
		parsedURL, _ := url.Parse(rawURL)
		if sig, names, fired := detectMismatch(host, parsedURL, newHeader, 0, credList); fired {
			logMismatch(os.Stderr, host, urlPath, method, sig, names)
			injections = append(injections, audit.Injection{
				Timestamp:   now,
				RequestID:   requestID,
				Host:        host,
				Method:      method,
				URLPath:     urlPath,
				AgentPID:    inj.agentPID,
				AgentCmd:    inj.agentCmd,
				Location:    "mismatch_suspected",
				SuspectFlag: true,
				AuthSignal:  sig,
			})
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
	inj.mu.RLock()
	matcher := inj.matcher
	patterns := inj.patterns
	creds := inj.creds
	inj.mu.RUnlock()

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

// anyNonBlocked reports whether at least one injection is a real swap (not a
// blocked entry emitted when host scoping denied the swap, and not a suspect row).
func anyNonBlocked(injections []audit.Injection) bool {
	for _, i := range injections {
		if i.Location != "blocked" && !i.SuspectFlag {
			return true
		}
	}
	return false
}

// dedupCredentials collapses the placeholder map into a unique slice. Basic
// credentials appear twice in the map (under secret and username placeholders);
// this collapses them to one entry per credential pointer.
func dedupCredentials(pmap map[string]*vault.Credential) []*vault.Credential {
	seen := make(map[*vault.Credential]struct{}, len(pmap))
	out := make([]*vault.Credential, 0, len(pmap))
	for _, c := range pmap {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
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
