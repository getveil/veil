package proxy

import (
	"net/http"
	"net/url"
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
		for _, ph := range matched {
			cred := creds[ph]
			if hostAuthorized(cred, host) {
				before := len(newURL)
				newURL = strings.ReplaceAll(newURL, ph, cred.Real)
				after := len(newURL)
				injections = append(injections, makeInjection(cred, "url", before, after))
			} else {
				injections = append(injections, makeInjection(cred, "blocked", 0, 0))
			}
		}
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

	if matcher != nil {
		for name, values := range newHeader {
			for i, v := range values {
				matched := matchedPatterns(matcher, []byte(v), patterns)
				for _, ph := range matched {
					cred := creds[ph]
					if hostAuthorized(cred, host) {
						before := len(values[i])
						values[i] = strings.ReplaceAll(values[i], ph, cred.Real)
						after := len(values[i])
						injections = append(injections, makeInjection(cred, "header", before, after))
					} else {
						injections = append(injections, makeInjection(cred, "blocked", 0, 0))
					}
				}
			}
			newHeader[name] = values
		}
	}

	// --- Body scanning ---
	newBody = body
	if matcher != nil && len(body) > 0 && len(body) <= inj.bodyCap {
		matched := matchedPatterns(matcher, body, patterns)
		if len(matched) > 0 {
			s := string(body)
			for _, ph := range matched {
				cred := creds[ph]
				if hostAuthorized(cred, host) {
					before := len(s)
					s = strings.ReplaceAll(s, ph, cred.Real)
					after := len(s)
					injections = append(injections, makeInjection(cred, "body", before, after))
				} else {
					injections = append(injections, makeInjection(cred, "blocked", 0, 0))
				}
			}
			newBody = []byte(s)
		}
	}

	// --- Mismatch detector (post-pass) ---
	if !anyNonBlocked(injections) {
		credList := dedupCredentials(creds)
		parsedURL, _ := url.Parse(rawURL)
		if sig, _, fired := detectMismatch(host, parsedURL, newHeader, 0, credList); fired {
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
