package placeholder

import (
	"net"
	"net/url"
	"strings"
)

// allowedSchemes lists URL schemes that ExtractURLHost will accept. Only
// http/https are included: TCP-protocol schemes like postgres:// and redis://
// bypass Veil's HTTP proxy entirely, so scoping a credential to a host derived
// from them would never narrow a match. The allowlist also closes SEC-8: a
// crafted env var like "javascript://evil.com" must not widen the proxy's
// allow-host set via HostsForCredential.
var allowedSchemes = map[string]bool{
	"http":  true,
	"https": true,
}

// HostMatches checks whether the given request host is authorized by the
// allowed hosts list. The host may include a port (e.g. "api.github.com:443")
// which is stripped before comparison. Allowed hosts entries are either exact
// hostnames or wildcard patterns like "*.amazonaws.com" (suffix match with
// leading dot to prevent partial matches).
func HostMatches(host string, allowedHosts []string) bool {
	if len(allowedHosts) == 0 {
		return false
	}
	host = stripPort(host)
	for _, allowed := range allowedHosts {
		if strings.HasPrefix(allowed, "*.") {
			// Wildcard suffix match: *.foo.com matches bar.foo.com
			// but not foo.com or notfoo.com.
			suffix := allowed[1:] // ".foo.com"
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
		} else if host == allowed {
			return true
		}
	}
	return false
}

// stripPort removes the port from a host:port string. If there is no port,
// the host is returned unchanged.
func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

// ExtractURLHost attempts to parse value as a URL and return the hostname
// (without port). Returns "" if value is not a parseable URL with a host,
// or if the URL scheme is outside allowedSchemes (http/https only).
func ExtractURLHost(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	if u.Host == "" || u.Scheme == "" {
		return ""
	}
	if !allowedSchemes[u.Scheme] {
		return ""
	}
	return stripPort(u.Host)
}

// HostsForCredential resolves the allowed hosts for a credential using the
// resolution chain:
//  1. Provider registry — if a provider matches, return its Hosts
//  2. URL parsing — if the value is URL-shaped, extract the host
//  3. Return nil (credential is inert until manually scoped)
func HostsForCredential(name, value string) []string {
	// 1. Check provider registry (registration-ordered after the launch
	// cuts dropped the handwritten-vs-format priority split).
	for _, p := range DefaultRegistry().All() {
		if p.Match(name, value) && len(p.Hosts) > 0 {
			hosts := make([]string, len(p.Hosts))
			copy(hosts, p.Hosts)
			return hosts
		}
	}

	// 2. Try URL host extraction.
	if h := ExtractURLHost(value); h != "" {
		return []string{h}
	}

	// 3. No hosts detected.
	return nil
}
