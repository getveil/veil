package proxy

import "strings"

// ShouldInjectBody reports whether the proxy should scan and rewrite the
// body for a request with the given Content-Type header value. Matching is
// case-insensitive and strict (allowlist): missing or unknown Content-Types
// return false. Media-type parameters (charset, boundary, etc.) are ignored.
func ShouldInjectBody(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/json",
		"application/x-www-form-urlencoded",
		"application/xml":
		return true
	}
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	if strings.HasPrefix(ct, "application/") &&
		(strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml")) {
		return true
	}
	return false
}
