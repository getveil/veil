package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
)

// canonicalURI normalizes the path portion of a URL per SigV4.
// S3 preserves consecutive slashes and dot segments; other services collapse
// them via path.Clean. Each path segment is URI-encoded (unreserved chars
// left alone, everything else %-encoded).
func canonicalURI(rawPath string, isS3 bool) string {
	if rawPath == "" {
		return "/"
	}
	cleaned := rawPath
	if !isS3 {
		// path.Clean strips a trailing slash unless path is "/"; SigV4 keeps
		// it when the original path ended with one (so "/foo/./bar/.." →
		// "/foo/"). Re-append the slash when the input ended with a slash
		// or a dot-segment ("." or "..") that resolved to a directory.
		cleaned = path.Clean(rawPath)
		endsInDir := strings.HasSuffix(rawPath, "/") ||
			strings.HasSuffix(rawPath, "/.") ||
			strings.HasSuffix(rawPath, "/..") ||
			rawPath == "." || rawPath == ".."
		if endsInDir && cleaned != "/" {
			cleaned += "/"
		}
	}
	// Percent-encode each segment. We split on "/" to preserve slashes
	// (encoded slashes are only valid for S3, which is left raw above).
	parts := strings.Split(cleaned, "/")
	for i, p := range parts {
		parts[i] = pathEscape(p)
	}
	return strings.Join(parts, "/")
}

// pathEscape percent-encodes a single URI path segment per RFC 3986
// unreserved rules (A-Z a-z 0-9 - . _ ~ are left unescaped).
func pathEscape(seg string) string {
	var b strings.Builder
	b.Grow(len(seg))
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			const hex = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0F])
		}
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z':
		return true
	case 'a' <= c && c <= 'z':
		return true
	case '0' <= c && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	}
	return false
}

// canonicalQueryString parses, sorts by name then value, and URI-encodes
// query parameters per SigV4 rules.
func canonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)

	var b strings.Builder
	first := true
	for _, name := range names {
		vs := append([]string(nil), values[name]...)
		sort.Strings(vs)
		for _, v := range vs {
			if !first {
				b.WriteByte('&')
			}
			first = false
			// AWS SigV4 mandates %20 for spaces (not the '+' that
			// url.QueryEscape emits for application/x-www-form-urlencoded).
			b.WriteString(strings.ReplaceAll(url.QueryEscape(name), "+", "%20"))
			b.WriteByte('=')
			b.WriteString(strings.ReplaceAll(url.QueryEscape(v), "+", "%20"))
		}
	}
	return b.String()
}

// canonicalHeaders emits the selected headers, lowercased name, whitespace-
// trimmed value, terminated by '\n', in the order supplied by signedHeaders.
func canonicalHeaders(hdr http.Header, signedHeaders []string) string {
	var b strings.Builder
	for _, name := range signedHeaders {
		b.WriteString(strings.ToLower(name))
		b.WriteByte(':')
		values := hdr.Values(name)
		joined := strings.Join(values, ",")
		b.WriteString(trimInnerWhitespace(joined))
		b.WriteByte('\n')
	}
	return b.String()
}

// sigV4Auth is the parsed form of an AWS4-HMAC-SHA256 Authorization header.
type sigV4Auth struct {
	AccessKeyID   string
	Date          string
	Region        string
	Service       string
	SignedHeaders []string
	Signature     string
}

// parseSigV4Authorization parses an "AWS4-HMAC-SHA256 …" header value.
func parseSigV4Authorization(value string) (sigV4Auth, error) {
	const prefix = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(value, prefix) {
		return sigV4Auth{}, fmt.Errorf("not a SigV4 header")
	}
	rest := value[len(prefix):]

	var (
		cred    string
		signed  string
		sig     string
		haveAll = 0
	)
	for _, part := range strings.Split(rest, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "Credential":
			cred = kv[1]
			haveAll++
		case "SignedHeaders":
			signed = kv[1]
			haveAll++
		case "Signature":
			sig = kv[1]
			haveAll++
		}
	}
	if haveAll != 3 {
		return sigV4Auth{}, fmt.Errorf("authorization missing Credential/SignedHeaders/Signature")
	}
	parts := strings.Split(cred, "/")
	if len(parts) != 5 || parts[4] != "aws4_request" {
		return sigV4Auth{}, fmt.Errorf("malformed Credential scope: %q", cred)
	}
	return sigV4Auth{
		AccessKeyID:   parts[0],
		Date:          parts[1],
		Region:        parts[2],
		Service:       parts[3],
		SignedHeaders: strings.Split(signed, ";"),
		Signature:     sig,
	}, nil
}

// deriveSigningKey computes kSigning per SigV4 spec:
//
//	kSecret  = "AWS4" + secret
//	kDate    = HMAC(kSecret, date)
//	kRegion  = HMAC(kDate, region)
//	kService = HMAC(kRegion, service)
//	kSigning = HMAC(kService, "aws4_request")
func deriveSigningKey(secretAccessKey, date, region, service string) []byte {
	kSecret := []byte("AWS4" + secretAccessKey)
	kDate := hmacSHA256(kSecret, []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum)
}

// trimInnerWhitespace trims surrounding whitespace and collapses internal
// runs of whitespace to a single space.
func trimInnerWhitespace(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if !prevSpace {
				b.WriteByte(' ')
			}
			prevSpace = true
			continue
		}
		prevSpace = false
		b.WriteRune(r)
	}
	return b.String()
}
