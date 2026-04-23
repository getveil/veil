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
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/vault"
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

// signAWSSigV4 inspects the request for an AWS4-HMAC-SHA256 Authorization
// header and, when a matching vaulted credential exists, re-signs the request
// with the real SecretAccessKey. Returns an outcome Location constant and an
// audit.Injection slice describing what happened. The returned outcome is
// "" when the request bears no AWS4 Authorization at all (caller should
// continue with other signers / pass-through).
//
// body is the already-buffered request body; the signer does not mutate
// req.Body — the caller remains responsible for that.
func signAWSSigV4(req *http.Request, body []byte, creds map[string]*vault.Credential, host string) ([]audit.Injection, string) {
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return nil, ""
	}

	parsed, err := parseSigV4Authorization(auth)
	if err != nil {
		return []audit.Injection{failInjection(host, req, SignerErrAuthorizationMalformed)}, LocationSignerFailed
	}

	// Credential lookup via the placeholder map: the SDK embedded our
	// AWSAccessKeyIDPlaceholder into the Credential= scope. We require the
	// vault entry to actually carry an AWSAccessKeyID (typed field) so a
	// corrupted Scheme string cannot cause wrong-signer dispatch.
	cred, lookupOK := creds[parsed.AccessKeyID]
	if !lookupOK || cred.AWSAccessKeyID == "" || !placeholder.HostMatches(host, cred.AllowedHosts) {
		// Check whether *any* aws credential covers this host. If so,
		// fail-closed (the agent picked the wrong AKID); otherwise let the
		// request pass through unchanged.
		if veilOwnsAWSHost(creds, host) {
			return []audit.Injection{failInjection(host, req, SignerErrUnknownAccessKeyID)}, LocationSignerFailed
		}
		return nil, LocationSchemeUnmediated
	}

	// Session-token sanity: the proxy refuses to send a token the user
	// didn't store, and refuses to drop a token the request expects.
	reqTok := req.Header.Get("X-Amz-Security-Token")
	switch {
	case cred.AWSSessionToken == "" && reqTok != "":
		return []audit.Injection{failInjection(host, req, SignerErrUnexpectedSessionToken)}, LocationSignerFailed
	case cred.AWSSessionToken != "" && reqTok == "":
		return []audit.Injection{failInjection(host, req, SignerErrMissingSessionToken)}, LocationSignerFailed
	}

	// Replace placeholder AKID with real, swap session token if present.
	beforeLen := len(auth)
	newAuth := strings.Replace(auth,
		"Credential="+parsed.AccessKeyID+"/",
		"Credential="+cred.AWSAccessKeyID+"/",
		1)
	req.Header.Set("Authorization", newAuth)
	if cred.AWSSessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", cred.AWSSessionToken)
	}

	// Recompute canonical request.
	isS3 := strings.HasPrefix(parsed.Service, "s3")
	canonURI := canonicalURI(req.URL.Path, isS3)
	canonQuery := canonicalQueryString(req.URL.RawQuery)

	var payloadHash string
	if req.Header.Get("X-Amz-Content-Sha256") == "UNSIGNED-PAYLOAD" {
		payloadHash = "UNSIGNED-PAYLOAD"
	} else {
		payloadHash = sha256Hex(body)
		if req.Header.Get("X-Amz-Content-Sha256") != "" {
			req.Header.Set("X-Amz-Content-Sha256", payloadHash)
		}
	}

	// canonicalHeaders must be computed AFTER any header mutation above so
	// the hashed string-to-sign matches the wire request the SDK will see.
	canonHeaders := canonicalHeaders(req.Header, parsed.SignedHeaders)
	signed := strings.Join(parsed.SignedHeaders, ";")

	canonReq := req.Method + "\n" +
		canonURI + "\n" +
		canonQuery + "\n" +
		canonHeaders + "\n" +
		signed + "\n" +
		payloadHash

	scope := parsed.Date + "/" + parsed.Region + "/" + parsed.Service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" +
		req.Header.Get("X-Amz-Date") + "\n" +
		scope + "\n" +
		sha256Hex([]byte(canonReq))

	key := deriveSigningKey(cred.Real, parsed.Date, parsed.Region, parsed.Service)
	newSig := fmt.Sprintf("%x", hmacSHA256(key, []byte(stringToSign)))

	finalAuth := strings.Replace(req.Header.Get("Authorization"),
		"Signature="+parsed.Signature, "Signature="+newSig, 1)
	req.Header.Set("Authorization", finalAuth)

	return []audit.Injection{{
		Timestamp:      time.Now(),
		Host:           host,
		CredentialID:   cred.ID,
		CredentialName: cred.Name,
		BytesBefore:    beforeLen,
		BytesAfter:     len(finalAuth),
		Location:       LocationAWSSigV4Resigned,
	}}, LocationAWSSigV4Resigned
}

// veilOwnsAWSHost reports whether any credential in creds (with a non-empty
// typed AWSAccessKeyID) covers host. Used to decide between fail-closed and
// unmediated when an Authorization arrives with an AKID we can't resolve.
func veilOwnsAWSHost(creds map[string]*vault.Credential, host string) bool {
	seen := map[*vault.Credential]bool{}
	for _, c := range creds {
		if c == nil || seen[c] || c.AWSAccessKeyID == "" {
			continue
		}
		seen[c] = true
		if placeholder.HostMatches(host, c.AllowedHosts) {
			return true
		}
	}
	return false
}

// failInjection builds the audit record emitted when the signer cannot
// produce a valid signature. The caller (request injector) fills in
// RequestID / AgentPID / AgentCmd before persisting.
func failInjection(host string, req *http.Request, errClass string) audit.Injection {
	return audit.Injection{
		Timestamp:   time.Now(),
		Host:        host,
		Method:      req.Method,
		URLPath:     req.URL.Path,
		Location:    LocationSignerFailed,
		SignerError: errClass,
	}
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
