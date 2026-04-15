package proxy

import (
	"encoding/base64"
	"strings"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/vault"
)

// basicSchemes lists the header names that carry HTTP Basic credentials.
// Values are canonical header names as produced by http.Header.Set.
var basicSchemes = []string{"Authorization", "Proxy-Authorization"}

// decodeAndSwapBasic looks for "Basic <base64(user:secret)>" in Authorization
// and Proxy-Authorization headers, and if both halves map to the same vault
// credential whose AllowedHosts covers host, rewrites the header with the real
// user:secret pair and returns an audit.Injection record per swap. The header
// values are mutated in place.
//
// On any mismatch, malformed encoding, cross-credential mix, or disallowed
// host, the header is left untouched and no injection is returned — the
// mismatch detector will observe injection==0 and emit a warning.
func decodeAndSwapBasic(hdr map[string][]string, pmap map[string]*vault.Credential, host string) []audit.Injection {
	var out []audit.Injection
	now := time.Now()

	for _, name := range basicSchemes {
		values := hdr[name]
		for i, v := range values {
			cred, newValue, ok := tryRewriteBasic(v, pmap, host)
			if !ok {
				continue
			}
			before := len(v)
			values[i] = newValue
			after := len(newValue)
			out = append(out, audit.Injection{
				Timestamp:      now,
				Host:           host,
				CredentialID:   cred.ID,
				CredentialName: cred.Name,
				BytesBefore:    before,
				BytesAfter:     after,
				Location:       "header",
			})
		}
		if len(values) > 0 {
			hdr[name] = values
		}
	}
	return out
}

// tryRewriteBasic parses one header value. Returns (credential, new-value, true)
// when a swap should be performed; (nil, "", false) otherwise.
func tryRewriteBasic(value string, pmap map[string]*vault.Credential, host string) (*vault.Credential, string, bool) {
	if value == "" {
		return nil, "", false
	}
	const schemeLen = len("Basic ")
	if len(value) <= schemeLen {
		return nil, "", false
	}
	if !strings.EqualFold(value[:schemeLen], "Basic ") {
		return nil, "", false
	}
	encoded := strings.TrimSpace(value[schemeLen:])
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, "", false
		}
	}
	userPart, secretPart, found := strings.Cut(string(raw), ":")
	if !found {
		return nil, "", false
	}

	secretCred, secretOK := pmap[secretPart]
	userCred, userOK := pmap[userPart]
	if !secretOK || !userOK {
		return nil, "", false
	}
	if secretCred != userCred {
		return nil, "", false
	}
	cred := secretCred
	if cred.Username == "" || cred.UsernamePlaceholder == "" {
		return nil, "", false
	}
	if secretPart != cred.Placeholder || userPart != cred.UsernamePlaceholder {
		return nil, "", false
	}
	if !placeholder.HostMatches(host, cred.AllowedHosts) {
		return nil, "", false
	}

	newPayload := cred.Username + ":" + cred.Real
	newEncoded := base64.StdEncoding.EncodeToString([]byte(newPayload))
	return cred, "Basic " + newEncoded, true
}
