package proxy

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/vault"
)

// Auth-signal identifiers persisted in audit rows and log fields.
const (
	authSignalAuthorizationHeader      = "authorization_header"
	authSignalProxyAuthorizationHeader = "proxy_authorization_header"
	authSignalCookie                   = "cookie"
	authSignalXCustomHeader            = "x_custom_header"
	authSignalQueryParam               = "query_param"
)

// xTokenHeaderRE matches header names of the form X-*-{token,auth,key,sig,signature}.
var xTokenHeaderRE = regexp.MustCompile(`(?i)^x-.*-(token|auth|key|sig|signature)$|^x-(auth|token|apikey|api-key)$`)

// authQueryParams lists query parameter names that signal request-carried auth.
var authQueryParams = map[string]struct{}{
	"auth":         {},
	"signature":    {},
	"sig":          {},
	"token":        {},
	"api_key":      {},
	"apikey":       {},
	"access_token": {},
}

// detectMismatch returns (authSignal, candidateCredentialNames, fired).
func detectMismatch(host string, u *url.URL, hdr http.Header, injectionCount int, creds []*vault.Credential) (string, []string, bool) {
	if injectionCount > 0 {
		return "", nil, false
	}

	var candidates []string
	for _, c := range creds {
		if placeholder.HostMatches(host, c.AllowedHosts) {
			candidates = append(candidates, c.Name)
		}
	}
	if len(candidates) == 0 {
		return "", nil, false
	}

	if v := hdr.Get("Authorization"); v != "" {
		return authSignalAuthorizationHeader, candidates, true
	}
	if v := hdr.Get("Proxy-Authorization"); v != "" {
		return authSignalProxyAuthorizationHeader, candidates, true
	}
	if v := hdr.Get("Cookie"); v != "" {
		return authSignalCookie, candidates, true
	}
	for name := range hdr {
		if xTokenHeaderRE.MatchString(strings.ToLower(name)) {
			return authSignalXCustomHeader, candidates, true
		}
	}
	if u != nil {
		q := u.Query()
		for k := range q {
			if _, ok := authQueryParams[strings.ToLower(k)]; ok {
				return authSignalQueryParam, candidates, true
			}
		}
	}
	return "", nil, false
}
