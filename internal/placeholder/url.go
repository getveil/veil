package placeholder

import (
	"net/url"
	"strings"
)

// allowedSchemes lists URL schemes that tryURL will process.
var allowedSchemes = map[string]bool{
	"postgres":    true,
	"postgresql":  true,
	"mysql":       true,
	"mongodb":     true,
	"mongodb+srv": true,
	"redis":       true,
	"rediss":      true,
	"amqp":        true,
	"amqps":       true,
	"http":        true,
	"https":       true,
}

// isURLWithPassword checks if value is a URL with a password in a supported
// scheme, without generating any fake data (no RNG consumption).
func isURLWithPassword(value string) bool {
	u, err := url.Parse(value)
	if err != nil {
		return false
	}
	if !allowedSchemes[u.Scheme] {
		return false
	}
	if u.User == nil {
		return false
	}
	_, has := u.User.Password()
	return has
}

// tryURL checks if value is a URL with a password in a supported scheme.
// If so, it replaces only the password segment with a charclass fake and
// returns the modified URL. It operates on the raw string to avoid
// encoding round-trip issues that could change the URL length.
func tryURL(value string) (string, bool) {
	u, err := url.Parse(value)
	if err != nil {
		return "", false
	}
	if !allowedSchemes[u.Scheme] {
		return "", false
	}
	if u.User == nil {
		return "", false
	}
	_, hasPassword := u.User.Password()
	if !hasPassword {
		return "", false
	}

	// Locate the password in the raw URL by byte offset (not via net/url,
	// which percent-decodes and could change length).
	// Format: scheme://[user[:password]@]host[:port][/path][?query][#fragment]
	schemeEnd := strings.Index(value, "://")
	if schemeEnd < 0 {
		return "", false
	}
	authStart := schemeEnd + 3

	// Bound the search to the authority — path/query/fragment delimiters end
	// it. Without this bound, an '@' in the path (e.g. /x@y) could be picked
	// as the userinfo terminator.
	authEnd := len(value)
	if i := strings.IndexAny(value[authStart:], "/?#"); i >= 0 {
		authEnd = authStart + i
	}
	rest := value[authStart:authEnd]

	// LastIndex of '@' inside the authority matches net/url and keeps
	// unencoded '@' inside a password from prematurely closing userinfo.
	atIdx := strings.LastIndex(rest, "@")
	if atIdx < 0 {
		return "", false
	}
	userinfo := rest[:atIdx]

	// First ':' separates user from password; LastIndex would split a
	// password that contains ':'.
	colonIdx := strings.Index(userinfo, ":")
	if colonIdx < 0 {
		return "", false
	}

	rawPassword := userinfo[colonIdx+1:]
	if rawPassword == "" {
		return "", false
	}

	fake := sentinelize(charClassFake(rawPassword), 0)

	passwordStart := authStart + colonIdx + 1
	passwordEnd := authStart + atIdx
	return value[:passwordStart] + fake + value[passwordEnd:], true
}
