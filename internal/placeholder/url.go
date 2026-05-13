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

	// Find the password in the raw URL string.
	// URL format: scheme://[user[:password]@]host[:port][/path][?query][#fragment]
	schemeEnd := strings.Index(value, "://")
	if schemeEnd < 0 {
		return "", false
	}
	authStart := schemeEnd + 3

	// Bound the search to the authority. The authority terminates at the
	// first '/', '?', or '#' after authStart, or at the end of the string.
	// This matters when the password contains an unencoded '@' (security
	// issue H1): without this bound, the userinfo/host boundary lookup
	// could see an '@' from the path and mis-locate the split.
	authEnd := len(value)
	for i := authStart; i < len(value); i++ {
		c := value[i]
		if c == '/' || c == '?' || c == '#' {
			authEnd = i
			break
		}
	}
	rest := value[authStart:authEnd]

	// Find the LAST '@' inside the authority. This matches Go's net/url
	// parser, which uses LastIndex so that unencoded '@' inside the
	// password does not prematurely terminate the userinfo.
	atIdx := strings.LastIndex(rest, "@")
	if atIdx < 0 {
		return "", false
	}
	userinfo := rest[:atIdx]

	// Find the FIRST ':' inside the userinfo: it separates the username
	// from the password. Use Index (not LastIndex) so passwords containing
	// ':' are kept intact in rawPassword.
	colonIdx := strings.Index(userinfo, ":")
	if colonIdx < 0 {
		return "", false
	}

	rawPassword := userinfo[colonIdx+1:]
	if rawPassword == "" {
		return "", false
	}

	// Sentinel is embedded into the fake password body so the proxy can
	// detect a leaked URL placeholder with a single substring scan. The
	// password portion is entirely randomized, so overwriting the first
	// 4 bytes is safe.
	fake := sentinelize(charClassFake(rawPassword), 0)

	// Replace the password in the original string.
	passwordStart := authStart + colonIdx + 1
	passwordEnd := authStart + atIdx
	result := value[:passwordStart] + fake + value[passwordEnd:]
	return result, true
}
