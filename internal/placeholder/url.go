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
	// URL format: scheme://[user[:password]@]host/path
	schemeEnd := strings.Index(value, "://")
	if schemeEnd < 0 {
		return "", false
	}
	authStart := schemeEnd + 3

	// Find @ that ends the userinfo.
	rest := value[authStart:]
	atIdx := strings.Index(rest, "@")
	if atIdx < 0 {
		return "", false
	}
	userinfo := rest[:atIdx]

	// Find : that separates user from password.
	colonIdx := strings.Index(userinfo, ":")
	if colonIdx < 0 {
		return "", false
	}

	rawPassword := userinfo[colonIdx+1:]
	if rawPassword == "" {
		return "", false
	}

	fake := charClassFake(rawPassword)

	// Replace the password in the original string.
	passwordStart := authStart + colonIdx + 1
	passwordEnd := authStart + atIdx
	result := value[:passwordStart] + fake + value[passwordEnd:]
	return result, true
}
