package placeholder

import (
	"net/url"
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

// tryURL checks if value is a URL with a password in a supported scheme.
// If so, it replaces only the password segment with a charclass fake and
// returns the modified URL. Otherwise it returns ("", false).
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
	password, hasPassword := u.User.Password()
	if !hasPassword {
		return "", false
	}
	fakePassword := charClassFake(password)
	u.User = url.UserPassword(u.User.Username(), fakePassword)
	return u.String(), true
}
