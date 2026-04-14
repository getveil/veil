package scanner

import "errors"

var (
	// ErrEnvParse indicates a malformed .env line (unclosed quote, bad escape, etc.).
	ErrEnvParse = errors.New("scanner: env parse error")
)
