package scanner

import (
	"bytes"
	"os"
	"strings"
)

// LineKind categorises a parsed line.
type LineKind int

const (
	// BlankLine is an empty or whitespace-only line.
	BlankLine LineKind = iota
	// CommentLine is a comment (starts with #) or unparseable line.
	CommentLine
	// KVLine is a key=value assignment.
	KVLine
)

// QuoteStyle records how the value was quoted in the source file.
type QuoteStyle int

const (
	// Unquoted means no quotes around the value.
	Unquoted QuoteStyle = iota
	// SingleQuote means the value was wrapped in single quotes.
	SingleQuote
	// DoubleQuote means the value was wrapped in double quotes.
	DoubleQuote
)

// Line represents a single line from an .env file.
type Line struct {
	Raw    string     // the complete original line text (without trailing newline)
	Kind   LineKind   // Blank, Comment, KV
	Key    string     // only for KV
	Value  string     // only for KV — the decoded value (unquoted, unescaped)
	Quoted QuoteStyle // only for KV
	Export bool       // only for KV — true if the line started with "export "
	dirty  bool       // true if Value has been modified via SetValue
}

// EnvFile represents a parsed .env file with full round-trip fidelity.
type EnvFile struct {
	Path            string
	Lines           []Line
	trailingNewline bool
}

// ParseFile reads and parses the .env file at path.
func ParseFile(path string) (*EnvFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)

	// Split into lines. We handle the trailing newline carefully:
	// if the file ends with \n, the last split element will be empty
	// and we should NOT include it as a line (it's the terminator, not
	// an extra blank line).
	rawLines := strings.Split(content, "\n")
	if len(rawLines) > 0 && rawLines[len(rawLines)-1] == "" {
		rawLines = rawLines[:len(rawLines)-1]
	}

	f := &EnvFile{Path: path}
	f.trailingNewline = len(content) > 0 && content[len(content)-1] == '\n'
	for _, raw := range rawLines {
		f.Lines = append(f.Lines, parseLine(raw))
	}
	return f, nil
}

// parseLine parses a single line of .env content.
func parseLine(raw string) Line {
	trimmed := strings.TrimSpace(raw)

	// Blank line
	if trimmed == "" {
		return Line{Raw: raw, Kind: BlankLine}
	}

	// Comment line
	if strings.HasPrefix(trimmed, "#") {
		return Line{Raw: raw, Kind: CommentLine}
	}

	// Try to parse as KV
	line, ok := parseKV(raw)
	if !ok {
		// Unparseable — treat as comment
		return Line{Raw: raw, Kind: CommentLine}
	}
	return line
}

// parseKV attempts to parse raw as a KEY=VALUE line.
func parseKV(raw string) (Line, bool) {
	work := raw
	trimmed := strings.TrimSpace(work)

	// Detect export prefix
	export := false
	kvPart := trimmed
	if strings.HasPrefix(trimmed, "export ") || strings.HasPrefix(trimmed, "export\t") {
		export = true
		kvPart = strings.TrimSpace(trimmed[len("export"):])
	}

	// Find the = separator
	eqIdx := strings.IndexByte(kvPart, '=')
	if eqIdx < 0 {
		return Line{}, false
	}

	key := strings.TrimSpace(kvPart[:eqIdx])
	if key == "" {
		return Line{}, false
	}

	valRaw := kvPart[eqIdx+1:]

	value, quoted, ok := parseValue(valRaw)
	if !ok {
		return Line{}, false
	}

	return Line{
		Raw:    raw,
		Kind:   KVLine,
		Key:    key,
		Value:  value,
		Quoted: quoted,
		Export: export,
	}, true
}

// parseValue parses the value portion after the = sign.
// Returns the decoded value, quote style, and ok=true on success.
// Returns ("", 0, false) when the value has an unclosed quote that cannot be
// recovered (e.g. an unclosed single-quote), signalling parseKV to demote the
// line to a CommentLine.
func parseValue(raw string) (string, QuoteStyle, bool) {
	// Check for single-quoted value.
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "'") {
		content, ok := extractSingleQuoted(trimmed[1:])
		if ok {
			return content, SingleQuote, true
		}
		// Unclosed single-quote: signal failure so the caller demotes to CommentLine.
		return "", 0, false
	}

	// Check for double-quoted value
	if strings.HasPrefix(trimmed, "\"") {
		// Find the matching closing quote, respecting escapes
		content, ok := extractDoubleQuoted(trimmed[1:])
		if ok {
			return unescapeDoubleQuoted(content), DoubleQuote, true
		}
		// Malformed double-quote — strip the opening quote and fall through
		raw = strings.TrimPrefix(raw, "\"")
	}

	// Unquoted: trim whitespace, strip inline comments
	val := strings.TrimSpace(raw)
	val = stripInlineComment(val)
	return val, Unquoted, true
}

// extractSingleQuoted extracts content from inside single quotes, honouring
// the shell idiom '\'' (close quote, literal quote, open quote) which lets
// users embed a literal single quote inside a single-quoted string.
//
// Input starts after the opening quote. Returns the literal content and
// true on success; "" and false if the quote is unclosed.
func extractSingleQuoted(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\'' {
			// Check for the '\'' idiom: we're at a closing quote, next is
			// backslash+quote+quote meaning "literal quote, reopen".
			if i+3 < len(s) && s[i+1] == '\\' && s[i+2] == '\'' && s[i+3] == '\'' {
				b.WriteByte('\'')
				i += 4 // advance past: ' \ ' '
				continue
			}
			// Plain closing quote.
			return b.String(), true
		}
		b.WriteByte(s[i])
		i++
	}
	return "", false
}

// extractDoubleQuoted extracts content from inside double quotes.
// Input starts after the opening quote.
func extractDoubleQuoted(s string) (string, bool) {
	var i int
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2 // skip escaped char
			continue
		}
		if s[i] == '"' {
			return s[:i], true
		}
		i++
	}
	return "", false
}

// unescapeDoubleQuoted processes escape sequences in double-quoted values.
func unescapeDoubleQuoted(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			switch next {
			case 'n':
				b.WriteByte('\n')
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			default:
				b.WriteByte('\\')
				b.WriteByte(next)
			}
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// stripInlineComment removes an inline # comment from an unquoted value.
// A comment starts with # preceded by whitespace.
func stripInlineComment(val string) string {
	// Walk through looking for ' #' or '\t#'
	for i := 1; i < len(val); i++ {
		if val[i] == '#' && (val[i-1] == ' ' || val[i-1] == '\t') {
			return strings.TrimRight(val[:i], " \t")
		}
	}
	return val
}

// Bytes reconstructs the file content from Lines with round-trip fidelity.
func (f *EnvFile) Bytes() []byte {
	var buf bytes.Buffer
	for i, l := range f.Lines {
		switch {
		case l.Kind == KVLine && l.dirty:
			// Reconstruct from structured fields with updated value.
			if l.Export {
				buf.WriteString("export ")
			}
			buf.WriteString(l.Key)
			buf.WriteByte('=')
			buf.WriteString(encodeValue(l.Value, l.Quoted))
		default:
			// Emit the original line verbatim for round-trip fidelity.
			buf.WriteString(l.Raw)
		}
		if i < len(f.Lines)-1 || f.trailingNewline {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

// encodeValue re-encodes a value with the given quote style.
func encodeValue(value string, q QuoteStyle) string {
	switch q {
	case SingleQuote:
		return "'" + value + "'"
	case DoubleQuote:
		return "\"" + escapeDoubleQuoted(value) + "\""
	default:
		if needsQuoting(value) {
			return "\"" + escapeDoubleQuoted(value) + "\""
		}
		return value
	}
}

// needsQuoting reports whether an unquoted value needs to be wrapped in
// double quotes to survive a round-trip parse (e.g. it contains leading/
// trailing whitespace or an inline-comment pattern).
func needsQuoting(s string) bool {
	if strings.TrimSpace(s) != s {
		return true
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return true
		}
	}
	return false
}

// escapeDoubleQuoted applies escape sequences for double-quoted output.
func escapeDoubleQuoted(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			b.WriteString("\\\\")
		case '"':
			b.WriteString("\\\"")
		case '\n':
			b.WriteString("\\n")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// SetValue updates the decoded value for the given key.
// Returns true if the key was found, false otherwise.
func (f *EnvFile) SetValue(key, newValue string) bool {
	for i := range f.Lines {
		if f.Lines[i].Kind == KVLine && f.Lines[i].Key == key {
			f.Lines[i].Value = newValue
			f.Lines[i].dirty = true
			return true
		}
	}
	return false
}

// Lookup returns the decoded value for the given key.
// Returns ("", false) if the key is not found.
func (f *EnvFile) Lookup(key string) (string, bool) {
	for i := range f.Lines {
		if f.Lines[i].Kind == KVLine && f.Lines[i].Key == key {
			return f.Lines[i].Value, true
		}
	}
	return "", false
}
