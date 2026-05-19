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
	// TrailingComment holds the trailing inline comment exactly as it appeared
	// in the source (leading whitespace + "#" + text), or "" if there was none.
	// Preserved on re-emission so dirty lines keep their inline comments.
	TrailingComment string
	dirty           bool // true if Value has been modified via SetValue
}

// EnvFile represents a parsed .env file with full round-trip fidelity.
type EnvFile struct {
	Path            string
	Lines           []Line
	trailingNewline bool

	// hasBOM is true when the input began with a UTF-8 BOM (U+FEFF). The
	// BOM is stripped before parsing so it does not become part of the
	// first KV's key, and re-emitted by Bytes() so the user's encoding
	// marker round-trips.
	hasBOM bool

	// lineSep is the file's line-ending style ("\n" for LF, "\r\n" for
	// CRLF). Detected at parse time so dirty (re-emitted) KV lines match
	// the surrounding file convention; without this, rewriting one KV in
	// a CRLF file would leave that single line LF-terminated.
	lineSep string
}

// ParseFile reads and parses the .env file at path.
func ParseFile(path string) (*EnvFile, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, err
	}
	f := parseContent(string(data))
	f.Path = path
	return f, nil
}

// ParseBytes parses an .env file from a byte slice. Behaves identically
// to ParseFile modulo the I/O step.
func ParseBytes(data []byte) *EnvFile {
	return parseContent(string(data))
}

func parseContent(content string) *EnvFile {
	f := &EnvFile{lineSep: "\n"}
	// Strip a leading UTF-8 BOM so it doesn't become part of the first KV's
	// key (TrimSpace doesn't treat U+FEFF as whitespace). Re-emitted in Bytes
	// so the file's encoding marker round-trips.
	const bom = "\uFEFF"
	if strings.HasPrefix(content, bom) {
		f.hasBOM = true
		content = content[len(bom):]
	}
	// Detect line-ending style from the first newline encountered. CRLF files
	// (typical of Windows editors) keep \r on every untouched line via Raw;
	// dirty re-emissions need lineSep to match or the file ends up with
	// mixed terminators.
	if i := strings.IndexByte(content, '\n'); i > 0 && content[i-1] == '\r' {
		f.lineSep = "\r\n"
	}
	// Split into lines. We handle the trailing newline carefully:
	// if the file ends with \n, the last split element will be empty
	// and we should NOT include it as a line (it's the terminator, not
	// an extra blank line).
	rawLines := strings.Split(content, "\n")
	if len(rawLines) > 0 && rawLines[len(rawLines)-1] == "" {
		rawLines = rawLines[:len(rawLines)-1]
	}
	f.trailingNewline = len(content) > 0 && content[len(content)-1] == '\n'
	for i := 0; i < len(rawLines); {
		raw := rawLines[i]
		if consumed := tryMultilineQuotedKV(rawLines, i); consumed > 1 {
			joined := strings.Join(rawLines[i:i+consumed], "\n")
			f.Lines = append(f.Lines, parseLine(joined))
			i += consumed
			continue
		}
		f.Lines = append(f.Lines, parseLine(raw))
		i++
	}
	return f
}

// tryMultilineQuotedKV checks whether rawLines[start] opens a KV whose quoted
// value extends across subsequent physical lines, and returns the number of
// lines to consume as one logical Line. Returns 1 (single-line) if the opener
// is closed on the same line, if no closing quote is found before EOF, or if
// an intermediate line looks like an independent KV definition (which would
// suggest a user typo rather than a real multi-line value — we refuse to
// silently swallow it).
//
// Without this accumulation, multi-line PEM/JSON values such as
//
//	RSA_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
//	MIIEvg...
//	-----END RSA PRIVATE KEY-----"
//
// are parsed as a single KV on line 1 (with only "-----BEGIN…" as the value)
// and CommentLines for the rest, leaving the base64 body and END marker in
// plaintext after a vault rewrite.
func tryMultilineQuotedKV(rawLines []string, start int) int {
	if unclosedQuoteChar(rawLines[start]) == 0 {
		return 1
	}
	for j := start + 1; j < len(rawLines); j++ {
		// Safety: don't consume what looks like an independent KV definition.
		// A user who forgot the closing quote on the opener should see only
		// that KV mishandled, not have subsequent valid KVs disappear into it.
		if looksLikeIndependentKV(rawLines[j]) {
			return 1
		}
		accumulated := strings.Join(rawLines[start:j+1], "\n")
		if unclosedQuoteChar(accumulated) == 0 {
			return j - start + 1
		}
	}
	return 1
}

// stripExportPrefix returns s with a leading "export" + whitespace removed,
// or s unchanged if no such prefix is present. The second return value
// reports whether the prefix was found.
func stripExportPrefix(s string) (string, bool) {
	if strings.HasPrefix(s, "export ") || strings.HasPrefix(s, "export\t") {
		return strings.TrimSpace(s[len("export"):]), true
	}
	return s, false
}

// unclosedQuoteChar returns the quote character (' or ") when line parses as
// a KV assignment whose value opens with a quote that does not close. Returns
// 0 if the line isn't a KV opener, the value isn't quoted, or the quote closes.
func unclosedQuoteChar(line string) byte {
	work, _ := stripExportPrefix(strings.TrimSpace(line))
	_, after, ok := strings.Cut(work, "=")
	if !ok {
		return 0
	}
	val := strings.TrimSpace(after)
	if len(val) == 0 {
		return 0
	}
	switch val[0] {
	case '"':
		if _, _, ok := extractDoubleQuoted(val[1:]); !ok {
			return '"'
		}
	case '\'':
		if _, _, ok := extractSingleQuoted(val[1:]); !ok {
			return '\''
		}
	}
	return 0
}

// looksLikeIndependentKV is a conservative heuristic for detecting standalone
// KV assignments. It is used by tryMultilineQuotedKV to refuse swallowing what
// is probably a user's other env var into a multi-line value above. The length
// cap on the identifier rules out base64-encoded PEM body lines, which can
// contain a trailing "=" padding character (e.g.
// "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDb...=").
//
// SHORT-base64 caveat: PEM keys end with a final body line whose length is
// whatever the encoding leaves, often <=32 chars and frequently ending in "="
// or "==" padding (e.g. "abcdefghi=="). Such a line would otherwise pass the
// length cap and ident shape checks. We additionally require the name to
// contain at least one uppercase ASCII letter, which real env vars carry by
// convention (UPPER_CASE / camelCase / PascalCase) and random base64 chunks
// of all-lowercase do not — without this the safety check itself caused
// vault rewrites to silently leave PEM bodies in plaintext on disk.
func looksLikeIndependentKV(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	trimmed, _ = stripExportPrefix(trimmed)
	eqIdx := strings.IndexByte(trimmed, '=')
	// eqIdx > 32 rejects base64 chunks (typical PEM line is ~64 chars before
	// the optional "=" padding); real env var names are far shorter.
	if eqIdx <= 0 || eqIdx > 32 {
		return false
	}
	name := trimmed[:eqIdx]
	if !isShellIdentStart(name[0]) {
		return false
	}
	hasUpper := name[0] >= 'A' && name[0] <= 'Z'
	for i := 1; i < len(name); i++ {
		if !isShellIdentContinue(name[i]) {
			return false
		}
		if name[i] >= 'A' && name[i] <= 'Z' {
			hasUpper = true
		}
	}
	return hasUpper
}

func isShellIdentStart(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '_'
}

func isShellIdentContinue(b byte) bool {
	return isShellIdentStart(b) || (b >= '0' && b <= '9')
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
	kvPart, export := stripExportPrefix(strings.TrimSpace(raw))

	keyPart, valPart, ok := strings.Cut(kvPart, "=")
	if !ok {
		return Line{}, false
	}

	key := strings.TrimSpace(keyPart)
	if key == "" {
		return Line{}, false
	}

	value, quoted, comment, ok := parseValue(valPart)
	if !ok {
		return Line{}, false
	}

	return Line{
		Raw:             raw,
		Kind:            KVLine,
		Key:             key,
		Value:           value,
		Quoted:          quoted,
		Export:          export,
		TrailingComment: comment,
	}, true
}

// parseValue parses the value portion after the = sign.
// Returns the decoded value, quote style, the verbatim trailing comment
// (leading whitespace + "#" + text, or "" if absent), and ok=true on success.
// Returns ("", 0, "", false) when the value has an unclosed quote that cannot
// be recovered (e.g. an unclosed single-quote), signalling parseKV to demote
// the line to a CommentLine.
func parseValue(raw string) (string, QuoteStyle, string, bool) {
	// Check for single-quoted value.
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "'") {
		content, rest, ok := extractSingleQuoted(trimmed[1:])
		if ok {
			return content, SingleQuote, extractTrailingComment(rest), true
		}
		// Unclosed single-quote: signal failure so the caller demotes to CommentLine.
		return "", 0, "", false
	}

	// Check for double-quoted value
	if strings.HasPrefix(trimmed, "\"") {
		// Find the matching closing quote, respecting escapes
		content, rest, ok := extractDoubleQuoted(trimmed[1:])
		if ok {
			return unescapeDoubleQuoted(content), DoubleQuote, extractTrailingComment(rest), true
		}
		// Malformed double-quote — strip the opening quote and fall through
		raw = strings.TrimPrefix(raw, "\"")
	}

	// Unquoted: trim whitespace, strip inline comments
	val := strings.TrimSpace(raw)
	val, comment := splitInlineComment(val)
	return val, Unquoted, comment, true
}

// extractSingleQuoted extracts content from inside single quotes, honouring
// the shell idiom backslash-quote (close quote, literal quote, open quote)
// which lets users embed a literal single quote inside a single-quoted string.
//
// Input starts after the opening quote. Returns the literal content, the
// remainder after the closing quote, and true on success; "", "" and false
// if the quote is unclosed.
func extractSingleQuoted(s string) (string, string, bool) {
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
			return b.String(), s[i+1:], true
		}
		b.WriteByte(s[i])
		i++
	}
	return "", "", false
}

// extractDoubleQuoted extracts content from inside double quotes.
// Input starts after the opening quote. Returns the inner content, the
// remainder after the closing quote, and true on success.
func extractDoubleQuoted(s string) (string, string, bool) {
	var i int
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2 // skip escaped char
			continue
		}
		if s[i] == '"' {
			return s[:i], s[i+1:], true
		}
		i++
	}
	return "", "", false
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

// splitInlineComment splits an unquoted value at its inline comment.
// Returns the value (with trailing whitespace before the # trimmed) and the
// verbatim comment text including its leading whitespace and "#". Returns
// (val, "") when no inline comment is present.
func splitInlineComment(val string) (string, string) {
	// Walk through looking for ' #' or '\t#'
	for i := 1; i < len(val); i++ {
		if val[i] == '#' && (val[i-1] == ' ' || val[i-1] == '\t') {
			// Find the start of the run of whitespace preceding the '#'.
			j := i
			for j > 0 && (val[j-1] == ' ' || val[j-1] == '\t') {
				j--
			}
			return val[:j], val[j:]
		}
	}
	return val, ""
}

// extractTrailingComment returns the verbatim trailing comment from the
// remainder of a line after a closing quote. If the remainder contains only
// whitespace, returns "". If it contains a "#"-prefixed comment (optionally
// with leading whitespace), returns it verbatim.
func extractTrailingComment(rest string) string {
	trimmed := strings.TrimLeft(rest, " \t")
	if trimmed == "" || trimmed[0] != '#' {
		return ""
	}
	return rest
}

// Bytes reconstructs the file content from Lines with round-trip fidelity.
func (f *EnvFile) Bytes() []byte {
	var buf bytes.Buffer
	if f.hasBOM {
		buf.WriteString("\uFEFF")
	}
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
			// Re-attach the trailing inline comment. For unquoted values that
			// gained a "#" pattern (and therefore got promoted to quoted via
			// encodeValue's needsQuoting check), the comment is still safe to
			// append — the value is now wrapped in quotes.
			if l.TrailingComment != "" {
				if !startsWithSpace(l.TrailingComment) {
					buf.WriteByte(' ')
				}
				buf.WriteString(l.TrailingComment)
			}
			// Untouched lines keep the original CR via Raw; the rebuilt
			// line has none, so add one when the file's convention is CRLF
			// to avoid mixed line endings in the rewritten file.
			if f.lineSep == "\r\n" {
				buf.WriteByte('\r')
			}
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

func startsWithSpace(s string) bool {
	return len(s) > 0 && (s[0] == ' ' || s[0] == '\t')
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
