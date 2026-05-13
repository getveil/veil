package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureRelPath = "../../test/fixtures/envs/comprehensive.env"

func fixturePath(t *testing.T) string {
	t.Helper()
	// Resolve relative to this test file's package directory.
	abs, err := filepath.Abs(fixtureRelPath)
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}
	return abs
}

func TestRoundTrip(t *testing.T) {
	path := fixturePath(t)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	got := f.Bytes()
	if !bytes.Equal(got, original) {
		t.Errorf("round-trip mismatch:\n--- original (%d bytes) ---\n%s\n--- got (%d bytes) ---\n%s",
			len(original), original, len(got), got)
	}
}

func TestParseValues(t *testing.T) {
	path := fixturePath(t)
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	tests := []struct {
		key  string
		want string
	}{
		{"SIMPLE", "hello"},
		{"SPACES", "world"},
		{"EXPORTED", "yes"},
		{"SINGLE", `no escape \n here`}, // literal backslash-n, NOT a newline
		{"DOUBLE", "escape \n here"},    // real newline
		{"DOUBLE_BS", "back\\slash"},    // one backslash
		{"DOUBLE_DQ", `has "quote"`},    // literal double quote
		{"EMPTY", ""},
		{"NO_TRAILING_SPACE", "value"},
		{"WITH_INLINE_COMMENT", "realvalue"},
		{"URL", "https://example.com/path?query=1"},
	}

	for _, tt := range tests {
		val, ok := f.Lookup(tt.key)
		if !ok {
			t.Errorf("Lookup(%q): not found", tt.key)
			continue
		}
		if val != tt.want {
			t.Errorf("Lookup(%q) = %q, want %q", tt.key, val, tt.want)
		}
	}
}

func TestUnquotedInlineCommentStripping(t *testing.T) {
	path := fixturePath(t)
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	val, ok := f.Lookup("WITH_INLINE_COMMENT")
	if !ok {
		t.Fatal("WITH_INLINE_COMMENT not found")
	}
	if val != "realvalue" {
		t.Errorf("WITH_INLINE_COMMENT = %q, want %q", val, "realvalue")
	}
}

func TestSingleQuotedNoEscape(t *testing.T) {
	path := fixturePath(t)
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	val, ok := f.Lookup("SINGLE")
	if !ok {
		t.Fatal("SINGLE not found")
	}
	// Should contain literal backslash + n, not a newline character
	if val != `no escape \n here` {
		t.Errorf("SINGLE = %q, want %q", val, `no escape \n here`)
	}
}

func TestDoubleQuotedEscapes(t *testing.T) {
	path := fixturePath(t)
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	// \n -> real newline
	val, ok := f.Lookup("DOUBLE")
	if !ok {
		t.Fatal("DOUBLE not found")
	}
	if val != "escape \n here" {
		t.Errorf("DOUBLE = %q, want %q", val, "escape \n here")
	}

	// \\ -> single backslash
	val, ok = f.Lookup("DOUBLE_BS")
	if !ok {
		t.Fatal("DOUBLE_BS not found")
	}
	if val != "back\\slash" {
		t.Errorf("DOUBLE_BS = %q, want %q", val, "back\\slash")
	}

	// \" -> literal quote
	val, ok = f.Lookup("DOUBLE_DQ")
	if !ok {
		t.Fatal("DOUBLE_DQ not found")
	}
	if val != `has "quote"` {
		t.Errorf("DOUBLE_DQ = %q, want %q", val, `has "quote"`)
	}
}

func TestExportDetection(t *testing.T) {
	path := fixturePath(t)
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	for _, l := range f.Lines {
		if l.Kind == KVLine && l.Key == "EXPORTED" {
			if !l.Export {
				t.Error("EXPORTED should have Export=true")
			}
			return
		}
	}
	t.Error("EXPORTED line not found")
}

func TestQuoteStyleTracking(t *testing.T) {
	path := fixturePath(t)
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	tests := []struct {
		key  string
		want QuoteStyle
	}{
		{"SIMPLE", Unquoted},
		{"SINGLE", SingleQuote},
		{"DOUBLE", DoubleQuote},
		{"DOUBLE_BS", DoubleQuote},
		{"DOUBLE_DQ", DoubleQuote},
	}

	linesByKey := make(map[string]*Line)
	for i := range f.Lines {
		if f.Lines[i].Kind == KVLine {
			linesByKey[f.Lines[i].Key] = &f.Lines[i]
		}
	}

	for _, tt := range tests {
		l, ok := linesByKey[tt.key]
		if !ok {
			t.Errorf("key %q not found", tt.key)
			continue
		}
		if l.Quoted != tt.want {
			t.Errorf("key %q: Quoted = %d, want %d", tt.key, l.Quoted, tt.want)
		}
	}
}

func TestBlankLineCount(t *testing.T) {
	path := fixturePath(t)
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	count := 0
	for _, l := range f.Lines {
		if l.Kind == BlankLine {
			count++
		}
	}
	if count != 1 {
		t.Errorf("blank line count = %d, want 1", count)
	}
}

func TestCommentLineCount(t *testing.T) {
	path := fixturePath(t)
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	count := 0
	for _, l := range f.Lines {
		if l.Kind == CommentLine {
			count++
		}
	}
	if count != 1 {
		t.Errorf("comment line count = %d, want 1", count)
	}
}

func TestLookupMiss(t *testing.T) {
	path := fixturePath(t)
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	val, ok := f.Lookup("NONEXISTENT")
	if ok {
		t.Errorf("Lookup(NONEXISTENT) returned ok=true, val=%q", val)
	}
	if val != "" {
		t.Errorf("Lookup(NONEXISTENT) returned val=%q, want empty", val)
	}
}

func TestSetValueMiss(t *testing.T) {
	path := fixturePath(t)
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	if f.SetValue("NONEXISTENT", "x") {
		t.Error("SetValue(NONEXISTENT) returned true, want false")
	}
}

func TestRoundTripNoTrailingNewline(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "no-trailing-nl.env")
	content := []byte("KEY=value")
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	f, err := ParseFile(tmp)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	got := f.Bytes()
	if !bytes.Equal(got, content) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, content)
	}
}

func TestSetValueWithHashInValue(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "hash.env")
	if err := os.WriteFile(tmp, []byte("KEY=original\n"), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	f, err := ParseFile(tmp)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	// Set a value containing an inline-comment pattern
	if !f.SetValue("KEY", "foo # bar") {
		t.Fatal("SetValue returned false")
	}

	// Write and re-parse
	tmp2 := filepath.Join(t.TempDir(), "hash2.env")
	if err := os.WriteFile(tmp2, f.Bytes(), 0o644); err != nil {
		t.Fatalf("writing modified file: %v", err)
	}

	f2, err := ParseFile(tmp2)
	if err != nil {
		t.Fatalf("re-parsing: %v", err)
	}

	val, ok := f2.Lookup("KEY")
	if !ok {
		t.Fatal("KEY not found after re-parse")
	}
	if val != "foo # bar" {
		t.Errorf("Lookup(KEY) = %q, want %q", val, "foo # bar")
	}

	// Also test leading-space value
	f3, _ := ParseFile(tmp)
	if !f3.SetValue("KEY", " leading space") {
		t.Fatal("SetValue returned false")
	}

	tmp3 := filepath.Join(t.TempDir(), "space.env")
	if err := os.WriteFile(tmp3, f3.Bytes(), 0o644); err != nil {
		t.Fatalf("writing modified file: %v", err)
	}

	f4, err := ParseFile(tmp3)
	if err != nil {
		t.Fatalf("re-parsing: %v", err)
	}

	val, ok = f4.Lookup("KEY")
	if !ok {
		t.Fatal("KEY not found after re-parse (leading space)")
	}
	if val != " leading space" {
		t.Errorf("Lookup(KEY) = %q, want %q", val, " leading space")
	}
}

func TestSingleQuoteWithTrailingContent(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "single-quote.env")
	if err := os.WriteFile(tmp, []byte("KEY='hello' # comment\n"), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	f, err := ParseFile(tmp)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	val, ok := f.Lookup("KEY")
	if !ok {
		t.Fatal("KEY not found")
	}
	if val != "hello" {
		t.Errorf("Lookup(KEY) = %q, want %q", val, "hello")
	}
}

func TestMalformedDoubleQuote(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "malformed-dq.env")
	if err := os.WriteFile(tmp, []byte("KEY=\"unclosed value\n"), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	f, err := ParseFile(tmp)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	val, ok := f.Lookup("KEY")
	if !ok {
		t.Fatal("KEY not found")
	}
	if strings.HasPrefix(val, "\"") {
		t.Errorf("Lookup(KEY) = %q, should not start with double quote", val)
	}
}

func TestParseFileSingleQuote(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		key     string
		value   string
		wantErr bool // true if parser should flag this line (demote to comment)
	}{
		{"simple", `KEY='simple'`, "KEY", "simple", false},
		{"shell escaped quote", `KEY='it'\''s'`, "KEY", "it's", false},
		{"has equals", `KEY='has=equals'`, "KEY", "has=equals", false},
		{"literal backslash", `KEY='has\nliteral'`, "KEY", `has\nliteral`, false},
		{"empty", `KEY=''`, "KEY", "", false},
		{"unclosed", `KEY='unclosed`, "KEY", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, ".env")
			if err := os.WriteFile(p, []byte(tc.input+"\n"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			f, err := ParseFile(p)
			if err != nil {
				t.Fatalf("parse file: %v", err)
			}
			var got string
			var foundKV bool
			for _, l := range f.Lines {
				if l.Kind == KVLine && l.Key == tc.key {
					got = l.Value
					foundKV = true
					break
				}
			}
			if tc.wantErr {
				if foundKV {
					t.Fatalf("expected line demoted to comment, but got KV with value=%q", got)
				}
				return
			}
			if !foundKV {
				t.Fatalf("expected KV line for key=%q; lines were: %+v", tc.key, f.Lines)
			}
			if got != tc.value {
				t.Fatalf("value: got %q, want %q", got, tc.value)
			}
		})
	}
}

func TestSetValue(t *testing.T) {
	path := fixturePath(t)
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	// Change SIMPLE's value
	if !f.SetValue("SIMPLE", "changed") {
		t.Fatal("SetValue(SIMPLE) returned false")
	}

	// Write to a temp file and re-parse
	tmp := filepath.Join(t.TempDir(), "modified.env")
	if err := os.WriteFile(tmp, f.Bytes(), 0o644); err != nil {
		t.Fatalf("writing modified file: %v", err)
	}

	f2, err := ParseFile(tmp)
	if err != nil {
		t.Fatalf("re-parsing modified file: %v", err)
	}

	// Verify SIMPLE changed
	val, ok := f2.Lookup("SIMPLE")
	if !ok {
		t.Fatal("SIMPLE not found after SetValue")
	}
	if val != "changed" {
		t.Errorf("SIMPLE = %q after SetValue, want %q", val, "changed")
	}

	// Verify other values unchanged
	unchanged := []struct {
		key  string
		want string
	}{
		{"SPACES", "world"},
		{"EXPORTED", "yes"},
		{"SINGLE", `no escape \n here`},
		{"DOUBLE", "escape \n here"},
		{"DOUBLE_BS", "back\\slash"},
		{"DOUBLE_DQ", `has "quote"`},
		{"EMPTY", ""},
		{"NO_TRAILING_SPACE", "value"},
		{"WITH_INLINE_COMMENT", "realvalue"},
		{"URL", "https://example.com/path?query=1"},
	}
	for _, tt := range unchanged {
		val, ok := f2.Lookup(tt.key)
		if !ok {
			t.Errorf("Lookup(%q) after SetValue: not found", tt.key)
			continue
		}
		if val != tt.want {
			t.Errorf("Lookup(%q) after SetValue = %q, want %q", tt.key, val, tt.want)
		}
	}
}

// TestMultilineQuotedValue exercises the parser's ability to accumulate lines
// across newlines when a KV value opens with a quote that doesn't close on the
// same line. Without this, multi-line PEM/JSON secrets get silently fragmented:
// only the first physical line is treated as the KV value (with the leading
// quote stripped) and the remaining body + closing marker stay in plaintext
// after a vault rewrite.
func TestMultilineQuotedValue(t *testing.T) {
	const pemBody = "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDbxxxxxxxxxxxxxxxx\n" +
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/0000\n" +
		"-----END RSA PRIVATE KEY-----"

	cases := []struct {
		name      string
		input     string
		key       string
		wantValue string
		wantStyle QuoteStyle
	}{
		{
			name:      "double-quoted PEM",
			input:     "RSA_PRIVATE_KEY=\"" + pemBody + "\"\n",
			key:       "RSA_PRIVATE_KEY",
			wantValue: pemBody,
			wantStyle: DoubleQuote,
		},
		{
			name:      "single-quoted multi-line",
			input:     "JSON_BLOB='{\n  \"a\": 1,\n  \"b\": 2\n}'\n",
			key:       "JSON_BLOB",
			wantValue: "{\n  \"a\": 1,\n  \"b\": 2\n}",
			wantStyle: SingleQuote,
		},
		{
			name:      "exported multi-line",
			input:     "export KEY=\"line1\nline2\"\n",
			key:       "KEY",
			wantValue: "line1\nline2",
			wantStyle: DoubleQuote,
		},
		{
			name:      "trailing content after closing quote",
			input:     "KEY=\"line1\nline2\" # trailing\n",
			key:       "KEY",
			wantValue: "line1\nline2",
			wantStyle: DoubleQuote,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := filepath.Join(t.TempDir(), "multi.env")
			if err := os.WriteFile(tmp, []byte(tc.input), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			f, err := ParseFile(tmp)
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			val, ok := f.Lookup(tc.key)
			if !ok {
				t.Fatalf("Lookup(%q): not found; lines were: %+v", tc.key, f.Lines)
			}
			if val != tc.wantValue {
				t.Errorf("Lookup(%q) = %q, want %q", tc.key, val, tc.wantValue)
			}
			var foundStyle QuoteStyle
			for _, l := range f.Lines {
				if l.Kind == KVLine && l.Key == tc.key {
					foundStyle = l.Quoted
					break
				}
			}
			if foundStyle != tc.wantStyle {
				t.Errorf("Quote style = %d, want %d", foundStyle, tc.wantStyle)
			}

			// Round-trip: untouched multi-line should re-emit byte-for-byte.
			if got := f.Bytes(); !bytes.Equal(got, []byte(tc.input)) {
				t.Errorf("round-trip mismatch:\ngot:\n%s\nwant:\n%s", got, tc.input)
			}
		})
	}
}

// TestMultilineQuotedValueVaulting verifies the security fix end-to-end: a
// SetValue on a multi-line PEM key produces a single rewritten line and leaves
// NO traces of the original base64 body in the emitted bytes. This is the
// exact failure mode the fix targets: previously, only the first physical
// line's value was vaulted while the PEM body remained on disk in plaintext.
func TestMultilineQuotedValueVaulting(t *testing.T) {
	const pemBody = "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDbsensitivebody\n" +
		"abcdefghijklmnopqrstuvwxyz1234567890+/abcdefghijklmnopqrstuvwxyz==\n" +
		"-----END RSA PRIVATE KEY-----"
	input := "OTHER=before\nRSA_PRIVATE_KEY=\"" + pemBody + "\"\nOTHER2=after\n"

	tmp := filepath.Join(t.TempDir(), "vault.env")
	if err := os.WriteFile(tmp, []byte(input), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := ParseFile(tmp)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if !f.SetValue("RSA_PRIVATE_KEY", "{{veil:placeholder}}") {
		t.Fatal("SetValue: RSA_PRIVATE_KEY not found")
	}

	got := string(f.Bytes())
	// The placeholder must be present and the PEM body must NOT remain in
	// plaintext anywhere in the emitted bytes.
	if !strings.Contains(got, `RSA_PRIVATE_KEY="{{veil:placeholder}}"`) {
		t.Errorf("expected vaulted line in output; got:\n%s", got)
	}
	for _, leak := range []string{"MIIEvgIBADAN", "sensitivebody", "abcdefghijklmnop", "-----END RSA"} {
		if strings.Contains(got, leak) {
			t.Errorf("PEM body fragment %q leaked into output:\n%s", leak, got)
		}
	}
	// The unrelated KVs above and below must still be present.
	if !strings.Contains(got, "OTHER=before") || !strings.Contains(got, "OTHER2=after") {
		t.Errorf("surrounding KVs lost in output:\n%s", got)
	}
}

// TestUnclosedQuoteDoesNotSwallowKVs verifies the safety check: when a user
// forgets the closing quote on one KV, the accumulator must not silently
// consume their other env vars into the broken value. The opener falls back
// to single-line handling and subsequent KVs parse independently.
func TestUnclosedQuoteDoesNotSwallowKVs(t *testing.T) {
	// KEY1 has an unclosed quote and no closing quote anywhere in the file.
	// KEY2 and KEY3 must still be parseable as their own KVs.
	input := "KEY1=\"oops typo\nKEY2=value2\nKEY3=value3\n"
	tmp := filepath.Join(t.TempDir(), "unclosed.env")
	if err := os.WriteFile(tmp, []byte(input), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := ParseFile(tmp)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	v2, ok := f.Lookup("KEY2")
	if !ok || v2 != "value2" {
		t.Errorf("KEY2: got (%q, %v), want (\"value2\", true)", v2, ok)
	}
	v3, ok := f.Lookup("KEY3")
	if !ok || v3 != "value3" {
		t.Errorf("KEY3: got (%q, %v), want (\"value3\", true)", v3, ok)
	}
}

// TestUnclosedQuoteAcrossLinesNoCloser verifies that when a quote opens but no
// closing quote exists anywhere in the file (and there's no later KV that
// would terminate accumulation either), the parser falls back to single-line
// handling instead of swallowing the entire rest of the file.
func TestUnclosedQuoteAcrossLinesNoCloser(t *testing.T) {
	// Body lines are PEM-like (no "=" delimiters) but the closing quote is
	// missing. Accumulation should reach EOF without finding a close and the
	// opener should fall back to its prior single-line behavior.
	input := "KEY=\"-----BEGIN\nbodyline1\nbodyline2\n"
	tmp := filepath.Join(t.TempDir(), "no-close.env")
	if err := os.WriteFile(tmp, []byte(input), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := ParseFile(tmp)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	// The opener should still produce a KVLine via single-line fallback.
	val, ok := f.Lookup("KEY")
	if !ok {
		t.Fatalf("KEY not found; lines were: %+v", f.Lines)
	}
	if strings.HasPrefix(val, "\"") {
		t.Errorf("opener fell back but kept the opening quote: %q", val)
	}
	// And the body lines must NOT have been concatenated into KEY's value.
	if strings.Contains(val, "bodyline1") || strings.Contains(val, "bodyline2") {
		t.Errorf("accumulation should have failed without a closer, but KEY = %q", val)
	}
}

// TestTrailingCommentRoundTrip exercises F-4: inline trailing comments must
// survive a SetValue/Bytes/re-parse cycle for unquoted, double-quoted, and
// single-quoted values, and a "#" inside a quoted value must NOT be treated
// as the start of a comment.
func TestTrailingCommentRoundTrip(t *testing.T) {
	src := "K1=val # comment\n" +
		"K2=\"val\" # comment2\n" +
		"K3='val' # comment3\n" +
		"K4=\"val # not-comment\"\n"

	tmp := filepath.Join(t.TempDir(), "trailing.env")
	if err := os.WriteFile(tmp, []byte(src), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	f, err := ParseFile(tmp)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	wantInitial := []struct {
		key, value, comment string
	}{
		{"K1", "val", " # comment"},
		{"K2", "val", " # comment2"},
		{"K3", "val", " # comment3"},
		{"K4", "val # not-comment", ""},
	}
	linesByKey := map[string]*Line{}
	for i := range f.Lines {
		if f.Lines[i].Kind == KVLine {
			linesByKey[f.Lines[i].Key] = &f.Lines[i]
		}
	}
	for _, w := range wantInitial {
		l, ok := linesByKey[w.key]
		if !ok {
			t.Fatalf("key %q not parsed", w.key)
		}
		if l.Value != w.value {
			t.Errorf("%s initial value = %q, want %q", w.key, l.Value, w.value)
		}
		if l.TrailingComment != w.comment {
			t.Errorf("%s initial TrailingComment = %q, want %q", w.key, l.TrailingComment, w.comment)
		}
	}

	// Mark every KV line dirty by setting a new value.
	newValues := map[string]string{
		"K1": "newval1",
		"K2": "newval2",
		"K3": "newval3",
		"K4": "newval4 # still-not-comment",
	}
	for k, v := range newValues {
		if !f.SetValue(k, v) {
			t.Fatalf("SetValue(%q): not found", k)
		}
	}

	// Write the re-emitted bytes and re-parse.
	tmp2 := filepath.Join(t.TempDir(), "trailing2.env")
	if err := os.WriteFile(tmp2, f.Bytes(), 0o644); err != nil {
		t.Fatalf("write modified: %v", err)
	}
	f2, err := ParseFile(tmp2)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	wantFinal := []struct {
		key, value, comment string
	}{
		{"K1", "newval1", " # comment"},
		{"K2", "newval2", " # comment2"},
		{"K3", "newval3", " # comment3"},
		{"K4", "newval4 # still-not-comment", ""},
	}
	linesByKey2 := map[string]*Line{}
	for i := range f2.Lines {
		if f2.Lines[i].Kind == KVLine {
			linesByKey2[f2.Lines[i].Key] = &f2.Lines[i]
		}
	}
	for _, w := range wantFinal {
		l, ok := linesByKey2[w.key]
		if !ok {
			t.Fatalf("key %q missing after re-parse", w.key)
		}
		if l.Value != w.value {
			t.Errorf("%s round-trip value = %q, want %q", w.key, l.Value, w.value)
		}
		if l.TrailingComment != w.comment {
			t.Errorf("%s round-trip TrailingComment = %q, want %q", w.key, l.TrailingComment, w.comment)
		}
	}
}
