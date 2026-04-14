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
