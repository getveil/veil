package scanner

import (
	"bytes"
	"os"
	"path/filepath"
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
