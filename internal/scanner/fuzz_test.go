package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseEnvFile feeds random bytes to ParseFile and asserts no panic.
// For any input that parses successfully without dirty lines, Bytes() must
// round-trip to the original bytes — a property the production parser
// promises callers that edit .env files in place.
func FuzzParseEnvFile(f *testing.F) {
	seedFromFile(f, "../../test/fixtures/envs/comprehensive.env")

	// Edge cases not already covered by the fixture.
	f.Add([]byte(""))
	f.Add([]byte("\n"))
	f.Add([]byte("KEY=val\n"))
	f.Add([]byte("export FOO='bar'\n"))
	f.Add([]byte("KEY=\"unclosed\n"))
	f.Add([]byte("# comment only\n"))
	f.Add([]byte("KEY=val # inline\n"))
	f.Add([]byte("=noKey\n"))
	f.Add([]byte("KEY='unclosed single\n"))
	f.Add([]byte("KEY=\"with \\\"escaped\\\" quote\"\n"))
	f.Add([]byte("export KEY=val"))
	f.Add([]byte("\t  \t\n"))

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(dir, "fuzz.env")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		ef, err := ParseFile(path)
		if err != nil {
			t.Fatalf("ParseFile returned error on readable file: %v", err)
		}
		if got := ef.Bytes(); !bytes.Equal(got, data) {
			t.Fatalf("round-trip mismatch\n input:  %q\n output: %q", data, got)
		}
	})
}

func seedFromFile(f *testing.F, path string) {
	f.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		f.Fatalf("read seed %s: %v", path, err)
	}
	f.Add(data)
}
