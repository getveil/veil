package placeholder

import (
	"bytes"
	"testing"
)

// deterministicReader returns a reader that cycles through the given bytes,
// providing deterministic "random" output for tests.
type deterministicReader struct {
	data []byte
	pos  int
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.data[r.pos%len(r.data)]
		r.pos++
	}
	return len(p), nil
}

func setDeterministicRng(seed byte) func() {
	old := rng
	rng = &deterministicReader{data: []byte{seed, seed + 1, seed + 2, seed + 3, seed + 7, seed + 13}}
	return func() { rng = old }
}

func TestGenerate_EmptyValue(t *testing.T) {
	_, err := Generate("KEY", "")
	if err == nil {
		t.Fatal("expected error for empty value")
	}
}

func TestGenerate_URLPath(t *testing.T) {
	restore := setDeterministicRng(42)
	defer restore()

	result, err := Generate("DATABASE_URL", "postgres://user:secret@host:5432/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "postgres://user:secret@host:5432/db" {
		t.Fatal("expected password to be replaced")
	}
	// Should still contain the scheme and host.
	if !bytes.Contains([]byte(result), []byte("postgres://")) {
		t.Fatalf("expected postgres scheme, got: %s", result)
	}
	if !bytes.Contains([]byte(result), []byte("@host:5432/db")) {
		t.Fatalf("expected host preserved, got: %s", result)
	}
}

func TestGenerate_ProviderMatch(t *testing.T) {
	restore := setDeterministicRng(10)
	defer restore()

	result, err := Generate("OPENAI_API_KEY", "sk-proj-abc123def456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != len("sk-proj-abc123def456") {
		t.Fatalf("expected same length, got %d vs %d", len(result), len("sk-proj-abc123def456"))
	}
	if result[:8] != "sk-proj-" {
		t.Fatalf("expected prefix preserved, got: %s", result)
	}
	if result == "sk-proj-abc123def456" {
		t.Fatal("expected different output from input")
	}
}

func TestGenerate_CharclassFallback(t *testing.T) {
	restore := setDeterministicRng(20)
	defer restore()

	value := "someRandomValue123!@#"
	result, err := Generate("UNKNOWN_KEY", value)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != len(value) {
		t.Fatalf("expected same length: got %d vs %d", len(result), len(value))
	}
	// Non-alphanumeric characters should be preserved.
	for i, r := range value {
		if r == '!' || r == '@' || r == '#' {
			if rune(result[i]) != r {
				t.Fatalf("expected separator preserved at pos %d: got %c, want %c", i, result[i], r)
			}
		}
	}
}

func TestGenerate_NonEmpty(t *testing.T) {
	// Generate should always return a non-empty string on success.
	result, err := Generate("KEY", "x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Fatal("expected non-empty result")
	}
}
