package placeholder

import (
	"strings"
	"testing"
)

func TestTryURL_PostgresPassword(t *testing.T) {
	restore := setDeterministicRng(50)
	defer restore()

	input := "postgres://user:secret@host:5432/db"
	result, ok := tryURL(input)
	if !ok {
		t.Fatal("expected ok=true for postgres URL with password")
	}
	if result == input {
		t.Fatal("expected password to be replaced")
	}
	// Scheme, user, host, port, path should be preserved.
	if !strings.HasPrefix(result, "postgres://user:") {
		t.Fatalf("expected user preserved, got: %s", result)
	}
	if !strings.HasSuffix(result, "@host:5432/db") {
		t.Fatalf("expected host/path preserved, got: %s", result)
	}
	// The password part should be different from "secret".
	parts := strings.SplitN(result[len("postgres://user:"):], "@", 2)
	if parts[0] == "secret" {
		t.Fatal("password was not replaced")
	}
	if len(parts[0]) != len("secret") {
		t.Fatalf("password length changed: %d vs %d", len(parts[0]), len("secret"))
	}
}

func TestTryURL_HTTPSPassword(t *testing.T) {
	restore := setDeterministicRng(60)
	defer restore()

	input := "https://user:pass@host/path?q=1"
	result, ok := tryURL(input)
	if !ok {
		t.Fatal("expected ok=true for https URL with password")
	}
	if result == input {
		t.Fatal("expected password to be replaced")
	}
	if !strings.Contains(result, "host/path?q=1") {
		t.Fatalf("expected query preserved, got: %s", result)
	}
}

func TestTryURL_NoPassword(t *testing.T) {
	_, ok := tryURL("redis://host:6379")
	if ok {
		t.Fatal("expected ok=false for URL without password")
	}
}

func TestTryURL_UnsupportedScheme(t *testing.T) {
	_, ok := tryURL("ftp://user:pass@host")
	if ok {
		t.Fatal("expected ok=false for unsupported scheme")
	}
}

func TestTryURL_PlainString(t *testing.T) {
	_, ok := tryURL("not-a-url")
	if ok {
		t.Fatal("expected ok=false for plain string")
	}
}

func TestTryURL_PostgreSQLScheme(t *testing.T) {
	restore := setDeterministicRng(70)
	defer restore()

	result, ok := tryURL("postgresql://admin:hunter2@db.example.com:5432/mydb")
	if !ok {
		t.Fatal("expected ok=true for postgresql scheme")
	}
	if !strings.HasPrefix(result, "postgresql://admin:") {
		t.Fatalf("expected scheme/user preserved, got: %s", result)
	}
}

func TestTryURL_MongoDBSRV(t *testing.T) {
	restore := setDeterministicRng(80)
	defer restore()

	_, ok := tryURL("mongodb+srv://user:pass@cluster.mongodb.net/db")
	if !ok {
		t.Fatal("expected ok=true for mongodb+srv scheme")
	}
}

func TestTryURL_LengthPreserved(t *testing.T) {
	restore := setDeterministicRng(90)
	defer restore()

	// Password must be longer than len(Sentinel) for length preservation —
	// shorter passwords route through sentinelize's append branch to avoid
	// producing a deterministic, zero-randomness placeholder.
	input := "postgres://user:p4ssw0rd@host/db"
	result, ok := tryURL(input)
	if !ok {
		t.Fatal("expected ok=true for postgres URL with password")
	}
	if len(result) != len(input) {
		t.Fatalf("URL length changed: input=%d result=%d\n  input:  %s\n  result: %s", len(input), len(result), input, result)
	}
}
