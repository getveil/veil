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

// TestTryURL_PasswordWithUnencodedAt covers the H1 security bug: when a
// password contains an unencoded '@' (common in .env DB URLs like
// "postgres://user:p@ss@host/db"), the prior implementation used
// strings.Index to locate the userinfo terminator and so split at the FIRST
// '@'. That treated the leading "p" as the password and let "ss" bleed
// through into the placeholder, leaking the secret. Go's net/url uses
// LastIndex for '@' within the authority, which is what the fixed code must
// match.
func TestTryURL_PasswordWithUnencodedAt(t *testing.T) {
	restore := setDeterministicRng(100)
	defer restore()

	// net/url parses this so userinfo is "user:p@sswordX" and host is
	// "host:5432". Use a long password so length preservation routes
	// through the in-place sentinel overwrite (the rawPassword-length
	// placeholder).
	input := "postgres://user:p@sswordX@host:5432/db"
	rawPassword := "p@sswordX"

	result, ok := tryURL(input)
	if !ok {
		t.Fatal("expected ok=true for postgres URL with password containing '@'")
	}
	if result == input {
		t.Fatal("expected password to be replaced")
	}
	// Scheme, user, host, port, path must be preserved exactly.
	if !strings.HasPrefix(result, "postgres://user:") {
		t.Fatalf("expected user preserved, got: %s", result)
	}
	if !strings.HasSuffix(result, "@host:5432/db") {
		t.Fatalf("expected host/path preserved, got: %s", result)
	}
	// The replaced password section (between "user:" and the FINAL '@') must
	// differ from the original raw password.
	const prefix = "postgres://user:"
	const suffix = "@host:5432/db"
	mid := result[len(prefix) : len(result)-len(suffix)]
	if mid == rawPassword {
		t.Fatalf("password section was not replaced: %q", mid)
	}
	if len(mid) != len(rawPassword) {
		t.Fatalf("password length changed: %d vs %d (mid=%q)", len(mid), len(rawPassword), mid)
	}
	// The most direct symptom of the H1 bug: the tail of the password after
	// the FIRST '@' ("sswordX") would survive verbatim as a suffix of the
	// authority. The fix replaces the whole password, so the leak substring
	// must not appear anywhere in the result.
	const leak = "sswordX"
	if strings.Contains(result, leak) {
		t.Fatalf("raw password tail %q leaked into result: %s", leak, result)
	}
	// And the full original raw password as a substring must not appear.
	if strings.Contains(result, rawPassword) {
		t.Fatalf("raw password %q appears in result: %s", rawPassword, result)
	}
}

// TestTryURL_PasswordWithAtColonAndPathAt exercises a password containing
// both '@' and ':' alongside a path that itself contains '@' and '/'. The
// authority terminator is the first '/', '?', or '#' after authStart, so the
// path '@' must NOT be treated as the userinfo terminator. Within the
// authority, the boundary is the LAST '@', matching Go's net/url. The buggy
// implementation used strings.Index over the entire post-scheme remainder
// and so picked the FIRST '@' (inside the password), leaking the rest of
// the password into the placeholder.
func TestTryURL_PasswordWithAtColonAndPathAt(t *testing.T) {
	restore := setDeterministicRng(110)
	defer restore()

	// net/url parses this with userinfo "user:p@sX:tY", host "db.host", and
	// path "/x@y/z". Raw password as it appears in the URL string is
	// "p@sX:tY" (length 7, longer than the sentinel "VEIL").
	input := "postgres://user:p@sX:tY@db.host/x@y/z"
	rawPassword := "p@sX:tY"

	result, ok := tryURL(input)
	if !ok {
		t.Fatal("expected ok=true for postgres URL with '@' and ':' in password")
	}
	if result == input {
		t.Fatal("expected password to be replaced")
	}
	if len(result) != len(input) {
		t.Fatalf("URL length changed: input=%d result=%d\n  input:  %s\n  result: %s", len(input), len(result), input, result)
	}
	// Host plus path (which itself contains '@' and '/') must be preserved
	// byte-for-byte. This catches the bug where the buggy boundary logic
	// would treat the path '@' as the userinfo terminator and corrupt the
	// rest of the URL.
	if !strings.HasSuffix(result, "@db.host/x@y/z") {
		t.Fatalf("expected '@db.host/x@y/z' preserved, got: %s", result)
	}
	if !strings.HasPrefix(result, "postgres://user:") {
		t.Fatalf("expected user preserved, got: %s", result)
	}
	const prefix = "postgres://user:"
	const suffix = "@db.host/x@y/z"
	mid := result[len(prefix) : len(result)-len(suffix)]
	if mid == rawPassword {
		t.Fatalf("password section was not replaced: %q", mid)
	}
	if len(mid) != len(rawPassword) {
		t.Fatalf("password length changed: %d vs %d (mid=%q)", len(mid), len(rawPassword), mid)
	}
	// The most direct symptom of the H1 bug for this URL: the tail of the
	// password after the FIRST '@' ("sX:tY") would survive verbatim, and the
	// FULL raw password would appear in the URL. The fix replaces the whole
	// password, so neither substring must appear in the result.
	const leak = "sX:tY"
	if strings.Contains(result, leak) {
		t.Fatalf("raw password tail %q leaked into result: %s", leak, result)
	}
	if strings.Contains(result, rawPassword) {
		t.Fatalf("raw password %q appears in result: %s", rawPassword, result)
	}
}

// TestTryURL_NoPathPasswordWithAt covers an authority-only URL (no path,
// query, or fragment) where the password contains an unencoded '@'. This
// asserts the authority-end logic falls through to len(value) when no path
// delimiter exists, so the userinfo/host boundary is found correctly.
func TestTryURL_NoPathPasswordWithAt(t *testing.T) {
	restore := setDeterministicRng(120)
	defer restore()

	// net/url parses this with userinfo "user:p@sswordX" and host "host".
	input := "postgres://user:p@sswordX@host"
	rawPassword := "p@sswordX"

	result, ok := tryURL(input)
	if !ok {
		t.Fatal("expected ok=true for postgres URL with password containing '@' and no path")
	}
	if result == input {
		t.Fatal("expected password to be replaced")
	}
	if !strings.HasPrefix(result, "postgres://user:") {
		t.Fatalf("expected user preserved, got: %s", result)
	}
	if !strings.HasSuffix(result, "@host") {
		t.Fatalf("expected host preserved, got: %s", result)
	}
	const prefix = "postgres://user:"
	const suffix = "@host"
	mid := result[len(prefix) : len(result)-len(suffix)]
	if mid == rawPassword {
		t.Fatalf("password section was not replaced: %q", mid)
	}
	if len(mid) != len(rawPassword) {
		t.Fatalf("password length changed: %d vs %d (mid=%q)", len(mid), len(rawPassword), mid)
	}
	// In the authority-only URL form, the bug would leave "sswordX" as a
	// suffix immediately before the '@' that introduces the host. The fix
	// replaces the entire password, so the leak substring and the full
	// password must not appear in the result.
	const leak = "sswordX"
	if strings.Contains(result, leak) {
		t.Fatalf("raw password tail %q leaked into result: %s", leak, result)
	}
	if strings.Contains(result, rawPassword) {
		t.Fatalf("raw password %q appears in result: %s", rawPassword, result)
	}
}
