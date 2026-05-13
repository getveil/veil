package proxy

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestBuildCABundle(t *testing.T) {
	// Generate a CA to get realistic PEM bytes.
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	bundlePath, err := BuildCABundle(ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle: %v", err)
	}
	defer func() { _ = os.Remove(bundlePath) }()

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	// Bundle must contain the Veil CA.
	if !bytes.Contains(data, ca.CertPEM) {
		t.Error("bundle does not contain Veil CA PEM")
	}

	// Bundle must contain at least one other certificate (system CAs).
	// Count all CERTIFICATE blocks.
	rest := data
	count := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			count++
		}
	}
	if count < 2 {
		t.Fatalf("bundle has %d certificates, want at least 2 (system + veil)", count)
	}
}

func TestBuildCABundle_Cleanup(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	bundlePath, err := BuildCABundle(ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle: %v", err)
	}

	// File should exist.
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("bundle file does not exist: %v", err)
	}

	// Clean up and verify.
	RemoveCABundle(bundlePath)
	if _, err := os.Stat(bundlePath); !os.IsNotExist(err) {
		t.Fatalf("bundle file still exists after RemoveCABundle")
	}
}

func TestBuildJavaTruststoreIn(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	sessionDir := t.TempDir()
	bundlePath, err := BuildCABundleIn(sessionDir, ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundleIn: %v", err)
	}
	bundlePEM, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	p12Path, p12Password, err := BuildJavaTruststoreIn(sessionDir, bundlePEM)
	if err != nil {
		t.Fatalf("BuildJavaTruststoreIn: %v", err)
	}

	// Must live inside sessionDir (not a shared global path).
	if !strings.HasPrefix(p12Path, sessionDir) {
		t.Fatalf("PKCS12 path %q is outside sessionDir %q", p12Path, sessionDir)
	}

	// File must exist and be non-empty.
	info, err := os.Stat(p12Path)
	if err != nil {
		t.Fatalf("stat PKCS12: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("PKCS12 file is empty")
	}

	// PKCS12 must decode with the per-session random password.
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("read PKCS12: %v", err)
	}
	decoded, err := pkcs12.DecodeTrustStore(p12Data, p12Password)
	if err != nil {
		t.Fatalf("DecodeTrustStore: %v", err)
	}

	pemCount := 0
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			pemCount++
		}
	}
	if len(decoded) != pemCount {
		t.Fatalf("PKCS12 has %d certs, want %d (match PEM bundle)", len(decoded), pemCount)
	}

	// Veil CA specifically must be present in the decoded set.
	veilBlock, _ := pem.Decode(ca.CertPEM)
	if veilBlock == nil {
		t.Fatal("could not decode Veil CA PEM")
	}
	veilCert, err := x509.ParseCertificate(veilBlock.Bytes)
	if err != nil {
		t.Fatalf("parse Veil CA: %v", err)
	}
	found := false
	for _, c := range decoded {
		if c.Equal(veilCert) {
			found = true
			break
		}
	}
	if !found {
		t.Error("Veil CA not found in decoded PKCS12 truststore")
	}
}

func TestBuildJavaTruststoreIn_CleanedByRemoveAll(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	sessionDir := t.TempDir()
	bundlePath, err := BuildCABundleIn(sessionDir, ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundleIn: %v", err)
	}
	bundlePEM, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	p12Path, _, err := BuildJavaTruststoreIn(sessionDir, bundlePEM)
	if err != nil {
		t.Fatalf("BuildJavaTruststoreIn: %v", err)
	}

	if err := os.RemoveAll(sessionDir); err != nil {
		t.Fatalf("RemoveAll sessionDir: %v", err)
	}
	if _, err := os.Stat(p12Path); !os.IsNotExist(err) {
		t.Fatalf("PKCS12 still exists after RemoveAll sessionDir: stat err=%v", err)
	}
}

func TestBuildJavaTruststoreIn_EmptyPEMReturnsError(t *testing.T) {
	sessionDir := t.TempDir()
	_, _, err := BuildJavaTruststoreIn(sessionDir, nil)
	if err == nil {
		t.Fatal("expected error for empty PEM input")
	}
}

// TestBuildJavaTruststoreIn_FileModeIs0600 verifies that the on-disk PKCS12
// is written 0600 (owner-only). The truststore password is random per
// session, but defense-in-depth says don't make the file world-readable
// even when the parent session dir is 0700.
func TestBuildJavaTruststoreIn_FileModeIs0600(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	sessionDir := t.TempDir()
	bundlePath, err := BuildCABundleIn(sessionDir, ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundleIn: %v", err)
	}
	bundlePEM, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	p12Path, _, err := BuildJavaTruststoreIn(sessionDir, bundlePEM)
	if err != nil {
		t.Fatalf("BuildJavaTruststoreIn: %v", err)
	}

	info, err := os.Stat(p12Path)
	if err != nil {
		t.Fatalf("stat PKCS12: %v", err)
	}
	gotMode := info.Mode().Perm()
	wantMode := os.FileMode(0o600)
	if gotMode != wantMode {
		t.Fatalf("PKCS12 mode = %o, want %o", gotMode, wantMode)
	}
}

// TestBuildJavaTruststoreIn_PasswordIsRandomAndSafe verifies the returned
// password is non-empty, cryptographically random (different each call),
// and free of any character that would break a double-quoted JAVA_TOOL_OPTIONS
// segment (whitespace, double-quote, backslash, control chars).
func TestBuildJavaTruststoreIn_PasswordIsRandomAndSafe(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	sessionDir := t.TempDir()
	bundlePath, err := BuildCABundleIn(sessionDir, ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundleIn: %v", err)
	}
	bundlePEM, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	// Two consecutive calls must yield different passwords. Use sibling
	// session dirs so the second call doesn't overwrite the first.
	_, pw1, err := BuildJavaTruststoreIn(sessionDir, bundlePEM)
	if err != nil {
		t.Fatalf("BuildJavaTruststoreIn #1: %v", err)
	}

	sessionDir2 := t.TempDir()
	if _, err := BuildCABundleIn(sessionDir2, ca.CertPEM); err != nil {
		t.Fatalf("BuildCABundleIn #2: %v", err)
	}
	_, pw2, err := BuildJavaTruststoreIn(sessionDir2, bundlePEM)
	if err != nil {
		t.Fatalf("BuildJavaTruststoreIn #2: %v", err)
	}

	if pw1 == "" {
		t.Fatal("password #1 is empty")
	}
	if pw2 == "" {
		t.Fatal("password #2 is empty")
	}
	if pw1 == pw2 {
		t.Fatalf("two consecutive passwords are identical: %q (should be random)", pw1)
	}

	for _, pw := range []string{pw1, pw2} {
		for i, r := range pw {
			switch {
			case r == '"':
				t.Errorf("password contains double-quote at index %d: %q", i, pw)
			case r == '\\':
				t.Errorf("password contains backslash at index %d: %q", i, pw)
			case r == ' ' || r == '\t' || r == '\n' || r == '\r':
				t.Errorf("password contains whitespace at index %d: %q", i, pw)
			case r < 0x20 || r == 0x7f:
				t.Errorf("password contains control char 0x%x at index %d: %q", r, i, pw)
			}
		}
	}
}

// TestJavaToolOptionsFlags_QuotesPathWithSpace verifies that a session dir
// containing whitespace — common on macOS under "~/Library/Application
// Support/..." — is rendered as a single, double-quoted argument so the JVM
// launcher (which splits JAVA_TOOL_OPTIONS on whitespace but respects quoted
// segments) parses the trustStore flag correctly.
func TestJavaToolOptionsFlags_QuotesPathWithSpace(t *testing.T) {
	path := "/tmp/has space/java-truststore.p12"
	password := "abc123"
	got := JavaToolOptionsFlags(path, password)

	wantSubstr := `-Djavax.net.ssl.trustStore="/tmp/has space/java-truststore.p12"`
	if !strings.Contains(got, wantSubstr) {
		t.Fatalf("JavaToolOptionsFlags = %q, want substring %q", got, wantSubstr)
	}
	wantPasswordSubstr := `-Djavax.net.ssl.trustStorePassword="abc123"`
	if !strings.Contains(got, wantPasswordSubstr) {
		t.Fatalf("JavaToolOptionsFlags = %q, want substring %q", got, wantPasswordSubstr)
	}
	if !strings.Contains(got, "-Djavax.net.ssl.trustStoreType=PKCS12") {
		t.Fatalf("JavaToolOptionsFlags = %q, missing trustStoreType=PKCS12", got)
	}
}
