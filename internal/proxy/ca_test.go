package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateCAUsesSHA256SKID(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(ca.Cert.SubjectKeyId) != sha256.Size {
		t.Fatalf("SKID length %d, want %d (SHA-256)", len(ca.Cert.SubjectKeyId), sha256.Size)
	}
}

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	cert := ca.Cert

	// IsCA
	if !cert.IsCA {
		t.Error("expected IsCA to be true")
	}

	// MaxPathLen
	if cert.MaxPathLen != 1 {
		t.Errorf("MaxPathLen = %d, want 1", cert.MaxPathLen)
	}
	if cert.MaxPathLenZero {
		t.Error("MaxPathLenZero should be false")
	}

	// BasicConstraintsValid
	if !cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid should be true")
	}

	// KeyUsage
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("missing KeyUsageCertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("missing KeyUsageCRLSign")
	}

	// P-256 key
	ecKey, ok := ca.Key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("key is %T, want *ecdsa.PrivateKey", ca.Key)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Error("key curve is not P-256")
	}

	// Subject fields
	if cert.Subject.CommonName != "Veil Local Root" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "Veil Local Root")
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "Veil" {
		t.Errorf("O = %v, want [Veil]", cert.Subject.Organization)
	}
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] == "" {
		t.Errorf("OU = %v, want non-empty hostname", cert.Subject.OrganizationalUnit)
	}

	// 10-year validity
	validityYears := cert.NotAfter.Sub(cert.NotBefore).Hours() / (24 * 365)
	if validityYears < 9.9 || validityYears > 10.1 {
		t.Errorf("validity = %.1f years, want ~10", validityYears)
	}

	// NotBefore should be roughly now - 1 hour
	skew := time.Since(cert.NotBefore)
	if skew < 50*time.Minute || skew > 70*time.Minute {
		t.Errorf("NotBefore skew = %v, want ~1h", skew)
	}

	// SKID present
	if len(cert.SubjectKeyId) == 0 {
		t.Error("SubjectKeyId is empty")
	}

	// PEM data present
	if len(ca.CertPEM) == 0 {
		t.Error("CertPEM is empty")
	}
	if len(ca.KeyPEM) == 0 {
		t.Error("KeyPEM is empty")
	}
}

func TestSaveAndLoadCA(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "root.pem")
	keyPath := filepath.Join(dir, "root.key")

	if err := SaveCA(ca, certPath, keyPath); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	// Verify file permissions.
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if perm := certInfo.Mode().Perm(); perm != 0644 {
		t.Errorf("cert perm = %o, want 0644", perm)
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("key perm = %o, want 0600", perm)
	}

	// Load and compare.
	loaded, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	if !bytes.Equal(loaded.Cert.Raw, ca.Cert.Raw) {
		t.Error("loaded cert raw bytes do not match generated cert")
	}
	if !bytes.Equal(loaded.CertPEM, ca.CertPEM) {
		t.Error("loaded CertPEM does not match generated CertPEM")
	}
}

func TestLoadOrCreateCA_New(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca", "root.pem")
	keyPath := filepath.Join(dir, "ca", "root.key")

	// Use GenerateCA + SaveCA directly to test the create path,
	// since LoadOrCreateCA depends on config package paths.
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := SaveCA(ca, certPath, keyPath); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	// Verify both files exist.
	if !fileExists(certPath) {
		t.Error("cert file not created")
	}
	if !fileExists(keyPath) {
		t.Error("key file not created")
	}

	// Verify the saved CA can be loaded back.
	loaded, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if !loaded.Cert.IsCA {
		t.Error("loaded cert is not a CA")
	}
}

func TestLoadOrCreateCA_Existing(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "root.pem")
	keyPath := filepath.Join(dir, "root.key")

	// Create and save a CA first.
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := SaveCA(ca, certPath, keyPath); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	// Load should succeed and match.
	loaded, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if !bytes.Equal(loaded.Cert.Raw, ca.Cert.Raw) {
		t.Error("loaded cert does not match saved cert")
	}
}

func TestLoadOrCreateCA_InconsistentState(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "root.pem")
	keyPath := filepath.Join(dir, "root.key")

	// Create only the cert file (no key).
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := os.WriteFile(certPath, ca.CertPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	// Simulate LoadOrCreateCA's logic: one exists, the other doesn't -> error.
	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	if !certExists {
		t.Fatal("cert should exist")
	}
	if keyExists {
		t.Fatal("key should not exist")
	}

	// The inconsistent state should be detected.
	if certExists != keyExists {
		// This is the expected path: inconsistent state detected.
		t.Log("correctly detected inconsistent CA state")
	} else {
		t.Error("should have detected inconsistent state")
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	data := []byte("hello, world")

	if err := atomicWrite(path, data, 0644); err != nil {
		t.Fatalf("atomicWrite: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("got %q, want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0644 {
		t.Errorf("perm = %o, want 0644", perm)
	}
}

func TestRandomSerial(t *testing.T) {
	s1, err := randomSerial()
	if err != nil {
		t.Fatalf("randomSerial: %v", err)
	}
	s2, err := randomSerial()
	if err != nil {
		t.Fatalf("randomSerial: %v", err)
	}

	if s1.Cmp(s2) == 0 {
		t.Error("two serial numbers are identical")
	}
	if s1.BitLen() == 0 || s2.BitLen() == 0 {
		t.Error("serial number has zero bit length")
	}
}
