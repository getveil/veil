package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func testCA(t *testing.T) *CA {
	t.Helper()
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	return ca
}

func TestGetOrCreate(t *testing.T) {
	ca := testCA(t)
	lc := NewLeafCache(ca)

	cert, err := lc.GetOrCreate("example.com")
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}

	// Parse the leaf certificate.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// Verify it's signed by the CA.
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: roots,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	})
	if err != nil {
		t.Fatalf("verify leaf: %v", err)
	}

	// Check Subject/DNSNames/ExtKeyUsage.
	if leaf.Subject.CommonName != "example.com" {
		t.Errorf("CN = %q, want %q", leaf.Subject.CommonName, "example.com")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v, want [example.com]", leaf.DNSNames)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage = %v, want [ServerAuth]", leaf.ExtKeyUsage)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("missing KeyUsageDigitalSignature")
	}
}

func TestCacheHit(t *testing.T) {
	ca := testCA(t)
	lc := NewLeafCache(ca)

	cert1, err := lc.GetOrCreate("example.com")
	if err != nil {
		t.Fatalf("GetOrCreate 1: %v", err)
	}
	cert2, err := lc.GetOrCreate("example.com")
	if err != nil {
		t.Fatalf("GetOrCreate 2: %v", err)
	}

	// Parse both to compare serial numbers.
	leaf1, _ := x509.ParseCertificate(cert1.Certificate[0])
	leaf2, _ := x509.ParseCertificate(cert2.Certificate[0])

	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) != 0 {
		t.Error("cache miss: different serial numbers on second call")
	}
}

func TestExpiry(t *testing.T) {
	ca := testCA(t)
	lc := NewLeafCache(ca)

	cert1, err := lc.GetOrCreate("example.com")
	if err != nil {
		t.Fatalf("GetOrCreate 1: %v", err)
	}
	leaf1, _ := x509.ParseCertificate(cert1.Certificate[0])

	// Manually expire the cache entry.
	lc.mu.Lock()
	entry := lc.entries["example.com"]
	entry.created = time.Now().Add(-2 * time.Hour)
	lc.mu.Unlock()

	cert2, err := lc.GetOrCreate("example.com")
	if err != nil {
		t.Fatalf("GetOrCreate 2: %v", err)
	}
	leaf2, _ := x509.ParseCertificate(cert2.Certificate[0])

	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) == 0 {
		t.Error("expected new cert after expiry, got same serial")
	}
}

func TestEviction(t *testing.T) {
	ca := testCA(t)
	lc := NewLeafCache(ca)
	lc.maxSize = 2

	// Fill with 3 different hosts.
	if _, err := lc.GetOrCreate("a.com"); err != nil {
		t.Fatalf("GetOrCreate a.com: %v", err)
	}

	// Ensure ordering: make a.com the oldest.
	lc.mu.Lock()
	lc.entries["a.com"].created = time.Now().Add(-10 * time.Minute)
	lc.mu.Unlock()

	if _, err := lc.GetOrCreate("b.com"); err != nil {
		t.Fatalf("GetOrCreate b.com: %v", err)
	}
	if _, err := lc.GetOrCreate("c.com"); err != nil {
		t.Fatalf("GetOrCreate c.com: %v", err)
	}

	if lc.Size() != 2 {
		t.Errorf("cache size = %d, want 2", lc.Size())
	}

	// a.com should have been evicted (oldest).
	lc.mu.RLock()
	_, hasA := lc.entries["a.com"]
	lc.mu.RUnlock()
	if hasA {
		t.Error("a.com should have been evicted")
	}
}

func TestLeafValidForTLS(t *testing.T) {
	ca := testCA(t)
	lc := NewLeafCache(ca)

	host := "tls-test.example.com"
	leafCert, err := lc.GetOrCreate(host)
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}

	// Server TLS config using the leaf cert.
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
	}

	// Client TLS config trusting our CA.
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	clientCfg := &tls.Config{
		RootCAs:    roots,
		ServerName: host,
	}

	// Create a pipe and wrap in TLS.
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	errCh := make(chan error, 2)

	go func() {
		tlsServer := tls.Server(serverConn, serverCfg)
		errCh <- tlsServer.Handshake()
		_ = tlsServer.Close()
	}()

	go func() {
		tlsClient := tls.Client(clientConn, clientCfg)
		errCh <- tlsClient.Handshake()
		_ = tlsClient.Close()
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("TLS handshake error: %v", err)
		}
	}
}

func TestLeafCacheSize(t *testing.T) {
	ca := testCA(t)
	lc := NewLeafCache(ca)

	if lc.Size() != 0 {
		t.Errorf("initial size = %d, want 0", lc.Size())
	}

	if _, err := lc.GetOrCreate("one.com"); err != nil {
		t.Fatal(err)
	}
	if lc.Size() != 1 {
		t.Errorf("size = %d, want 1", lc.Size())
	}

	if _, err := lc.GetOrCreate("two.com"); err != nil {
		t.Fatal(err)
	}
	if lc.Size() != 2 {
		t.Errorf("size = %d, want 2", lc.Size())
	}

	// Same host should not increase size.
	if _, err := lc.GetOrCreate("one.com"); err != nil {
		t.Fatal(err)
	}
	if lc.Size() != 2 {
		t.Errorf("size = %d, want 2 (duplicate)", lc.Size())
	}
}
