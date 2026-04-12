package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"sync"
	"time"
)

const (
	defaultLeafCacheSize = 512
	defaultLeafTTL       = 1 * time.Hour
)

// LeafCache caches per-host TLS leaf certificates signed by a root CA.
type LeafCache struct {
	ca      *CA
	mu      sync.RWMutex
	entries map[string]*leafEntry
	maxSize int
	ttl     time.Duration
}

type leafEntry struct {
	cert    *tls.Certificate
	created time.Time
}

// NewLeafCache creates a new leaf certificate cache backed by the given CA.
func NewLeafCache(ca *CA) *LeafCache {
	return &LeafCache{
		ca:      ca,
		entries: make(map[string]*leafEntry),
		maxSize: defaultLeafCacheSize,
		ttl:     defaultLeafTTL,
	}
}

// GetOrCreate returns a cached TLS certificate for the given SNI host,
// generating and caching a new one if needed.
func (lc *LeafCache) GetOrCreate(sniHost string) (*tls.Certificate, error) {
	// Fast path: check cache under read lock.
	lc.mu.RLock()
	if entry, ok := lc.entries[sniHost]; ok {
		if time.Since(entry.created) < lc.ttl {
			cert := entry.cert
			lc.mu.RUnlock()
			return cert, nil
		}
	}
	lc.mu.RUnlock()

	// Slow path: generate under write lock.
	lc.mu.Lock()
	defer lc.mu.Unlock()

	// Double-check after acquiring write lock.
	if entry, ok := lc.entries[sniHost]; ok {
		if time.Since(entry.created) < lc.ttl {
			return entry.cert, nil
		}
	}

	cert, err := lc.generateLeaf(sniHost)
	if err != nil {
		return nil, err
	}

	// Evict oldest entry if at capacity.
	if len(lc.entries) >= lc.maxSize {
		lc.evictOldest()
	}

	lc.entries[sniHost] = &leafEntry{
		cert:    cert,
		created: time.Now(),
	}

	return cert, nil
}

// Size returns the current number of cached leaf certificates.
func (lc *LeafCache) Size() int {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	return len(lc.entries)
}

func (lc *LeafCache) generateLeaf(sniHost string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("leaf serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: sniHost,
		},
		DNSNames:    []string{sniHost},
		NotBefore:   now.Add(-10 * time.Minute),
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, lc.ca.Cert, &key.PublicKey, lc.ca.Key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf cert: %w", err)
	}

	leafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER, lc.ca.Cert.Raw},
		PrivateKey:  key,
		Leaf:        leafCert,
	}, nil
}

// evictOldest removes the cache entry with the earliest creation time.
// Must be called with lc.mu held for writing.
func (lc *LeafCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for k, v := range lc.entries {
		if first || v.created.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.created
			first = false
		}
	}

	if !first {
		delete(lc.entries, oldestKey)
	}
}
