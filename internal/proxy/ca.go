// Package proxy implements Veil's HTTPS MITM proxy.
package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/getveil/veil/internal/config"
)

// CA holds a root certificate authority used for signing leaf certificates.
type CA struct {
	Cert    *x509.Certificate
	Key     crypto.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// LoadOrCreateCA loads an existing CA from disk or generates a new one.
// It returns an error if only one of the cert/key files exists (inconsistent state).
func LoadOrCreateCA() (*CA, error) {
	certPath, err := config.CAFile()
	if err != nil {
		return nil, fmt.Errorf("%w: ca cert path: %w", ErrCALoad, err)
	}
	keyPath, err := config.CAKeyFile()
	if err != nil {
		return nil, fmt.Errorf("%w: ca key path: %w", ErrCALoad, err)
	}

	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	switch {
	case certExists && keyExists:
		return LoadCA(certPath, keyPath)
	case !certExists && !keyExists:
		ca, err := GenerateCA()
		if err != nil {
			return nil, fmt.Errorf("%w: generate ca: %w", ErrCAGenerate, err)
		}
		if err := SaveCA(ca, certPath, keyPath); err != nil {
			return nil, fmt.Errorf("%w: save ca: %w", ErrCAGenerate, err)
		}
		return ca, nil
	default:
		return nil, fmt.Errorf("%w: inconsistent CA state: one of cert/key exists without the other", ErrCALoad)
	}
}

// LoadCA reads a CA certificate and private key from PEM files on disk.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read ca cert: %w", ErrCALoad, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read ca key: %w", ErrCALoad, err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("%w: failed to decode CA certificate PEM", ErrCALoad)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse ca cert: %w", ErrCALoad, err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("%w: failed to decode CA key PEM", ErrCALoad)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse ca key: %w", ErrCALoad, err)
	}

	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// GenerateCA creates a new self-signed root CA with a P-256 ECDSA key.
func GenerateCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: generate ecdsa key: %w", ErrCAGenerate, err)
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCAGenerate, err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Compute SubjectKeyIdentifier as SHA-256 of the marshalled public key.
	// RFC 5280 s4.2.1.2 recommends SHA-1 but permits any method; we prefer
	// SHA-256 to avoid shipping a SHA-1 digest in freshly-minted roots.
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal public key: %w", ErrCAGenerate, err)
	}
	skid := sha256.Sum256(pubBytes)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "Veil Local Root",
			Organization:       []string{"Veil"},
			OrganizationalUnit: []string{hostname},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          skid[:],
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("%w: create certificate: %w", ErrCAGenerate, err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("%w: parse generated cert: %w", ErrCAGenerate, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal ec private key: %w", ErrCAGenerate, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// SaveCA writes the CA certificate and key to disk atomically.
func SaveCA(ca *CA, certPath, keyPath string) error {
	if err := config.EnsureDir(filepath.Dir(certPath), 0700); err != nil {
		return fmt.Errorf("ensure cert dir: %w", err)
	}
	if err := config.EnsureDir(filepath.Dir(keyPath), 0700); err != nil {
		return fmt.Errorf("ensure key dir: %w", err)
	}

	if err := atomicWrite(certPath, ca.CertPEM, 0644); err != nil {
		return fmt.Errorf("write ca cert: %w", err)
	}
	if err := atomicWrite(keyPath, ca.KeyPEM, 0600); err != nil {
		return fmt.Errorf("write ca key: %w", err)
	}
	return nil
}

// randomSerial generates a random 128-bit serial number for an X.509 certificate.
func randomSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}

// atomicWrite writes data to a temporary file then renames it to the target path.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".veil-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	defer func() {
		// Clean up temp file on failure.
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp to target: %w", err)
	}
	return nil
}

// fileExists returns true if the given path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
