// Package proxy implements Veil's HTTPS MITM proxy.
package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 for SKID per RFC 5280 s4.2.1.2
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/8enji/veil/internal/config"
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
		return nil, fmt.Errorf("ca cert path: %w", err)
	}
	keyPath, err := config.CAKeyFile()
	if err != nil {
		return nil, fmt.Errorf("ca key path: %w", err)
	}

	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	switch {
	case certExists && keyExists:
		return LoadCA(certPath, keyPath)
	case !certExists && !keyExists:
		ca, err := GenerateCA()
		if err != nil {
			return nil, fmt.Errorf("generate ca: %w", err)
		}
		if err := SaveCA(ca, certPath, keyPath); err != nil {
			return nil, fmt.Errorf("save ca: %w", err)
		}
		return ca, nil
	default:
		return nil, errors.New("inconsistent CA state: one of cert/key exists without the other")
	}
}

// LoadCA reads a CA certificate and private key from PEM files on disk.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("failed to decode CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to decode CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
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
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Compute SubjectKeyIdentifier as SHA-1 of the marshalled public key.
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	skid := sha1.Sum(pubBytes) //nolint:gosec // SHA-1 for SKID per RFC 5280 s4.2.1.2

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
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ec private key: %w", err)
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
