package proxy

import (
	"crypto/x509"
	"fmt"

	"github.com/smallstep/truststore"
)

// InstallCA installs the CA certificate at certPath into the system trust store.
func InstallCA(certPath string) error {
	if err := truststore.InstallFile(certPath); err != nil {
		return fmt.Errorf("install CA into trust store: %w", err)
	}
	return nil
}

// UninstallCA removes the CA certificate at certPath from the system trust store.
func UninstallCA(certPath string) error {
	if err := truststore.UninstallFile(certPath); err != nil {
		return fmt.Errorf("uninstall CA from trust store: %w", err)
	}
	return nil
}

// IsTrusted checks whether the given CA certificate is present in the system
// certificate pool by attempting to verify it against the system roots.
func IsTrusted(ca *CA) bool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return false
	}

	// A self-signed root CA will verify successfully only if it is present
	// in the provided root pool.
	_, err = ca.Cert.Verify(x509.VerifyOptions{
		Roots: pool,
	})
	return err == nil
}
