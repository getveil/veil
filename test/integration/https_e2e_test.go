package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2E_ProxyHTTPSInjection verifies the full HTTPS path end-to-end:
//
//	test → spawn `veil run curl https://localhost:<port>` →
//	proxy MITMs with a Veil-signed leaf whose DNS SAN matches "localhost" →
//	curl validates the leaf using SSL_CERT_FILE (Veil CA bundle, set by
//	runner.buildChildEnv) → proxy forwards to our TLS server trusting the
//	upstream CA via SSL_CERT_FILE in the veil parent env → upstream returns
//	200 with the injected Authorization header.
//
// Asserts:
//   - curl exits 0 and prints HTTP 200 (the full TLS chain works).
//   - upstream received the real secret (proving injection happened through MITM).
//   - audit log has a non-blocked injection entry for GITHUB_TOKEN.
//
// The veil binary is built with CGO_ENABLED=0 (see buildVeil), so Go's
// crypto/x509 uses root_unix.go on both darwin and linux — SSL_CERT_FILE is
// honored identically across platforms.
//
// We use a hostname ("localhost") rather than an IP because Veil's MITM leaf
// only populates DNSNames, not IPAddresses; curl strictly validates IP SANs.
// This mirrors real-world use where upstreams are DNS hostnames.
func TestE2E_ProxyHTTPSInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available on PATH; skipping HTTPS e2e test")
	}

	// Self-signed cert valid for DNS name "localhost". Used by our TLS server
	// and also serves as its own trust anchor (SSL_CERT_FILE in the veil parent).
	serverCert, caPEM := generateLocalhostCert(t)

	type captured struct{ Auth string }
	captureCh := make(chan captured, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captureCh <- captured{Auth: r.Header.Get("Authorization")}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	ts.StartTLS()
	defer ts.Close()

	upstreamCAFile := filepath.Join(t.TempDir(), "upstream-ca.pem")
	if err := os.WriteFile(upstreamCAFile, caPEM, 0o600); err != nil {
		t.Fatalf("write upstream CA: %v", err)
	}

	// Rewrite the URL to use "localhost" (which /etc/hosts maps to 127.0.0.1)
	// so the leaf's DNS SAN matches.
	_, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	if err != nil {
		t.Fatalf("split ts.URL %q: %v", ts.URL, err)
	}
	upstreamURL := "https://localhost:" + port

	env := makeEnv(t)
	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	originalKey := "ghp_httpstest1234567890abcdef1234567890"
	envContent := fmt.Sprintf("GITHUB_TOKEN=%s\n", originalKey)
	if err := os.WriteFile(filepath.Join(projDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	initCmd := exec.Command(veilBin, "init", "--path", projDir)
	initCmd.Env = env
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("veil init: %v\n%s", err, out)
	}

	placeholder := readPlaceholder(t, projDir, "GITHUB_TOKEN")
	if placeholder == "" || placeholder == originalKey {
		t.Fatal("could not find placeholder in rewritten .env")
	}

	// Scope the credential to localhost so the proxy injects on this host.
	addCmd := exec.Command(veilBin, "add", "--path", projDir, "--force",
		"--value", originalKey, "--host", "localhost", "GITHUB_TOKEN")
	addCmd.Env = env
	if out, err := addCmd.CombinedOutput(); err != nil {
		t.Fatalf("veil add: %v\n%s", err, out)
	}
	placeholder = readPlaceholder(t, projDir, "GITHUB_TOKEN")

	// Run curl through veil. SSL_CERT_FILE in the veil parent env tells the
	// proxy's outbound transport to trust our CA; runner.buildChildEnv strips
	// this and sets its own SSL_CERT_FILE=<veil-ca-bundle> for the child.
	//
	// --proxy + --noproxy '' force curl through the proxy even though localhost
	// is in NO_PROXY (runner.buildChildEnv defaults NO_PROXY to
	// localhost,127.0.0.1). Real upstreams aren't in NO_PROXY, so production
	// curl usage doesn't need these flags.
	runEnv := append(env, "SSL_CERT_FILE="+upstreamCAFile)
	curlCmd := fmt.Sprintf(
		`curl -sS -o /dev/null -w '%%{http_code}' --proxy "$HTTP_PROXY" --noproxy '' --cacert "$SSL_CERT_FILE" -H "Authorization: Bearer %s" %s/repos`,
		placeholder, upstreamURL,
	)
	runCmd := exec.Command(veilBin, "run", "--path", projDir, "--", "sh", "-c", curlCmd)
	runCmd.Env = runEnv
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil run curl failed: %v\n%s", err, runOut)
	}
	if !strings.Contains(string(runOut), "200") {
		t.Fatalf("expected HTTP 200 from curl, got output:\n%s", runOut)
	}

	cap := <-captureCh
	expectedAuth := "Bearer " + originalKey
	if cap.Auth != expectedAuth {
		t.Errorf("upstream Auth header: got %q, want %q", cap.Auth, expectedAuth)
	}
	if strings.Contains(cap.Auth, placeholder) {
		t.Errorf("placeholder leaked to upstream: %q", cap.Auth)
	}

	logCmd := exec.Command(veilBin, "log", "--path", projDir, "--json")
	logCmd.Env = env
	logOut, err := logCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil log: %v\n%s", err, logOut)
	}
	logStr := strings.TrimSpace(string(logOut))
	if logStr == "" {
		t.Fatal("audit log is empty; expected injection event")
	}
	var entry map[string]interface{}
	lines := strings.Split(logStr, "\n")
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parsing audit log JSON: %v\nline: %s", err, lines[0])
	}
	if entry["location"] == "blocked" {
		t.Error("injection should not be blocked for authorized host")
	}
	if entry["credential"] != "GITHUB_TOKEN" {
		t.Errorf("expected credential GITHUB_TOKEN, got %v", entry["credential"])
	}
}

// generateLocalhostCert returns a self-signed TLS certificate valid for DNS
// name "localhost" and IP 127.0.0.1, plus its PEM encoding suitable for use
// as a trust anchor (since it's self-signed, the cert is its own CA).
func generateLocalhostCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}, pemBytes
}

// readPlaceholder reads .env in projDir and returns the value of the given
// key. Returns "" if not found. Fails the test on read error.
func readPlaceholder(t *testing.T, projDir, key string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(projDir, ".env"))
	if err != nil {
		t.Fatalf("reading .env: %v", err)
	}
	prefix := key + "="
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}
