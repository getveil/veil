package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/vault"
)

// testSetup creates a temporary vault with a mem keystore and a temporary
// audit store. It returns a Server ready for Start().
func testSetup(t *testing.T, creds ...*vault.Credential) (*Server, *vault.Vault, *audit.Store) {
	t.Helper()

	root := t.TempDir()
	ks := vault.NewMemKeystore()

	vlt, err := vault.CreateVault(root, "test-proxy-project", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	for _, c := range creds {
		if err := vlt.Add(c); err != nil {
			t.Fatalf("Add credential: %v", err)
		}
	}

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	store, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	srv, err := New(ca, vlt, store, 9999, "test-agent")
	if err != nil {
		t.Fatalf("New proxy: %v", err)
	}

	return srv, vlt, store
}

// httpClient returns an *http.Client configured to use the given proxy address.
func httpClient(proxyAddr string) *http.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}
}

// httpsClient returns an *http.Client configured to use the given proxy
// address for HTTPS, trusting the given CA certificate. Because the test
// upstream uses an IP address (127.0.0.1) and the leaf cache generates
// DNS SANs only, we skip hostname verification while still verifying the
// certificate chain against the proxy CA.
func httpsClient(proxyAddr string, caCert *x509.Certificate) *http.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:            pool,
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true, //nolint:gosec // test only: upstream is 127.0.0.1, leaf has DNS SAN only
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					// Manually verify the certificate chain against our CA pool.
					certs := make([]*x509.Certificate, len(rawCerts))
					for i, raw := range rawCerts {
						cert, err := x509.ParseCertificate(raw)
						if err != nil {
							return err
						}
						certs[i] = cert
					}
					intermediates := x509.NewCertPool()
					for _, c := range certs[1:] {
						intermediates.AddCert(c)
					}
					_, err := certs[0].Verify(x509.VerifyOptions{
						Roots:         pool,
						Intermediates: intermediates,
					})
					return err
				},
			},
		},
		Timeout: 5 * time.Second,
	}
}

func TestProxyHTTP(t *testing.T) {
	// Upstream HTTP server that echoes back the Authorization header.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(r.Header.Get("Authorization")))
	}))
	defer upstream.Close()

	cred := &vault.Credential{
		ID:           "cred-http-1",
		Name:         "http-token",
		Placeholder:  "VEIL_PH_HTTP_TOKEN_1234",
		Real:         "Bearer real-http-secret",
		Source:       "manual",
		CreatedAt:    time.Now().UTC(),
		AllowedHosts: []string{"127.0.0.1"},
	}
	srv, _, _ := testSetup(t, cred)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	client := httpClient(srv.Addr())
	req, _ := http.NewRequest("GET", upstream.URL+"/test", nil)
	req.Header.Set("Authorization", "VEIL_PH_HTTP_TOKEN_1234")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "Bearer real-http-secret" {
		t.Errorf("upstream received %q, want %q", string(body), "Bearer real-http-secret")
	}
}

func TestProxyHTTPS(t *testing.T) {
	// Upstream HTTPS server that echoes back the request body.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	defer upstream.Close()

	cred := &vault.Credential{
		ID:           "cred-https-1",
		Name:         "https-key",
		Placeholder:  "VEIL_PH_HTTPS_KEY_5678",
		Real:         "sk-real-https-secret",
		Source:       "manual",
		CreatedAt:    time.Now().UTC(),
		AllowedHosts: []string{"127.0.0.1"},
	}

	root := t.TempDir()
	ks := vault.NewMemKeystore()
	vlt, err := vault.CreateVault(root, "test-https-project", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if err := vlt.Add(cred); err != nil {
		t.Fatalf("Add: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	store, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	srv, err := New(ca, vlt, store, 9999, "test-agent")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The proxy's outbound transport must trust the httptest TLS server.
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())
	srv.proxy.Tr.TLSClientConfig = &tls.Config{
		RootCAs:    upstreamPool,
		MinVersion: tls.VersionTLS12,
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	// Client trusts our proxy CA (for MITM'd connections).
	client := httpsClient(srv.Addr(), ca.Cert)

	resp, err := client.Post(upstream.URL+"/echo", "text/plain",
		strings.NewReader("body=VEIL_PH_HTTPS_KEY_5678"))
	if err != nil {
		t.Fatalf("HTTPS request through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "sk-real-https-secret") {
		t.Errorf("upstream body = %q, want real secret", string(body))
	}
	if strings.Contains(string(body), "VEIL_PH_HTTPS_KEY_5678") {
		t.Errorf("placeholder should have been replaced in body")
	}
}

func TestProxyBodyInject(t *testing.T) {
	// Upstream echoes request body.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	defer upstream.Close()

	cred := &vault.Credential{
		ID:           "cred-body-1",
		Name:         "body-secret",
		Placeholder:  "VEIL_PH_BODY_ABCD",
		Real:         "injected-real-value",
		Source:       "manual",
		CreatedAt:    time.Now().UTC(),
		AllowedHosts: []string{"127.0.0.1"},
	}

	srv, _, _ := testSetup(t, cred)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	client := httpClient(srv.Addr())
	resp, err := client.Post(upstream.URL+"/body", "application/json",
		strings.NewReader(`{"key":"VEIL_PH_BODY_ABCD"}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "injected-real-value") {
		t.Errorf("body = %q, want real value", string(body))
	}
	if strings.Contains(string(body), "VEIL_PH_BODY_ABCD") {
		t.Error("placeholder should have been replaced")
	}
}

func TestProxyNoInjection(t *testing.T) {
	// Upstream echoes request body.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	defer upstream.Close()

	cred := &vault.Credential{
		ID:           "cred-noinj-1",
		Name:         "noinject-key",
		Placeholder:  "VEIL_PH_NOINJECT_XYZ",
		Real:         "should-not-appear",
		AllowedHosts: []string{"127.0.0.1"},
		Source:       "manual",
		CreatedAt:    time.Now().UTC(),
	}

	srv, _, _ := testSetup(t, cred)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	client := httpClient(srv.Addr())
	resp, err := client.Post(upstream.URL+"/passthru", "text/plain",
		strings.NewReader("nothing special here"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(body) != "nothing special here" {
		t.Errorf("body = %q, want unchanged passthrough", string(body))
	}
	if strings.Contains(string(body), "should-not-appear") {
		t.Error("real secret should not appear when no placeholder is present")
	}
}

func TestProxyStartStop(t *testing.T) {
	srv, _, _ := testSetup(t)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	addr := srv.Addr()
	if addr == "" {
		t.Fatal("Addr() returned empty string")
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	if host != "127.0.0.1" {
		t.Errorf("host = %q, want 127.0.0.1", host)
	}
	if portStr == "0" || portStr == "" {
		t.Errorf("port = %q, want a real port", portStr)
	}

	port := srv.Port()
	if port == 0 {
		t.Error("Port() returned 0")
	}
	if fmt.Sprintf("%d", port) != portStr {
		t.Errorf("Port() = %d, Addr port = %s", port, portStr)
	}

	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Verify the port is freed by attempting to listen on it.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port %s not freed after Stop: %v", addr, err)
	}
	_ = ln.Close()
}
