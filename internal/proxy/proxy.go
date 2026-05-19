package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/placeholder"
	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
	"github.com/oklog/ulid/v2"
)

var (
	bodyWarnMu   sync.Mutex
	bodyWarnSeen = map[string]struct{}{}

	// sentinelBytes is the placeholder sentinel as a byte slice, precomputed
	// so the per-request body scan does not re-allocate it.
	sentinelBytes = []byte(placeholder.Sentinel)
)

// warnBodyReadOnce emits a warning on stderr at most once per host per
// session, preventing log spam from misbehaving clients.
func warnBodyReadOnce(host string, err error) {
	bodyWarnMu.Lock()
	defer bodyWarnMu.Unlock()
	if _, seen := bodyWarnSeen[host]; seen {
		return
	}
	bodyWarnSeen[host] = struct{}{}
	ui.Warnf(os.Stderr, "body read failed for %s: %v", host, err)
}

// mitmFilterWriter wraps an io.Writer and drops goproxy log lines that
// match benign MITM connection errors (client closed before proxy finished).
type mitmFilterWriter struct {
	out io.Writer
}

func (w *mitmFilterWriter) Write(p []byte) (int, error) {
	line := string(p)
	if strings.Contains(line, "Cannot read request from mitm'd client") &&
		strings.Contains(line, "connection reset by peer") {
		return len(p), nil // silently discard
	}
	if strings.Contains(line, "Cannot write response from mitm'd client") &&
		strings.Contains(line, "broken pipe") {
		return len(p), nil // silently discard
	}
	return w.out.Write(p)
}

// bodyCap is the maximum request body size the proxy will read for
// placeholder injection (10 MiB).
const bodyCap = 10 * 1024 * 1024

// Server is a local MITM proxy that intercepts HTTP/HTTPS traffic,
// replacing placeholder strings with real secrets via the Injector.
type Server struct {
	proxy    *goproxy.ProxyHttpServer
	listener net.Listener
	ca       *CA
	leafs    *LeafCache
	injector *Injector
	audit    *audit.Store
	addr     string
	done     chan struct{}
}

// New creates a new proxy Server wired with goproxy MITM, the injector,
// and audit store. The server is not yet listening; call Start().
func New(ca *CA, vlt *vault.Vault, auditStore *audit.Store, agentPID int, agentCmd string) (*Server, error) {
	px := goproxy.NewProxyHttpServer()
	px.Logger = log.New(&mitmFilterWriter{out: os.Stderr}, "", log.LstdFlags)

	// goproxy's default Tr.TLSClientConfig has InsecureSkipVerify=true. That
	// would hand the real credentials we're about to inject to any upstream
	// presenting any cert — exactly the MITM (hostile WiFi, DNS hijack,
	// captive portal) that Veil's threat model assumes can exist between us
	// and the API. Replace the default with a verifying config that also
	// honors SSL_CERT_FILE (matching curl/Python/Node/runner.buildChildEnv
	// conventions; Go's stdlib only reads it on non-darwin Unix).
	px.Tr.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    upstreamRootCAs(),
	}

	// Set the CA certificate that goproxy uses for MITM leaf signing.
	goproxy.GoproxyCa = tls.Certificate{
		Certificate: [][]byte{ca.Cert.Raw},
		PrivateKey:  ca.Key,
		Leaf:        ca.Cert,
	}

	leafs := NewLeafCache(ca)

	// For every CONNECT request, perform MITM using our leaf cache to
	// supply per-host TLS certificates signed by our CA.
	px.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			return &goproxy.ConnectAction{
				Action: goproxy.ConnectMitm,
				TLSConfig: func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
					hostname := stripHostPort(host)
					cert, err := leafs.GetOrCreate(hostname)
					if err != nil {
						return nil, err
					}
					return &tls.Config{
						Certificates: []tls.Certificate{*cert},
						MinVersion:   tls.VersionTLS12,
					}, nil
				},
			}, host
		},
	))

	inj := NewInjector(vlt.PlaceholderMap(), auditStore, agentPID, agentCmd)

	// Request handler: scan URL, headers, and body for placeholders.
	px.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Reject compressed bodies: Veil cannot scan or rewrite placeholders
		// inside a compressed payload without decompressing/re-compressing,
		// which can change Content-Length and silently drop matches under an
		// unknown encoding. "identity" is allowed (explicit "no compression").
		if ce := req.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(strings.TrimSpace(ce), "identity") {
			ui.Warnf(os.Stderr, "veil: rejecting request to %s — Content-Encoding %q not supported; Veil does not inject into compressed request bodies", req.Host, ce)
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway,
				"veil: Content-Encoding "+ce+" is not supported; Veil does not inject into compressed request bodies")
		}

		var body []byte
		if req.Body != nil && ShouldInjectBody(req.Header.Get("Content-Type")) {
			var err error
			// Read bodyCap+1 so we can detect oversize without buffering
			// unbounded input. A partial read still has to fail-closed: a
			// truncated copy may corrupt the request and may also defeat
			// placeholder scanning (a sentinel could sit past the cutoff).
			body, err = io.ReadAll(io.LimitReader(req.Body, int64(bodyCap)+1))
			_ = req.Body.Close()
			if err != nil {
				warnBodyReadOnce(req.Host, err)
				return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway,
					"veil: upstream body read failed")
			}
			if len(body) > bodyCap {
				ui.Warnf(os.Stderr,
					"veil: refusing to forward request to %s — body exceeds 10 MiB inject limit; split the request",
					req.Host)
				resp := goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway,
					"veil: request body exceeds 10 MiB inject limit; cannot scan for placeholders")
				resp.Header.Set("X-Veil-Error", "body_too_large")
				return req, resp
			}
		}

		requestID := ulid.Make().String()
		rawURL := req.URL.String()

		newURL, newHeader, newBody, _ := inj.ProcessRequest(
			requestID, req.Method, rawURL, req.Header, body)

		// Fail-closed sentinel guard: any sentinel in the final outbound
		// bytes means a placeholder wasn't swapped (host-scope mismatch,
		// partial match) or was planted by a caller. Block with 502 and
		// record a "leaked" audit row.
		if leakLocation, leaked := detectLeak(newURL, newHeader, newBody); leaked {
			if auditStore != nil {
				// Persist the pre-swap URL: if the URL swap succeeded but the
				// leak fired elsewhere, the post-swap URL contains the live
				// secret and would otherwise leak via `veil log --json`.
				host, urlPath, _ := parseRequestURL(rawURL)
				auditStore.Record(audit.Injection{
					Timestamp: time.Now(),
					RequestID: requestID,
					Host:      host,
					Method:    req.Method,
					URLPath:   urlPath,
					AgentPID:  agentPID,
					AgentCmd:  agentCmd,
					Location:  "leaked",
				})
			}
			ui.Warnf(os.Stderr, "veil: refusing to forward request to %s — placeholder leak detected in %s", req.Host, leakLocation)
			body := fmt.Sprintf("veil: placeholder leak detected in %s; request blocked (see audit log)", leakLocation)
			resp := goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway, body)
			return req, resp
		}

		// Apply modified URL.
		if newURL != req.URL.String() {
			parsed, err := url.Parse(newURL)
			if err == nil {
				req.URL = parsed
			}
		}

		// Apply modified headers and body.
		req.Header = newHeader
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(newBody))
			req.ContentLength = int64(len(newBody))
		}

		return req, nil
	})

	return &Server{
		proxy:    px,
		ca:       ca,
		leafs:    leafs,
		injector: inj,
		audit:    auditStore,
		done:     make(chan struct{}),
	}, nil
}

// Start begins listening on a random loopback port and serving requests.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrListen, err)
	}
	s.listener = ln
	s.addr = ln.Addr().String()

	go func() {
		_ = http.Serve(ln, s.proxy) //nolint:gosec // loopback-only listener, no TLS needed for the proxy itself
	}()

	return nil
}

// Addr returns the host:port string the proxy is listening on.
func (s *Server) Addr() string {
	return s.addr
}

// Port returns just the port number the proxy is listening on.
func (s *Server) Port() int {
	_, portStr, err := net.SplitHostPort(s.addr)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(portStr)
	return port
}

// Stop closes the listener and signals shutdown.
func (s *Server) Stop() error {
	close(s.done)
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// upstreamRootCAs returns the cert pool used to verify upstream TLS. It
// starts from the platform system pool (macOS keychain / system store) and
// appends certs from $SSL_CERT_FILE when set. Returning nil falls back to
// the stdlib default; we only construct a custom pool if SSL_CERT_FILE adds
// something. Errors are silent: a missing or unreadable bundle just leaves
// the pool unchanged, which is the conservative choice for a verifier.
func upstreamRootCAs() *x509.CertPool {
	path := os.Getenv("SSL_CERT_FILE")
	if path == "" {
		return nil
	}
	pem, err := os.ReadFile(path) // #nosec G304 G703 -- SSL_CERT_FILE is the standard env var the user sets to override the CA bundle
	if err != nil {
		return nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM(pem)
	return pool
}

// stripHostPort removes the port from a host:port string. If there is no
// port, the host is returned unchanged.
func stripHostPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

// detectLeak scans URL, header values, and body for the placeholder
// sentinel. The returned location is "url", "header:<name>", or "body".
func detectLeak(newURL string, newHeader http.Header, newBody []byte) (location string, leaked bool) {
	if strings.Contains(newURL, placeholder.Sentinel) {
		return "url", true
	}
	for name, values := range newHeader {
		for _, v := range values {
			if strings.Contains(v, placeholder.Sentinel) {
				return "header:" + name, true
			}
		}
	}
	if len(newBody) > 0 && bytes.Contains(newBody, sentinelBytes) {
		return "body", true
	}
	return "", false
}
