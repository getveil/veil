package proxy

import (
	"bytes"
	"crypto/tls"
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

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/ui"
	"github.com/8enji/veil/internal/vault"
	"github.com/elazarl/goproxy"
	"github.com/oklog/ulid/v2"
)

var (
	bodyWarnMu   sync.Mutex
	bodyWarnSeen = map[string]struct{}{}
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
		// SEC-3: reject compressed request bodies. Veil cannot reliably
		// scan or rewrite placeholder strings inside a compressed payload
		// without decompressing, mutating, and re-compressing — which can
		// change Content-Length, interact with Content-MD5, and silently
		// drop matches if the client used an encoding we don't understand.
		// Returning 502 surfaces the mismatch to the caller rather than
		// forwarding a payload that may still contain real placeholders.
		// Explicit identity is allowed because it signals "no compression".
		if ce := req.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(strings.TrimSpace(ce), "identity") {
			ui.Warnf(os.Stderr, "veil: rejecting request to %s — Content-Encoding %q not supported; Veil does not inject into compressed request bodies", req.Host, ce)
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway,
				"veil: Content-Encoding "+ce+" is not supported; Veil does not inject into compressed request bodies")
		}

		var body []byte
		if req.Body != nil && ShouldInjectBody(req.Header.Get("Content-Type")) {
			var err error
			body, err = io.ReadAll(io.LimitReader(req.Body, int64(bodyCap)+1))
			_ = req.Body.Close()
			if err != nil {
				// H6: body read failed; surface 502 rather than forwarding a
				// possibly-truncated payload that may still contain placeholder
				// strings.
				warnBodyReadOnce(req.Host, err)
				return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway,
					"veil: upstream body read failed")
			}
		}

		requestID := ulid.Make().String()

		newURL, newHeader, newBody, injections := inj.ProcessRequest(
			requestID, req.Method, req.URL.String(), req.Header, body)

		// --- Fail-closed signer guard ---
		// If any signer (AWS SigV4, GitHub App JWT, …) emitted a
		// signer_failed injection, we must not forward the request: the
		// placeholder credentials the SDK computed its signature against
		// are about to go on the wire, or the AKID/AppID points to an
		// identity we don't own. The 502 surfaces the error class to the
		// caller via X-Veil-Error so agents can diagnose without parsing
		// the audit log. The audit row was already recorded by the
		// injector.
		if sf := firstSignerFailure(injections); sf != nil {
			ui.Warnf(os.Stderr, "veil: refusing to forward request to %s — signer failed (%s)", req.Host, sf.SignerError)
			resp := goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway,
				fmt.Sprintf("veil: signer failed (%s); request blocked (see audit log)", sf.SignerError))
			resp.Header.Set("X-Veil-Error", sf.SignerError)
			return req, resp
		}

		// --- Fail-closed sentinel guard ---
		// Scan the final outbound bytes (URL, every header value, and body)
		// for the placeholder sentinel. A hit means a placeholder either
		// wasn't swapped (host-scope mismatch, partial match, etc.) or the
		// sentinel was planted by a caller — either way we must not forward
		// the request. We return 502 and record a "leaked" audit row so the
		// user can diagnose the miss without the secret reaching the wire.
		if leakLocation, leaked := detectLeak(newURL, newHeader, newBody); leaked {
			if auditStore != nil {
				host, urlPath, _ := parseRequestURL(newURL)
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
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway,
				fmt.Sprintf("veil: placeholder leak detected in %s; request blocked (see audit log)", leakLocation))
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

// stripHostPort removes the port from a host:port string. If there is no
// port, the host is returned unchanged.
func stripHostPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

// detectLeak scans the final outbound URL, header values, and body for the
// placeholder sentinel. A single bytes.Contains / strings.Contains lookup is
// enough because the sentinel is embedded at a known offset in every
// generated placeholder (see placeholder.Sentinel). The returned location is
// "url", "header:<name>", or "body"; leaked is true if any hit is found.
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
	if len(newBody) > 0 && bytes.Contains(newBody, []byte(placeholder.Sentinel)) {
		return "body", true
	}
	return "", false
}
