package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/vault"
	"github.com/elazarl/goproxy"
	"github.com/oklog/ulid/v2"
)

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
		// Skip body injection if Content-Encoding indicates a compressed body.
		if ce := req.Header.Get("Content-Encoding"); ce != "" {
			log.Printf("[veil] warning: skipping body injection for compressed request (Content-Encoding: %q)", ce) //nolint:gosec // ce is from a standard HTTP header, %q escapes any special characters
			return req, nil
		}

		// Read the body up to bodyCap.
		var body []byte
		if req.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(req.Body, int64(bodyCap)+1))
			_ = req.Body.Close()
		}

		requestID := ulid.Make().String()

		newURL, newHeader, newBody, _ := inj.ProcessRequest(
			requestID, req.Method, req.URL.String(), req.Header, body)

		// Apply modified URL.
		if newURL != req.URL.String() {
			parsed, err := url.Parse(newURL)
			if err == nil {
				req.URL = parsed
			}
		}

		// Apply modified headers and body.
		req.Header = newHeader
		req.Body = io.NopCloser(bytes.NewReader(newBody))
		req.ContentLength = int64(len(newBody))

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
		return err
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
