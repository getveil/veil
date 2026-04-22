package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestCompressedBodyRejected verifies that a request with a non-identity
// Content-Encoding is rejected with 502 instead of being forwarded unchanged.
// Per SEC-3, Veil cannot reliably scan or inject into a compressed body, so
// the only safe action is to block the request so the caller becomes aware.
func TestCompressedBodyRejected(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv, _, _ := testSetup(t)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	// Build a gzip-encoded request body.
	var gz bytes.Buffer
	gzw := gzip.NewWriter(&gz)
	if _, err := gzw.Write([]byte(`{"k":"v"}`)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	client := httpClient(srv.Addr())
	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/test", bytes.NewReader(gz.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d (body=%q), want 502", resp.StatusCode, string(body))
	}
	if got := atomic.LoadInt32(&upstreamHits); got != 0 {
		t.Fatalf("upstream received %d requests; want 0", got)
	}
}

// TestIdentityEncodingPassesThrough checks that explicit Content-Encoding:
// identity is treated as uncompressed and injection proceeds.
func TestIdentityEncodingPassesThrough(t *testing.T) {
	var received string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv, _, _ := testSetup(t)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	client := httpClient(srv.Addr())
	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/test", bytes.NewReader([]byte(`{"k":"v"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if received != `{"k":"v"}` {
		t.Fatalf("upstream received %q, want clean body", received)
	}
}
