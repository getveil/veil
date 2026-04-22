package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8enji/veil/internal/audit"
)

// TestFailClosedGuard_LeakedBody verifies that if the final outbound body
// contains the placeholder sentinel (i.e. a placeholder wasn't swapped for its
// real secret), the proxy returns 502 instead of forwarding the request, and
// records a "leaked" audit row.
func TestFailClosedGuard_LeakedBody(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// No credentials registered: the sentinel string in the body is not a
	// registered placeholder, so no injection happens. The guard must still
	// fire because "VEIL" appears in the outbound bytes.
	srv, _, store := testSetup(t)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	client := httpClient(srv.Addr())
	resp, err := client.Post(upstream.URL+"/test", "application/json",
		strings.NewReader(`{"secret":"sk-proj-VEILabcdefghij"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d (body=%q), want 502", resp.StatusCode, string(body))
	}
	if got := atomic.LoadInt32(&upstreamHits); got != 0 {
		t.Fatalf("upstream received %d requests; must receive 0 when leak detected", got)
	}

	// Allow the background flusher (100ms ticker) to persist the audit row.
	time.Sleep(250 * time.Millisecond)

	rows, err := store.Query(audit.Filter{IncludeBlocked: true, IncludeSuspect: true, Limit: 50})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var leakRow *audit.Row
	for i := range rows {
		if rows[i].Location == "leaked" {
			leakRow = &rows[i]
			break
		}
	}
	if leakRow == nil {
		t.Fatalf("no 'leaked' audit row found; got %d rows", len(rows))
	}
	if leakRow.Method != http.MethodPost {
		t.Errorf("leak row Method = %q, want POST", leakRow.Method)
	}
}

// TestFailClosedGuard_LeakedHeader verifies the guard scans header values,
// not just the body.
func TestFailClosedGuard_LeakedHeader(t *testing.T) {
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

	client := httpClient(srv.Addr())
	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/test", nil)
	req.Header.Set("X-Api-Key", "sk-proj-VEILleakedtokenAbc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&upstreamHits); got != 0 {
		t.Fatalf("upstream received %d requests; must be 0", got)
	}
}

// TestFailClosedGuard_LeakedURL verifies the guard scans the URL path/query.
func TestFailClosedGuard_LeakedURL(t *testing.T) {
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

	client := httpClient(srv.Addr())
	resp, err := client.Get(upstream.URL + "/q?token=sk-proj-VEILleakedFromURL")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&upstreamHits); got != 0 {
		t.Fatalf("upstream received %d requests; must be 0", got)
	}
}
