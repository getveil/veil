package proxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/vault"
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

// TestProxy_FailsClosedOnSignerFailure verifies that when the SigV4 signer
// reports a signer_failed outcome (e.g. because the SDK signed the request
// with an AKID Veil doesn't know, but Veil still owns the host), the proxy
// returns a 502 with the X-Veil-Error header set and does NOT forward the
// original broken-placeholder request upstream.
func TestProxy_FailsClosedOnSignerFailure(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// A credential whose AllowedHosts covers the upstream: this means
	// Veil "owns" the host for SigV4, so an Authorization with an unknown
	// AKID must fail-closed (not pass through unmediated).
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	hostOnly := strings.Split(upstreamHost, ":")[0]
	cred := &vault.Credential{
		ID:                        "c1",
		Name:                      "aws-prod",
		Scheme:                    "aws",
		Real:                      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		AWSAccessKeyID:            "AKIAREAL000000000000",
		AWSAccessKeyIDPlaceholder: "AKIAPH00000000000000",
		AllowedHosts:              []string{hostOnly, upstreamHost},
	}
	srv, _, _ := testSetup(t, cred)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	client := httpClient(srv.Addr())
	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	// Authorization bears an AKID that is NOT in the vault. Because Veil
	// owns the host, the signer must fail-closed.
	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 Credential=AKIAUNKNOWNXXXXXXXX/20150830/us-east-1/service/aws4_request, "+
			"SignedHeaders=host;x-amz-date, Signature=xx")

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
		t.Fatalf("upstream received %d requests; must be 0 when signer fails", got)
	}
	if got := resp.Header.Get("X-Veil-Error"); got != SignerErrUnknownAccessKeyID {
		t.Errorf("X-Veil-Error = %q, want %q", got, SignerErrUnknownAccessKeyID)
	}
}

// TestFailClosedGuard_LeakedBasicAuth verifies that a placeholder embedded
// inside the base64-encoded payload of an Authorization: Basic header is
// caught by the fail-closed guard. Without base64-decoding the credential,
// the raw header bytes do not contain the sentinel and the request would
// otherwise leak the placeholder to the upstream host.
func TestFailClosedGuard_LeakedBasicAuth(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv, _, store := testSetup(t)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	client := httpClient(srv.Addr())
	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/test", nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("user:sk-proj-VEILleakedBasic"))
	req.Header.Set("Authorization", "Basic "+encoded)

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
		t.Fatalf("upstream received %d requests; must be 0 when basic-auth leak detected", got)
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
	if leakRow.Method != http.MethodGet {
		t.Errorf("leak row Method = %q, want GET", leakRow.Method)
	}
}

// TestFailClosedGuard_LeakedBasicAuth_UserHalf verifies that the fail-closed
// guard catches the placeholder when it is in the user half of user:pass,
// not the password half.
func TestFailClosedGuard_LeakedBasicAuth_UserHalf(t *testing.T) {
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
	encoded := base64.StdEncoding.EncodeToString([]byte("VEIL_USER_LEAK:somepass"))
	req.Header.Set("Authorization", "Basic "+encoded)

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
		t.Fatalf("upstream received %d requests; must be 0", got)
	}
}

// TestFailClosedGuard_BasicAuthNoLeakPasses verifies that a normal Basic
// auth request without any placeholder sentinel is forwarded successfully
// (the fail-closed guard does not regress on benign Basic credentials).
func TestFailClosedGuard_BasicAuthNoLeakPasses(t *testing.T) {
	var upstreamHits int32
	var seenAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		seenAuth = r.Header.Get("Authorization")
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
	encoded := base64.StdEncoding.EncodeToString([]byte("alice:hunter2"))
	wanted := "Basic " + encoded
	req.Header.Set("Authorization", wanted)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d (body=%q), want 200", resp.StatusCode, string(body))
	}
	if got := atomic.LoadInt32(&upstreamHits); got != 1 {
		t.Fatalf("upstream received %d requests; want 1", got)
	}
	if seenAuth != wanted {
		t.Errorf("upstream Authorization = %q, want %q", seenAuth, wanted)
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
