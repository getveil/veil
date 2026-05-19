package proxy

import (
	"bytes"
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
		Real:                      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYREDACTDKEYY",
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

// TestFailClosedGuard_LeakAuditUsesRawURL verifies that when a URL placeholder
// is swapped successfully but the sentinel guard fires elsewhere (here, in the
// body), the persisted "leaked" audit row records the PRE-swap URL path — not
// the post-swap path that contains the real secret. Without this, a user who
// shares `veil log --json` for debugging would leak the live credential out of
// SQLite. Regression test for H3.
func TestFailClosedGuard_LeakAuditUsesRawURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upHost := strings.TrimPrefix(upstream.URL, "http://")
	hostOnly := strings.Split(upHost, ":")[0]

	// Placeholder embeds the sentinel (so the swapper recognizes it as a Veil
	// placeholder). The real value deliberately does NOT contain "VEIL".
	const placeholder = "phVEILplaceholderXYZ0000"
	const realSecret = "sk-real-zzzzzzzzzzzzzzzzzz"
	cred := &vault.Credential{
		ID:           "c-leak-urlpath",
		Name:         "url-placeholder",
		Real:         realSecret,
		Placeholder:  placeholder,
		AllowedHosts: []string{hostOnly, upHost},
	}
	srv, _, store := testSetup(t, cred)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	client := httpClient(srv.Addr())
	// URL contains the placeholder (it will swap to realSecret post-swap).
	// Body carries a SEPARATE sentinel that isn't a registered placeholder, so
	// it won't be swapped and will trip detectLeak — exercising the path
	// where the URL swap succeeded but the leak fires elsewhere.
	urlPath := "/users/" + placeholder + "/profile"
	resp, err := client.Post(upstream.URL+urlPath, "application/json",
		strings.NewReader(`{"trap":"VEILunmappedSentinel"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}

	// Allow the background flusher to persist the audit row.
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
	if strings.Contains(leakRow.URLPath, realSecret) {
		t.Fatalf("leak row URLPath = %q leaks the real secret %q to audit DB",
			leakRow.URLPath, realSecret)
	}
	if leakRow.URLPath != urlPath {
		t.Errorf("leak row URLPath = %q, want pre-swap path %q", leakRow.URLPath, urlPath)
	}
}

// TestFailClosedGuard_OversizedInjectableBody verifies that a request whose
// body exceeds bodyCap and whose Content-Type is injectable (e.g.
// application/json) is rejected with 502 — NOT silently truncated and
// forwarded. Previously the code did io.ReadAll(io.LimitReader(req.Body,
// bodyCap+1)) but then proceeded to inject and forward the truncated body,
// corrupting legitimate requests larger than 10 MiB without surfacing an error.
func TestFailClosedGuard_OversizedInjectableBody(t *testing.T) {
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

	// Build a body of bodyCap + 100 bytes of valid JSON (no placeholder).
	// The exact contents don't matter — what matters is that the body
	// is larger than bodyCap and the Content-Type triggers injection.
	overhead := []byte(`{"data":"`)
	tail := []byte(`"}`)
	padLen := bodyCap + 100 - len(overhead) - len(tail)
	pad := bytes.Repeat([]byte("A"), padLen)
	body := append(append([]byte{}, overhead...), pad...)
	body = append(body, tail...)
	if len(body) != bodyCap+100 {
		t.Fatalf("test body has wrong size: %d, want %d", len(body), bodyCap+100)
	}

	// Use a longer timeout because shipping a >10 MiB POST through the loopback
	// proxy can legitimately take longer than the 5-second default in httpClient.
	client := httpClient(srv.Addr())
	client.Timeout = 30 * time.Second

	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d (body=%q), want 502", resp.StatusCode, string(respBody))
	}
	if got := atomic.LoadInt32(&upstreamHits); got != 0 {
		t.Fatalf("upstream received %d requests; must be 0 when body exceeds inject limit", got)
	}

	respBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBody), "exceeds") || !strings.Contains(string(respBody), "inject limit") {
		t.Errorf("response body = %q, want it to mention exceeds/inject limit", string(respBody))
	}
	if got := resp.Header.Get("X-Veil-Error"); got == "" {
		t.Errorf("X-Veil-Error header is empty; expected the error class to be set")
	}
}

// TestFailClosedGuard_BoundaryBodyExactlyAtCap verifies that a body of exactly
// bodyCap bytes is forwarded successfully. bodyCap bytes is allowed; the
// reject threshold is strictly greater than bodyCap.
func TestFailClosedGuard_BoundaryBodyExactlyAtCap(t *testing.T) {
	var upstreamHits int32
	var receivedLen int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		b, _ := io.ReadAll(r.Body)
		receivedLen = len(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv, _, _ := testSetup(t)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	// Body of exactly bodyCap bytes (valid JSON).
	overhead := []byte(`{"data":"`)
	tail := []byte(`"}`)
	padLen := bodyCap - len(overhead) - len(tail)
	pad := bytes.Repeat([]byte("A"), padLen)
	body := append(append([]byte{}, overhead...), pad...)
	body = append(body, tail...)
	if len(body) != bodyCap {
		t.Fatalf("test body has wrong size: %d, want %d", len(body), bodyCap)
	}

	// Use a longer timeout because a 10 MiB POST is much larger than the
	// 5-second default in httpClient and may legitimately exceed it on
	// slow CI runners.
	client := httpClient(srv.Addr())
	client.Timeout = 30 * time.Second

	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d (body=%q), want 200 — bodyCap bytes must be allowed",
			resp.StatusCode, string(respBody))
	}
	if got := atomic.LoadInt32(&upstreamHits); got != 1 {
		t.Fatalf("upstream received %d requests; want 1", got)
	}
	if receivedLen != bodyCap {
		t.Errorf("upstream received %d bytes; want %d (no truncation)", receivedLen, bodyCap)
	}
}
