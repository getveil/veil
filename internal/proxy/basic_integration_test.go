package proxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/vault"
)

// upstreamHost returns just the host:port portion of a httptest.Server URL.
func upstreamHost(s *httptest.Server) string {
	u, _ := url.Parse(s.URL)
	return u.Host
}

// TestBasicAuthEndToEnd spins up an upstream HTTP server that requires a
// specific Basic auth header, runs a request through ProcessRequest with
// placeholder Basic, and asserts the upstream sees the real credentials.
func TestBasicAuthEndToEnd(t *testing.T) {
	realUser := "johndoe"
	realSecret := "ghp_real_secret_value"
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(realUser+":"+realSecret))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if got != expectedAuth {
			http.Error(w, "unauthorized: got "+got, http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	hostOnly := strings.Split(host, ":")[0]
	allowedHost := strings.Split(host, "/")[0]

	cred := &vault.Credential{
		ID: "c1", Name: "basic-e2e",
		Real:                realSecret,
		Placeholder:         "VEIL_SECRET_E2E",
		Username:            realUser,
		UsernamePlaceholder: "VEIL_USER_E2E",
		AllowedHosts:        []string{hostOnly, allowedHost},
	}
	inj := NewInjector(
		map[string]*vault.Credential{cred.Placeholder: cred, cred.UsernamePlaceholder: cred},
		nil, 1, "test-agent",
	)

	phAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("VEIL_USER_E2E:VEIL_SECRET_E2E"))
	hdr := http.Header{}
	hdr.Set("Authorization", phAuth)

	_, newHeader, _, injections := inj.ProcessRequest(
		"req-e2e", "GET", srv.URL+"/ping", hdr, nil)

	req, err := http.NewRequest("GET", srv.URL+"/ping", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, vs := range newHeader {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("upstream returned %d: %s", resp.StatusCode, body)
	}
	if len(injections) != 1 {
		t.Errorf("expected 1 injection, got %d", len(injections))
	}
	for _, i := range injections {
		if i.SuspectFlag {
			t.Errorf("unexpected suspect injection: %+v", i)
		}
	}
}

// TestDetectorFiresOnSigV4Shape spins up an upstream, sends a request that
// looks AWS-SigV4-shaped to a credentialed host, and asserts the detector
// fires without any swap happening (since SigV4 isn't implemented).
func TestDetectorFiresOnSigV4Shape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fake sigv4 rejection", http.StatusForbidden)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	hostOnly := strings.Split(host, ":")[0]

	cred := &vault.Credential{
		ID: "aws", Name: "aws-secret",
		Real:         "wJalr_real_secret",
		Placeholder:  "VEIL_AWS_PH",
		AllowedHosts: []string{hostOnly, host},
	}
	inj := NewInjector(map[string]*vault.Credential{cred.Placeholder: cred}, nil, 1, "test")

	hdr := http.Header{}
	hdr.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAFAKE/20260415/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcd1234")
	hdr.Set("X-Amz-Date", "20260415T000000Z")

	_, _, _, injections := inj.ProcessRequest(
		"req-sigv4", "GET", srv.URL+"/bucket", hdr, nil)

	var suspect int
	for _, i := range injections {
		if i.SuspectFlag {
			suspect++
			if i.AuthSignal != "authorization_header" {
				t.Errorf("AuthSignal = %q", i.AuthSignal)
			}
		}
	}
	if suspect != 1 {
		t.Errorf("expected 1 suspect injection, got %d (all: %+v)", suspect, injections)
	}
}

// TestBasicLeak_502ContainsHint_TwoSeparateCreds asserts that when the
// agent sends a Basic header whose two halves point to two different
// vault credentials (the pre-fix state for an unpaired init), the proxy
// returns 502, sets X-Veil-Error: basic_unpaired, and includes a
// targeted hint in the response body.
func TestBasicLeak_502ContainsHint_TwoSeparateCreds(t *testing.T) {
	// Upstream — will never be reached since the proxy blocks the request.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Two separate bearer creds — not paired into one Basic cred.
	credUser := &vault.Credential{
		ID:           "u",
		Name:         "GH_USERNAME",
		Real:         "alice",
		Placeholder:  "VEIL_USER_UNPAIRED",
		AllowedHosts: []string{upstreamHost(upstream), strings.Split(upstreamHost(upstream), ":")[0]},
	}
	credPass := &vault.Credential{
		ID:           "p",
		Name:         "GH_PASSWORD",
		Real:         "ghp_real",
		Placeholder:  "VEIL_SECRET_UNPAIRED",
		AllowedHosts: []string{upstreamHost(upstream), strings.Split(upstreamHost(upstream), ":")[0]},
	}

	srv, _, _ := testSetup(t, credUser, credPass)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	req, _ := http.NewRequest("GET", upstream.URL+"/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("VEIL_USER_UNPAIRED:VEIL_SECRET_UNPAIRED")))

	client := httpClient(srv.Addr())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Veil-Error"); got != "basic_unpaired" {
		t.Errorf("X-Veil-Error = %q, want basic_unpaired", got)
	}
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	for _, want := range []string{"GH_USERNAME", "GH_PASSWORD", "veil init --force", "--user"} {
		if !strings.Contains(bodyStr, want) {
			t.Errorf("body missing %q: %q", want, bodyStr)
		}
	}
}

