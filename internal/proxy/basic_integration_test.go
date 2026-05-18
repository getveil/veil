package proxy

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
	for _, want := range []string{"GH_USERNAME", "GH_PASSWORD", "veil add", "--scheme basic"} {
		if !strings.Contains(bodyStr, want) {
			t.Errorf("body missing %q: %q", want, bodyStr)
		}
	}
}

// TestIntegration_AWSSigV4_EndToEnd spins up an HTTP server that verifies a
// SigV4 signature with a known real SecretAccessKey, invokes the proxy with
// a request signed by the placeholder key, and asserts that the upstream
// verifies the real signature.
func TestIntegration_AWSSigV4_EndToEnd(t *testing.T) {
	realSecret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	realAKID := "AKIAIOSFODNN7EXAMPLE"
	placeholderAKID := "AKIAPH0000000000EXMP"
	placeholderSecret := "VeilSecretPlaceholderXXXXXXXXXXXXXXXXXXX"

	// Upstream validator: recompute canonical request + signature from the
	// incoming Authorization header and ensure it matches the real signing key.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		parsed, err := parseSigV4Authorization(auth)
		if err != nil {
			t.Errorf("upstream parse: %v", err)
			w.WriteHeader(400)
			return
		}
		if parsed.AccessKeyID != realAKID {
			t.Errorf("upstream saw AKID = %q, want real %q", parsed.AccessKeyID, realAKID)
		}
		body, _ := io.ReadAll(r.Body)
		canon := r.Method + "\n" +
			canonicalURI(r.URL.Path, false) + "\n" +
			canonicalQueryString(r.URL.RawQuery) + "\n" +
			canonicalHeaders(r.Header, parsed.SignedHeaders) + "\n" +
			strings.Join(parsed.SignedHeaders, ";") + "\n" +
			sha256Hex(body)
		scope := parsed.Date + "/" + parsed.Region + "/" + parsed.Service + "/aws4_request"
		sts := "AWS4-HMAC-SHA256\n" + r.Header.Get("X-Amz-Date") + "\n" + scope + "\n" + sha256Hex([]byte(canon))
		key := deriveSigningKey(realSecret, parsed.Date, parsed.Region, parsed.Service)
		want := fmt.Sprintf("%x", hmacSHA256(key, []byte(sts)))
		if parsed.Signature != want {
			t.Errorf("signature mismatch\n got=%s\nwant=%s", parsed.Signature, want)
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	upHost := upstreamHost(upstream)
	cred := &vault.Credential{
		ID: vault.NewID(), Name: "aws-prod", Scheme: "aws",
		Real: realSecret, Placeholder: placeholderSecret,
		AWSAccessKeyID: realAKID, AWSAccessKeyIDPlaceholder: placeholderAKID,
		AllowedHosts: []string{upHost, strings.Split(upHost, ":")[0]},
	}
	srv, _, _ := testSetup(t, cred)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	// Agent signs request with placeholder secret. The SignedHeaders list
	// deliberately omits "host": Go's http stack moves Host out of the
	// header map into req.Host before transport, so neither the proxy's
	// signer nor the upstream verifier can recover it from the header
	// map. Signing only x-amz-date keeps the canonical request stable
	// across both ends without needing to touch shared signer code.
	req, _ := http.NewRequest("GET", upstream.URL+"/path", nil)
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	canonReq := "GET\n/path\n\nx-amz-date:20150830T123600Z\n\nx-amz-date\n" + sha256Hex(nil)
	sts := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n" + sha256Hex([]byte(canonReq))
	phKey := deriveSigningKey(placeholderSecret, "20150830", "us-east-1", "service")
	phSig := fmt.Sprintf("%x", hmacSHA256(phKey, []byte(sts)))
	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 "+
			"Credential="+placeholderAKID+"/20150830/us-east-1/service/aws4_request, "+
			"SignedHeaders=x-amz-date, "+
			"Signature="+phSig)

	client := httpClient(srv.Addr())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("end-to-end returned %d: %s", resp.StatusCode, body)
	}
}

// TestIntegration_GitHubAppJWT_EndToEnd spins up an HTTP server that
// verifies a GitHub App JWT against a known real RSA public key, invokes
// the proxy with a JWT signed by the placeholder key, and asserts that the
// upstream verifies a JWT signed with the real key.
func TestIntegration_GitHubAppJWT_EndToEnd(t *testing.T) {
	realKey, realPEM := genPEM(t)
	placeholderKey, placeholderPEM := genPEM(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		jwt := strings.TrimPrefix(auth, "Bearer ")
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			t.Errorf("upstream JWT not 3-part: %s", jwt)
			w.WriteHeader(400)
			return
		}
		sig, err := base64URLDecode(parts[2])
		if err != nil {
			t.Errorf("upstream sig decode: %v", err)
			w.WriteHeader(400)
			return
		}
		h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		// crypto.SHA256 is the RFC 7518 §3.3 hash identifier; the wired-up
		// signer uses the same prefix.
		if err := rsa.VerifyPKCS1v15(&realKey.PublicKey, crypto.SHA256, h[:], sig); err != nil {
			t.Errorf("upstream JWT does not verify with real key: %v", err)
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	upHost := upstreamHost(upstream)
	cred := &vault.Credential{
		ID: vault.NewID(), Name: "gh-app", Scheme: "github_app",
		Real: realPEM, Placeholder: placeholderPEM,
		GitHubAppID:  7777,
		AllowedHosts: []string{upHost, strings.Split(upHost, ":")[0]},
	}
	srv, _, _ := testSetup(t, cred)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	jwt := signJWT(t, placeholderKey, 7777)
	req, _ := http.NewRequest("POST", upstream.URL+"/app/installations", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)

	client := httpClient(srv.Addr())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("end-to-end returned %d: %s", resp.StatusCode, body)
	}
}
