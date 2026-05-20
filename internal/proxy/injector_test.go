package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/testutil"
	"github.com/getveil/veil/internal/vault"
)

// makeCred is a thin wrapper that delegates to testutil.MakeCred while
// preserving the existing call-site arg order (name, placeholder, real, hosts)
// and the "cred-<name>" ID convention that audit-assertion tests depend on.
func makeCred(name, placeholder, real string, hosts ...string) *vault.Credential {
	c := testutil.MakeCred(name, real, placeholder, hosts...)
	c.ID = "cred-" + name
	return c
}

func placeholderMap(creds ...*vault.Credential) map[string]*vault.Credential {
	m := make(map[string]*vault.Credential, len(creds))
	for _, c := range creds {
		m[c.Placeholder] = c
	}
	return m
}

func TestReplaceURL(t *testing.T) {
	cred := makeCred("api-key", "VEIL_PLACEHOLDER_AAAA1111", "sk-real-secret-value", "api.example.com")
	inj := NewInjector(placeholderMap(cred), nil, 1234, "agent")

	rawURL := "https://api.example.com/v1?key=VEIL_PLACEHOLDER_AAAA1111"
	newURL, _, _, injections := inj.ProcessRequest("req-1", "GET", rawURL, http.Header{}, nil)

	if !strings.Contains(newURL, "sk-real-secret-value") {
		t.Errorf("expected real value in URL, got %s", newURL)
	}
	if strings.Contains(newURL, "VEIL_PLACEHOLDER_AAAA1111") {
		t.Errorf("placeholder should be replaced in URL, got %s", newURL)
	}
	if len(injections) != 1 {
		t.Fatalf("expected 1 injection, got %d", len(injections))
	}
	if injections[0].Location != "url" {
		t.Errorf("expected location 'url', got %q", injections[0].Location)
	}
}

func TestReplaceHeader(t *testing.T) {
	cred := makeCred("token", "VEIL_PLACEHOLDER_BBBB2222", "Bearer real-token-value", "api.example.com")
	inj := NewInjector(placeholderMap(cred), nil, 1234, "agent")

	hdr := http.Header{}
	hdr.Set("Authorization", "VEIL_PLACEHOLDER_BBBB2222")

	_, newHeader, _, injections := inj.ProcessRequest("req-2", "POST", "https://api.example.com/v1", hdr, nil)

	got := newHeader.Get("Authorization")
	if got != "Bearer real-token-value" {
		t.Errorf("expected real token in header, got %q", got)
	}
	if len(injections) != 1 {
		t.Fatalf("expected 1 injection, got %d", len(injections))
	}
	if injections[0].Location != "header" {
		t.Errorf("expected location 'header', got %q", injections[0].Location)
	}
}

func TestReplaceBody(t *testing.T) {
	cred := makeCred("db-pass", "VEIL_PLACEHOLDER_CCCC3333", "s3cret-db-pass!", "db.example.com")
	inj := NewInjector(placeholderMap(cred), nil, 1234, "agent")

	body := []byte(`{"password":"VEIL_PLACEHOLDER_CCCC3333"}`)

	_, _, newBody, injections := inj.ProcessRequest("req-3", "POST", "https://db.example.com/connect", http.Header{}, body)

	if !strings.Contains(string(newBody), "s3cret-db-pass!") {
		t.Errorf("expected real value in body, got %s", string(newBody))
	}
	if strings.Contains(string(newBody), "VEIL_PLACEHOLDER_CCCC3333") {
		t.Errorf("placeholder should be replaced in body")
	}
	if len(injections) != 1 {
		t.Fatalf("expected 1 injection, got %d", len(injections))
	}
	if injections[0].Location != "body" {
		t.Errorf("expected location 'body', got %q", injections[0].Location)
	}
}

func TestMultipleMatches(t *testing.T) {
	c1 := makeCred("key1", "VEIL_PLACEHOLDER_XXXX0001", "real-val-1", "example.com")
	c2 := makeCred("key2", "VEIL_PLACEHOLDER_XXXX0002", "real-val-2", "example.com")
	c3 := makeCred("key3", "VEIL_PLACEHOLDER_XXXX0003", "real-val-3", "example.com")
	inj := NewInjector(placeholderMap(c1, c2, c3), nil, 100, "multi-agent")

	body := []byte("a=VEIL_PLACEHOLDER_XXXX0001&b=VEIL_PLACEHOLDER_XXXX0002&c=VEIL_PLACEHOLDER_XXXX0003")

	_, _, newBody, injections := inj.ProcessRequest("req-4", "POST", "https://example.com/", http.Header{}, body)

	s := string(newBody)
	for _, want := range []string{"real-val-1", "real-val-2", "real-val-3"} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %q in body, got %s", want, s)
		}
	}
	if len(injections) != 3 {
		t.Errorf("expected 3 injections, got %d", len(injections))
	}
}

func TestBodyCap(t *testing.T) {
	cred := makeCred("key", "VEIL_PLACEHOLDER_DDDD4444", "real-value", "example.com")
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")
	inj.bodyCap = 100 // set a small cap for testing

	// Body exceeds the cap.
	body := make([]byte, 101)
	copy(body, "VEIL_PLACEHOLDER_DDDD4444")

	_, _, newBody, injections := inj.ProcessRequest("req-5", "POST", "https://example.com/", http.Header{}, body)

	// Body should pass through untouched.
	if len(newBody) != 101 {
		t.Errorf("expected body length 101, got %d", len(newBody))
	}
	// There should be no body injections (URL/header injections are still possible).
	for _, inj := range injections {
		if inj.Location == "body" {
			t.Errorf("expected no body injections when body exceeds cap")
		}
	}
}

func TestNoMatch(t *testing.T) {
	cred := makeCred("key", "VEIL_PLACEHOLDER_EEEE5555", "real-value", "example.com")
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	rawURL := "https://example.com/api"
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	body := []byte(`{"data":"nothing special here"}`)

	newURL, newHeader, newBody, injections := inj.ProcessRequest("req-6", "GET", rawURL, hdr, body)

	if newURL != rawURL {
		t.Errorf("URL should be unchanged, got %s", newURL)
	}
	if newHeader.Get("Content-Type") != "application/json" {
		t.Errorf("header should be unchanged")
	}
	if string(newBody) != string(body) {
		t.Errorf("body should be unchanged")
	}
	if len(injections) != 0 {
		t.Errorf("expected 0 injections, got %d", len(injections))
	}
}

func TestAuditInjectionFields(t *testing.T) {
	cred := makeCred("my-secret", "VEIL_PLACEHOLDER_FFFF6666", "the-real-deal", "api.example.com")
	inj := NewInjector(placeholderMap(cred), nil, 42, "my-agent-cmd")

	rawURL := "https://api.example.com:8443/v2/resource?tok=VEIL_PLACEHOLDER_FFFF6666"
	_, _, _, injections := inj.ProcessRequest("req-audit", "PUT", rawURL, http.Header{}, nil)

	if len(injections) != 1 {
		t.Fatalf("expected 1 injection, got %d", len(injections))
	}
	inj0 := injections[0]

	if inj0.Host != "api.example.com:8443" {
		t.Errorf("Host = %q, want %q", inj0.Host, "api.example.com:8443")
	}
	if inj0.Method != "PUT" {
		t.Errorf("Method = %q, want %q", inj0.Method, "PUT")
	}
	if inj0.URLPath != "/v2/resource" {
		t.Errorf("URLPath = %q, want %q", inj0.URLPath, "/v2/resource")
	}
	if inj0.CredentialID != "cred-my-secret" {
		t.Errorf("CredentialID = %q, want %q", inj0.CredentialID, "cred-my-secret")
	}
	if inj0.CredentialName != "my-secret" {
		t.Errorf("CredentialName = %q, want %q", inj0.CredentialName, "my-secret")
	}
	if inj0.Location != "url" {
		t.Errorf("Location = %q, want %q", inj0.Location, "url")
	}
	if inj0.AgentPID != 42 {
		t.Errorf("AgentPID = %d, want %d", inj0.AgentPID, 42)
	}
	if inj0.AgentCmd != "my-agent-cmd" {
		t.Errorf("AgentCmd = %q, want %q", inj0.AgentCmd, "my-agent-cmd")
	}
	if inj0.RequestID != "req-audit" {
		t.Errorf("RequestID = %q, want %q", inj0.RequestID, "req-audit")
	}
	if inj0.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestOverlappingPlaceholderInMultipleLocations(t *testing.T) {
	cred := makeCred("shared", "VEIL_PLACEHOLDER_GGGG7777", "replaced-value", "example.com")
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	rawURL := "https://example.com/path?key=VEIL_PLACEHOLDER_GGGG7777"
	hdr := http.Header{}
	hdr.Set("X-Api-Key", "VEIL_PLACEHOLDER_GGGG7777")
	body := []byte(`{"token":"VEIL_PLACEHOLDER_GGGG7777"}`)

	newURL, newHeader, newBody, injections := inj.ProcessRequest("req-overlap", "POST", rawURL, hdr, body)

	// Verify all locations were replaced.
	if strings.Contains(newURL, "VEIL_PLACEHOLDER_GGGG7777") {
		t.Error("URL placeholder not replaced")
	}
	if strings.Contains(newHeader.Get("X-Api-Key"), "VEIL_PLACEHOLDER_GGGG7777") {
		t.Error("header placeholder not replaced")
	}
	if strings.Contains(string(newBody), "VEIL_PLACEHOLDER_GGGG7777") {
		t.Error("body placeholder not replaced")
	}

	if len(injections) != 3 {
		t.Fatalf("expected 3 injections, got %d", len(injections))
	}

	// Verify each location appears exactly once.
	locations := map[string]int{}
	for _, inj := range injections {
		locations[inj.Location]++
	}
	for _, loc := range []string{"url", "header", "body"} {
		if locations[loc] != 1 {
			t.Errorf("expected exactly 1 injection with location %q, got %d", loc, locations[loc])
		}
	}
}

func TestReplaceFunction(t *testing.T) {
	cred := makeCred("key", "VEIL_PH_ABCDEF123456", "real-secret")
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	got := inj.Replace("token=VEIL_PH_ABCDEF123456&extra=data")
	want := "token=real-secret&extra=data"
	if got != want {
		t.Errorf("Replace() = %q, want %q", got, want)
	}
}

func TestEmptyPlaceholderMap(t *testing.T) {
	inj := NewInjector(map[string]*vault.Credential{}, nil, 1, "agent")

	rawURL := "https://example.com/"
	newURL, _, _, injections := inj.ProcessRequest("req-empty", "GET", rawURL, http.Header{}, []byte("body"))

	if newURL != rawURL {
		t.Errorf("URL should be unchanged with empty map")
	}
	if len(injections) != 0 {
		t.Errorf("expected 0 injections, got %d", len(injections))
	}
}

func TestHostScoping_BlockedInjection(t *testing.T) {
	cred := makeCred("github-token", "VEIL_PLACEHOLDER_HOST0001", "ghp-real-secret", "api.github.com")
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	body := []byte(`{"context":"VEIL_PLACEHOLDER_HOST0001"}`)
	_, _, newBody, injections := inj.ProcessRequest(
		"req-host-1", "POST", "https://api.anthropic.com/v1/messages", http.Header{}, body)

	// Placeholder should NOT be replaced.
	if !strings.Contains(string(newBody), "VEIL_PLACEHOLDER_HOST0001") {
		t.Error("placeholder should not be replaced for non-matching host")
	}
	if strings.Contains(string(newBody), "ghp-real-secret") {
		t.Error("real secret should not appear in body for non-matching host")
	}
	// Should have a blocked audit entry.
	if len(injections) != 1 {
		t.Fatalf("expected 1 blocked injection, got %d", len(injections))
	}
	if injections[0].Location != "blocked" {
		t.Errorf("expected location 'blocked', got %q", injections[0].Location)
	}
}

func TestHostScoping_AllowedInjection(t *testing.T) {
	cred := makeCred("github-token", "VEIL_PLACEHOLDER_HOST0002", "ghp-real-secret", "api.github.com")
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer VEIL_PLACEHOLDER_HOST0002")
	_, newHeader, _, injections := inj.ProcessRequest(
		"req-host-2", "GET", "https://api.github.com/repos", hdr, nil)

	if newHeader.Get("Authorization") != "Bearer ghp-real-secret" {
		t.Errorf("expected real secret in header, got %q", newHeader.Get("Authorization"))
	}
	if len(injections) != 1 {
		t.Fatalf("expected 1 injection, got %d", len(injections))
	}
	if injections[0].Location != "header" {
		t.Errorf("expected location 'header', got %q", injections[0].Location)
	}
}

func TestHostScoping_MixedAuthorization(t *testing.T) {
	ghCred := makeCred("github-token", "VEIL_PLACEHOLDER_HOST0003", "ghp-real", "api.github.com")
	oaiCred := makeCred("openai-key", "VEIL_PLACEHOLDER_HOST0004", "sk-real", "api.openai.com")

	inj := NewInjector(placeholderMap(ghCred, oaiCred), nil, 1, "agent")

	body := []byte(`gh=VEIL_PLACEHOLDER_HOST0003&oai=VEIL_PLACEHOLDER_HOST0004`)
	_, _, newBody, injections := inj.ProcessRequest(
		"req-host-3", "POST", "https://api.github.com/graphql", http.Header{}, body)

	s := string(newBody)
	// GitHub cred should be replaced (matching host).
	if !strings.Contains(s, "ghp-real") {
		t.Error("expected github credential to be replaced")
	}
	// OpenAI cred should NOT be replaced (non-matching host).
	if !strings.Contains(s, "VEIL_PLACEHOLDER_HOST0004") {
		t.Error("expected openai placeholder to remain")
	}
	if strings.Contains(s, "sk-real") {
		t.Error("openai secret should not appear for github host")
	}

	// Should have 2 audit entries: 1 injection + 1 blocked.
	if len(injections) != 2 {
		t.Fatalf("expected 2 injections, got %d", len(injections))
	}
	locations := map[string]int{}
	for _, inj := range injections {
		locations[inj.Location]++
	}
	if locations["body"] != 1 {
		t.Errorf("expected 1 body injection, got %d", locations["body"])
	}
	if locations["blocked"] != 1 {
		t.Errorf("expected 1 blocked injection, got %d", locations["blocked"])
	}
}

func TestHostScoping_EmptyAllowedHosts(t *testing.T) {
	cred := makeCred("inert", "VEIL_PLACEHOLDER_HOST0005", "real-secret")
	// AllowedHosts is nil — should never inject.
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	body := []byte(`token=VEIL_PLACEHOLDER_HOST0005`)
	_, _, newBody, injections := inj.ProcessRequest(
		"req-host-4", "POST", "https://any-host.example.com/api", http.Header{}, body)

	if !strings.Contains(string(newBody), "VEIL_PLACEHOLDER_HOST0005") {
		t.Error("placeholder should not be replaced with empty AllowedHosts")
	}
	if len(injections) != 1 || injections[0].Location != "blocked" {
		t.Errorf("expected 1 blocked injection, got %v", injections)
	}
}

func TestHostScoping_WildcardMatch(t *testing.T) {
	cred := makeCred("aws-key", "VEIL_PLACEHOLDER_HOST0006", "AKIA-real-key", "*.amazonaws.com")
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	rawURL := "https://s3.us-east-1.amazonaws.com/bucket?key=VEIL_PLACEHOLDER_HOST0006"
	newURL, _, _, injections := inj.ProcessRequest(
		"req-host-5", "GET", rawURL, http.Header{}, nil)

	if strings.Contains(newURL, "VEIL_PLACEHOLDER_HOST0006") {
		t.Error("placeholder should be replaced for wildcard-matching host")
	}
	if !strings.Contains(newURL, "AKIA-real-key") {
		t.Error("expected real value in URL")
	}
	if len(injections) != 1 || injections[0].Location != "url" {
		t.Errorf("expected 1 url injection, got %v", injections)
	}
}

// Verify the audit package is importable and the Injection type is used
// correctly. This is a compile-time check more than a runtime one.
var _ audit.Injection

func TestProcessRequestInjectsQueryString(t *testing.T) {
	cred := makeCred("API_KEY", "sk_fake_ABCDEFGHIJ", "sk_real_1234567890", "api.example.com")
	inj := NewInjector(placeholderMap(cred), nil, 1234, "agent")

	newURL, _, _, injections := inj.ProcessRequest(
		"req-1",
		"GET",
		"https://api.example.com/v1/thing?api_key=sk_fake_ABCDEFGHIJ",
		http.Header{},
		nil,
	)
	if !strings.Contains(newURL, "api_key=sk_real_1234567890") {
		t.Fatalf("query string not injected: %s", newURL)
	}
	if len(injections) != 1 || injections[0].Location != "url" {
		t.Fatalf("expected 1 url injection, got %+v", injections)
	}
	if strings.Contains(injections[0].URLPath, "?") ||
		strings.Contains(injections[0].URLPath, "sk_") {
		t.Fatalf("audit URLPath leaked query data: %q", injections[0].URLPath)
	}
}

