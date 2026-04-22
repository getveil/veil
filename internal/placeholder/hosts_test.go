package placeholder

import "testing"

func TestHostMatches_ExactMatch(t *testing.T) {
	if !HostMatches("api.github.com", []string{"api.github.com"}) {
		t.Error("expected exact match to succeed")
	}
}

func TestHostMatches_NoMatch(t *testing.T) {
	if HostMatches("api.anthropic.com", []string{"api.github.com"}) {
		t.Error("expected no match for different host")
	}
}

func TestHostMatches_WildcardSuffix(t *testing.T) {
	if !HostMatches("s3.us-east-1.amazonaws.com", []string{"*.amazonaws.com"}) {
		t.Error("expected wildcard suffix match to succeed")
	}
}

func TestHostMatches_WildcardNoPartialMatch(t *testing.T) {
	if HostMatches("notamazonaws.com", []string{"*.amazonaws.com"}) {
		t.Error("expected wildcard to not match partial host")
	}
}

func TestHostMatches_WildcardExactBase(t *testing.T) {
	// *.amazonaws.com should NOT match bare "amazonaws.com"
	if HostMatches("amazonaws.com", []string{"*.amazonaws.com"}) {
		t.Error("expected wildcard to not match bare base domain")
	}
}

func TestHostMatches_EmptyAllowedHosts(t *testing.T) {
	if HostMatches("api.github.com", nil) {
		t.Error("expected no match with nil allowed hosts")
	}
	if HostMatches("api.github.com", []string{}) {
		t.Error("expected no match with empty allowed hosts")
	}
}

func TestHostMatches_MultipleHosts(t *testing.T) {
	hosts := []string{"api.github.com", "uploads.github.com"}
	if !HostMatches("uploads.github.com", hosts) {
		t.Error("expected match on second host in list")
	}
}

func TestHostMatches_PortStripped(t *testing.T) {
	if !HostMatches("api.github.com:443", []string{"api.github.com"}) {
		t.Error("expected match after stripping port")
	}
}

func TestExtractURLHost_PostgresURL(t *testing.T) {
	host := ExtractURLHost("postgres://user:pass@db.prod.internal:5432/mydb")
	if host != "db.prod.internal" {
		t.Errorf("expected db.prod.internal, got %q", host)
	}
}

func TestExtractURLHost_HTTPS(t *testing.T) {
	host := ExtractURLHost("https://api.example.com/v1")
	if host != "api.example.com" {
		t.Errorf("expected api.example.com, got %q", host)
	}
}

func TestExtractURLHost_PlainString(t *testing.T) {
	host := ExtractURLHost("sk-ant-api03-something")
	if host != "" {
		t.Errorf("expected empty string for non-URL, got %q", host)
	}
}

func TestExtractURLHost_NoScheme(t *testing.T) {
	host := ExtractURLHost("db.example.com:5432")
	if host != "" {
		t.Errorf("expected empty string for host without scheme, got %q", host)
	}
}

func TestHostsForCredential_GitHubToken(t *testing.T) {
	hosts := HostsForCredential("GITHUB_TOKEN", "ghp_abc123def456")
	if len(hosts) == 0 {
		t.Fatal("expected hosts for GitHub token")
	}
	found := false
	for _, h := range hosts {
		if h == "api.github.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected api.github.com in hosts, got %v", hosts)
	}
}

func TestHostsForCredential_OpenAIKey(t *testing.T) {
	hosts := HostsForCredential("OPENAI_API_KEY", "sk-proj-abc123")
	if len(hosts) != 1 || hosts[0] != "api.openai.com" {
		t.Errorf("expected [api.openai.com], got %v", hosts)
	}
}

func TestHostsForCredential_DatabaseURL(t *testing.T) {
	hosts := HostsForCredential("DATABASE_URL", "postgres://user:pass@db.prod.internal:5432/mydb")
	if len(hosts) != 1 || hosts[0] != "db.prod.internal" {
		t.Errorf("expected [db.prod.internal], got %v", hosts)
	}
}

func TestHostsForCredential_UnknownSecret(t *testing.T) {
	hosts := HostsForCredential("CUSTOM_SECRET", "some-opaque-value-1234567890")
	if hosts != nil {
		t.Errorf("expected nil for unknown secret, got %v", hosts)
	}
}

func TestHostsForCredential_NameMatchGitHub(t *testing.T) {
	// Name contains GITHUB but value has no prefix — should still match provider.
	hosts := HostsForCredential("GITHUB_ENTERPRISE_TOKEN", "custom-token-value")
	if len(hosts) == 0 {
		t.Fatal("expected hosts for name-matched GitHub credential")
	}
	found := false
	for _, h := range hosts {
		if h == "api.github.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected api.github.com in hosts, got %v", hosts)
	}
}

// TestExtractURLHost_RejectsUnknownScheme asserts that schemes outside the
// allowlist yield empty host regardless of URL syntax validity. This closes
// SEC-8 from the 2026-04-22 audit: a crafted env var value like
// "javascript://evil.com" must not widen the proxy's allow-host set.
func TestExtractURLHost_RejectsUnknownScheme(t *testing.T) {
	cases := []string{
		"javascript://evil.com",
		"javascript://evil.com/foo",
		"file:///etc/passwd",
		"data://base64,abc",
		"vscode://sourcegraph/auth?token=abc",
		"ftp://ftp.example.com/file",
		"ldap://ldap.example.com",
	}
	for _, value := range cases {
		t.Run(value, func(t *testing.T) {
			host := ExtractURLHost(value)
			if host != "" {
				t.Fatalf("scheme-disallowed URL %q yielded host %q; expected empty", value, host)
			}
		})
	}
}

// TestExtractURLHost_AcceptsAllowedSchemes asserts existing scheme handling
// is preserved for the allowlisted schemes.
func TestExtractURLHost_AcceptsAllowedSchemes(t *testing.T) {
	cases := []struct {
		value    string
		wantHost string
	}{
		{"http://example.com/x", "example.com"},
		{"https://api.example.com:443/", "api.example.com"},
		{"postgres://user:pw@db.internal:5432/mydb", "db.internal"},
		{"mysql://root:pw@mysql.internal/db", "mysql.internal"},
		{"redis://:pw@redis.internal:6379/0", "redis.internal"},
		{"mongodb+srv://user:pw@cluster.mongo.internal/db", "cluster.mongo.internal"},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			got := ExtractURLHost(tc.value)
			if got != tc.wantHost {
				t.Fatalf("ExtractURLHost(%q) = %q, want %q", tc.value, got, tc.wantHost)
			}
		})
	}
}
