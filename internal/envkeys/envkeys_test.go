package envkeys

import "testing"

// TestProxyKeysCoverage guards against silent drift: a new proxy-related
// env var must be added here, so the runner's strip logic stays in sync.
func TestProxyKeysCoverage(t *testing.T) {
	want := map[string]bool{
		"HTTP_PROXY": true, "HTTPS_PROXY": true,
		"http_proxy": true, "https_proxy": true,
		"NO_PROXY": true, "no_proxy": true,
	}
	got := make(map[string]bool, len(ProxyKeys))
	for _, k := range ProxyKeys {
		got[k] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("ProxyKeys missing %q", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("ProxyKeys has unexpected %q", k)
		}
	}
}

func TestCAKeysCoverage(t *testing.T) {
	want := map[string]bool{
		"NODE_EXTRA_CA_CERTS": true,
		"SSL_CERT_FILE":       true,
		"CURL_CA_BUNDLE":      true,
		"REQUESTS_CA_BUNDLE":  true,
		"HTTPLIB2_CA_CERTS":   true,
	}
	got := make(map[string]bool, len(CAKeys))
	for _, k := range CAKeys {
		got[k] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("CAKeys missing %q", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("CAKeys has unexpected %q", k)
		}
	}
}

func TestToggleConstants(t *testing.T) {
	if TestKeystoreToggle != "VEIL_TEST_KEYSTORE" {
		t.Errorf("TestKeystoreToggle = %q, want VEIL_TEST_KEYSTORE", TestKeystoreToggle)
	}
	if MCPConfigOverride != "VEIL_MCP_CONFIG_PATH" {
		t.Errorf("MCPConfigOverride = %q, want VEIL_MCP_CONFIG_PATH", MCPConfigOverride)
	}
}
