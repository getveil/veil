package envkeys

import (
	"slices"
	"testing"
)

// TestProxyKeysCoverage guards against silent drift: a new proxy-related
// env var must be added here, so the runner's strip logic stays in sync.
func TestProxyKeysCoverage(t *testing.T) {
	want := map[string]bool{
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true,
		"http_proxy": true, "https_proxy": true, "all_proxy": true,
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
		"CARGO_HTTP_CAINFO":   true,
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
	if Passphrase != "VEIL_PASSPHRASE" {
		t.Errorf("Passphrase = %q, want VEIL_PASSPHRASE", Passphrase)
	}
}

func TestMCPDisableDiscoveryConstant(t *testing.T) {
	if MCPDisableDiscovery != "VEIL_MCP_DISABLE_DISCOVERY" {
		t.Errorf("MCPDisableDiscovery = %q, want VEIL_MCP_DISABLE_DISCOVERY", MCPDisableDiscovery)
	}
}

func TestVeilInternalKeysContainsDisableDiscovery(t *testing.T) {
	if !slices.Contains(VeilInternalKeys, MCPDisableDiscovery) {
		t.Errorf("VeilInternalKeys missing %q — agent could re-enable discovery via inherited env", MCPDisableDiscovery)
	}
}

// TestVeilInternalKeysCoverage guards against silent drift: any new Veil-
// internal env var that the runner must strip from the child environment
// has to be added here so the runner's strip helper picks it up
// automatically. VEIL_PASSPHRASE in particular is load-bearing — its
// absence here would silently re-open the file-keystore vault-decryption
// attack.
func TestVeilInternalKeysCoverage(t *testing.T) {
	want := map[string]bool{
		"VEIL_PASSPHRASE":            true,
		"VEIL_TEST_KEYSTORE":         true,
		"VEIL_MCP_CONFIG_PATH":       true,
		"VEIL_MCP_DISABLE_DISCOVERY": true,
	}
	got := make(map[string]bool, len(VeilInternalKeys))
	for _, k := range VeilInternalKeys {
		got[k] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("VeilInternalKeys missing %q", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("VeilInternalKeys has unexpected %q", k)
		}
	}
}
