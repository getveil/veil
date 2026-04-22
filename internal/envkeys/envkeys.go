// Package envkeys centralizes the names of environment variables Veil reads
// or strips. Declaring them here keeps callers from drifting on casing,
// spelling, or membership. Only variable names live here; the semantics
// (who reads them, what values are valid) stay with the consuming package.
package envkeys

// TestKeystoreToggle, when set to "mem" in a binary built with the
// testkeystore build tag, causes Veil to use an in-process MemKeystore
// instead of the platform keychain. Production binaries (built without
// the tag) never read this variable — see internal/cli/helpers_prodkeystore.go.
const TestKeystoreToggle = "VEIL_TEST_KEYSTORE"

// MCPConfigOverride, when set, replaces the auto-discovered Claude Desktop
// MCP config path. Intended for test hermeticity; production callers rarely
// set it.
const MCPConfigOverride = "VEIL_MCP_CONFIG_PATH"

// ProxyKeys lists every environment variable that configures an HTTP proxy.
// The runner strips these from the child environment before injecting its
// own loopback proxy URL.
var ProxyKeys = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
	"NO_PROXY", "no_proxy",
}

// CAKeys lists environment variables that configure CA certificate bundles
// across common runtimes (Node, curl, Python requests, httplib2, OpenSSL).
// The runner strips these and replaces them with Veil's combined bundle.
var CAKeys = []string{
	"NODE_EXTRA_CA_CERTS",
	"SSL_CERT_FILE",
	"CURL_CA_BUNDLE",
	"REQUESTS_CA_BUNDLE",
	"HTTPLIB2_CA_CERTS",
}
