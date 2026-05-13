// Package envkeys centralizes the names of environment variables Veil reads
// or strips. Declaring them here keeps callers from drifting on casing,
// spelling, or membership. Only variable names live here; the semantics
// (who reads them, what values are valid) stay with the consuming package.
package envkeys

import "slices"

// TestKeystoreToggle, when set to "mem" in a binary built with the
// testkeystore build tag, causes Veil to use an in-process MemKeystore
// instead of the platform keychain. Production binaries (built without
// the tag) never read this variable — see internal/cli/helpers_prodkeystore.go.
const TestKeystoreToggle = "VEIL_TEST_KEYSTORE"

// MCPConfigOverride, when set, replaces the auto-discovered Claude Desktop
// MCP config path. Intended for test hermeticity; production callers rarely
// set it.
const MCPConfigOverride = "VEIL_MCP_CONFIG_PATH"

// Passphrase is the env var Veil reads to decrypt the age-encrypted master
// key file on Linux when no Secret Service is available
// (internal/vault/keystore_file.go). Knowing this passphrase plus read
// access to ~/.local/state/veil/master.key.age is sufficient to recover
// every credential in the vault — so it must never reach a child agent.
const Passphrase = "VEIL_PASSPHRASE"

// VeilInternalKeys lists every Veil-internal environment variable that
// must be stripped from the agent's environment. The agent has no
// legitimate use for any of these, and leaving them would let an agent
// process either decrypt the vault (Passphrase) or redirect Veil's own
// behavior (TestKeystoreToggle, MCPConfigOverride) if it shells out
// to "veil". No placeholder is reinjected — these are control variables,
// not user secrets.
var VeilInternalKeys = []string{
	Passphrase,
	TestKeystoreToggle,
	MCPConfigOverride,
}

// HTTPProxyKeys lists the HTTP_PROXY/HTTPS_PROXY name variants (upper and
// lower case). The runner strips these and re-injects its own loopback proxy
// URL under each name.
var HTTPProxyKeys = []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"}

// NoProxyKeys lists the NO_PROXY name variants. The runner strips these and
// re-injects the merged skip-host list under each name.
var NoProxyKeys = []string{"NO_PROXY", "no_proxy"}

// ProxyKeys lists every environment variable that configures an HTTP proxy
// (both URL-bearing and skip-list-bearing). The runner strips these from the
// child environment before injecting its own values.
var ProxyKeys = slices.Concat(HTTPProxyKeys, NoProxyKeys)

// CAKeys lists environment variables that configure CA certificate bundles
// across common runtimes (Node, curl, Python requests, httplib2, OpenSSL,
// cargo). The runner strips these and replaces them with Veil's combined
// bundle path.
var CAKeys = []string{
	"NODE_EXTRA_CA_CERTS",
	"SSL_CERT_FILE",
	"CURL_CA_BUNDLE",
	"REQUESTS_CA_BUNDLE",
	"HTTPLIB2_CA_CERTS",
	"CARGO_HTTP_CAINFO",
}

// JavaToolOptions is the env var the JVM consults at startup. The runner
// merges Veil's truststore flags with any pre-existing value before re-export.
const JavaToolOptions = "JAVA_TOOL_OPTIONS"
