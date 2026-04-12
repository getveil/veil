// Command testclient makes an HTTP request through a proxy with a custom header.
// It is compiled and invoked by the integration tests to verify proxy injection.
//
// Usage: testclient <url>
//
// Environment:
//
//	TEST_API_KEY   - value to send as Authorization: Bearer <value>
//	HTTP_PROXY     - proxy URL (used explicitly, bypassing NO_PROXY)
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: testclient <url>")
		os.Exit(2)
	}
	targetURL := os.Args[1]
	apiKey := os.Getenv("TEST_API_KEY")

	// Build an HTTP client that explicitly uses the proxy, bypassing NO_PROXY.
	// This is necessary because the veil runner sets NO_PROXY=localhost,127.0.0.1,::1
	// and our test server runs on localhost.
	proxyURL := os.Getenv("HTTP_PROXY")
	var transport *http.Transport
	if proxyURL != "" {
		parsed, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad HTTP_PROXY %q: %v\n", proxyURL, err)
			os.Exit(1)
		}
		transport = &http.Transport{
			Proxy: http.ProxyURL(parsed),
		}
	} else {
		transport = &http.Transport{}
	}

	client := &http.Client{Transport: transport}

	req, err := http.NewRequest("GET", targetURL, nil) //nolint:gosec // URL comes from test harness, not user input
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(req) //nolint:gosec // intentional test client
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(os.Stdout, resp.Body)
}
