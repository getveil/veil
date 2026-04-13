// Command testclient_post makes an HTTP POST request through a proxy with a JSON body.
// It is compiled and invoked by the integration tests to verify proxy body injection.
//
// Usage: testclient_post <url>
//
// Environment:
//
//	TEST_BODY      - JSON body to send (may contain placeholders)
//	HTTP_PROXY     - proxy URL (used explicitly, bypassing NO_PROXY)
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: testclient_post <url>")
		os.Exit(2)
	}
	targetURL := os.Args[1]
	body := os.Getenv("TEST_BODY")

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

	req, err := http.NewRequest("POST", targetURL, strings.NewReader(body)) //nolint:gosec
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req) //nolint:gosec
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(os.Stdout, resp.Body)
}
