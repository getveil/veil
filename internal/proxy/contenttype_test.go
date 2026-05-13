package proxy_test

import (
	"testing"

	"github.com/getveil/veil/internal/proxy"
)

func TestShouldInjectBody(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"APPLICATION/JSON", true},
		{"application/x-www-form-urlencoded", true},
		{"text/plain", true},
		{"text/html; charset=utf-8", true},
		{"application/xml", true},
		{"application/ld+json", true},
		{"application/atom+xml", true},
		// SEC-3: these real-world secret-bearing payloads were previously
		// silently forwarded without placeholder scanning.
		{"application/yaml", true},
		{"application/x-yaml", true},
		{"application/toml", true},
		{"application/x-ndjson", true},
		{"application/graphql", true},
		{"application/graphql+json", true},
		{"application/octet-stream", false},
		{"image/jpeg", false},
		{"video/mp4", false},
		{"application/grpc", false},
		{"application/x-protobuf", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.ct, func(t *testing.T) {
			got := proxy.ShouldInjectBody(tc.ct)
			if got != tc.want {
				t.Fatalf("%q: got %v, want %v", tc.ct, got, tc.want)
			}
		})
	}
}
