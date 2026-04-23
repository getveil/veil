package proxy

import (
	"fmt"
	"testing"
)

func TestCanonicalURI(t *testing.T) {
	cases := []struct {
		name, in, want string
		isS3           bool
	}{
		{"root path", "/", "/", false},
		{"normal path", "/foo/bar", "/foo/bar", false},
		{"percent-encoded reserved", "/a b", "/a%20b", false},
		{"s3 preserves double slash", "/foo//bar", "/foo//bar", true},
		{"non-s3 collapses double slash", "/foo//bar", "/foo/bar", false},
		{"dot segments collapsed non-s3", "/foo/./bar/..", "/foo/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canonicalURI(tc.in, tc.isS3)
			if got != tc.want {
				t.Errorf("canonicalURI(%q, s3=%v) = %q, want %q", tc.in, tc.isS3, got, tc.want)
			}
		})
	}
}

func TestCanonicalQueryString(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"single", "foo=bar", "foo=bar"},
		{"sort by name", "b=2&a=1", "a=1&b=2"},
		{"same name sort by value", "a=2&a=1", "a=1&a=2"},
		{"empty value keeps =", "a=", "a="},
		{"encode space", "a=1 2", "a=1%202"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canonicalQueryString(tc.in)
			if got != tc.want {
				t.Errorf("canonicalQueryString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseSigV4Authorization(t *testing.T) {
	value := "AWS4-HMAC-SHA256 " +
		"Credential=AKIAIOSFODNN7EXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	got, err := parseSigV4Authorization(value)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AccessKeyID = %q", got.AccessKeyID)
	}
	if got.Date != "20150830" || got.Region != "us-east-1" || got.Service != "iam" {
		t.Errorf("scope wrong: %+v", got)
	}
	if len(got.SignedHeaders) != 3 || got.SignedHeaders[0] != "content-type" {
		t.Errorf("SignedHeaders = %v", got.SignedHeaders)
	}
	if got.Signature == "" {
		t.Error("Signature empty")
	}
}

func TestParseSigV4Authorization_Malformed(t *testing.T) {
	cases := []string{
		"",
		"Bearer foo",
		"AWS4-HMAC-SHA256 Credential=missing-slashes",
		"AWS4-HMAC-SHA256 SignedHeaders=host, Signature=xx", // no Credential
	}
	for _, c := range cases {
		if _, err := parseSigV4Authorization(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

// AWS SigV4 signing-key derivation test vector, published at:
// https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
func TestDeriveSigningKey_PublishedVector(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	date := "20150830"
	region := "us-east-1"
	service := "iam"
	key := deriveSigningKey(secret, date, region, service)
	got := fmt.Sprintf("%x", key)
	want := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	if got != want {
		t.Errorf("deriveSigningKey = %s, want %s", got, want)
	}
}

func TestCanonicalHeaders(t *testing.T) {
	hdr := map[string][]string{
		"Host":         {"s3.amazonaws.com"},
		"X-Amz-Date":   {"20150830T123600Z"},
		"Content-Type": {"  application/json   "},
	}
	signed := []string{"host", "x-amz-date", "content-type"}
	got := canonicalHeaders(hdr, signed)
	want := "host:s3.amazonaws.com\nx-amz-date:20150830T123600Z\ncontent-type:application/json\n"
	if got != want {
		t.Errorf("canonicalHeaders mismatch:\n got=%q\nwant=%q", got, want)
	}
}
